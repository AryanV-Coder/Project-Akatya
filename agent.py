import os
import sys
import time
import json
import base64
import socket
import threading
from queue import Queue
from pathlib import Path
from collections import deque
import requests
import psutil

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from utils.crypto import (
    encrypt_aes_gcm,
    encrypt_rsa_oaep,
    compute_sha256
)

# Configuration Defaults
CONFIG_FILE = Path("agent_config.json")
SANDBOX_DIR = Path("demo_sandbox").resolve()
DEFAULT_SERVER_URL = "http://127.0.0.1:8000"

# Heuristic Rules
RATE_WINDOW_SECONDS = 1.5
RATE_THRESHOLD_MODS = 4  # >= 4 file modifications within 1.5 seconds triggers kill-switch


class EndpointAgent:
    def __init__(self, server_url: str = DEFAULT_SERVER_URL):
        self.server_url = server_url.rstrip("/")
        self.endpoint_id = None
        self.public_key_pem = None
        self.file_cache = {}             # {filepath: clean_sha256}
        self.paused = False              # Freezes backup uploads when attack is detected
        self.mod_timestamps = deque()    # Sliding window of modification timestamps
        self.lock = threading.Lock()
        self.backup_queue = Queue()      # Background queue for cloud uploads

    def initialize(self):
        """Loads configuration or performs handshake registration with backend."""
        SANDBOX_DIR.mkdir(parents=True, exist_ok=True)

        if CONFIG_FILE.exists():
            with open(CONFIG_FILE, "r") as f:
                config = json.load(f)
                self.endpoint_id = config.get("endpoint_id")
                self.public_key_pem = config.get("public_key")
                self.server_url = config.get("server_url", self.server_url)
                print(f"[*] Loaded existing configuration for Endpoint ID: {self.endpoint_id}")
        else:
            self.register()

        print("[✓] RSA Public Key loaded successfully into agent memory.")
        
        # Start background worker for asynchronous backups so watchdog loop is never blocked
        t = threading.Thread(target=self._backup_worker, daemon=True)
        t.start()

    def register(self):
        """Performs initial registration handshake with the FastAPI server."""
        hostname = socket.gethostname()
        print(f"[*] Contacting backend {self.server_url} to register hostname '{hostname}'...")

        try:
            resp = requests.post(
                f"{self.server_url}/api/register",
                json={"hostname": hostname},
                timeout=10
            )
            resp.raise_for_status()
            data = resp.json()

            self.endpoint_id = data["endpoint_id"]
            self.public_key_pem = data["public_key"]

            with open(CONFIG_FILE, "w") as f:
                json.dump({
                    "endpoint_id": self.endpoint_id,
                    "hostname": hostname,
                    "public_key": self.public_key_pem,
                    "server_url": self.server_url
                }, f, indent=4)

            print(f"[✓] Registration successful! Assigned Endpoint ID: {self.endpoint_id}")

        except Exception as e:
            print(f"[!] Registration failed: {e}")
            sys.exit(1)

    def record_and_check_heuristic(self) -> bool:
        """
        Microsecond-level rate limiter:
        Returns True if modification rate indicates a ransomware attack.
        """
        now = time.time()
        with self.lock:
            self.mod_timestamps.append(now)
            while self.mod_timestamps and (now - self.mod_timestamps[0]) > RATE_WINDOW_SECONDS:
                self.mod_timestamps.popleft()

            return len(self.mod_timestamps) >= RATE_THRESHOLD_MODS

    def trigger_kill_switch(self):
        """
        Heuristic Kill-Switch:
        1. Freezes backup pipeline immediately.
        2. Kills offending malicious processes via psutil.
        3. Gathers digital evidence.
        4. Transmits alert to FastAPI.
        """
        with self.lock:
            if self.paused:
                return
            self.paused = True

        print("\n" + "!" * 65)
        print("🚨 [ALERT] RAPID FILE MODIFICATION SPIKE DETECTED! INITIATING KILL-SWITCH!")
        print("!" * 65)

        # Clear any pending backups in the queue
        while not self.backup_queue.empty():
            try:
                self.backup_queue.get_nowait()
                self.backup_queue.task_done()
            except Exception:
                break

        # 1. Terminate offending process
        killed_processes = []
        current_pid = os.getpid()

        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                if proc.info['pid'] == current_pid:
                    continue

                cmdline_str = " ".join(proc.info.get('cmdline') or [])
                if "simulate_attack.py" in cmdline_str or "ransomware" in cmdline_str.lower():
                    print(f"[KILL-SWITCH] 🎯 Found offending malicious process: PID {proc.info['pid']} ({cmdline_str})")
                    p = psutil.Process(proc.info['pid'])
                    p.kill()
                    killed_processes.append(f"PID {proc.info['pid']}")
                    print(f"[KILL-SWITCH] 🛑 Offending process PID {proc.info['pid']} TERMINATED instantly via psutil!")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # 2. Gather digital evidence (corrupted files)
        evidence = []
        for file_path in SANDBOX_DIR.iterdir():
            if file_path.is_file() and not file_path.name.startswith("."):
                try:
                    with open(file_path, "rb") as f:
                        content = f.read()

                    cur_hash = compute_sha256(content)
                    prev_hash = self.file_cache.get(str(file_path))

                    # If corrupted with ransomware marker or changed
                    if b"[LOCKED_BY_RANSOMWARE" in content or (prev_hash and cur_hash != prev_hash):
                        evidence.append({
                            "corrupted_filepath": file_path.name,
                            "corrupted_hash": cur_hash
                        })
                except Exception as read_err:
                    print(f"[!] Error reading evidence file '{file_path.name}': {read_err}")

        print(f"[EVIDENCE] Cataloged {len(evidence)} corrupted file(s) for forensic preservation.")

        # 3. Report incident to FastAPI
        try:
            incident_payload = {
                "endpoint_id": self.endpoint_id,
                "process_killed": len(killed_processes) > 0,
                "evidence": evidence
            }
            resp = requests.post(f"{self.server_url}/api/incident", json=incident_payload, timeout=10)
            if resp.status_code == 200:
                inc_data = resp.json()
                print(f"[✓] Incident successfully logged to Supabase! Incident ID: {inc_data['incident_id']}")
            else:
                print(f"[!] Failed to log incident: {resp.text}")
        except Exception as net_err:
            print(f"[!] Error transmitting incident alert: {net_err}")

        print("=" * 65)
        print("🛑 SYSTEM LOCKED: Backup pipeline frozen. Ready for admin forensic report & recovery.")
        print("=" * 65 + "\n")

    def queue_backup(self, file_path: Path):
        """Enqueues file for background backup if agent is healthy."""
        if not self.paused:
            self.backup_queue.put(file_path)

    def _backup_worker(self):
        """Background thread worker that executes cloud uploads without blocking watchdog."""
        while True:
            file_path = self.backup_queue.get()
            if self.paused:
                self.backup_queue.task_done()
                continue

            try:
                self.encrypt_and_backup(file_path)
            except Exception as e:
                print(f"[!] Backup worker error: {e}")
            finally:
                self.backup_queue.task_done()

    def encrypt_and_backup(self, file_path: Path):
        """Performs hybrid encryption and uploads to FastAPI."""
        if self.paused:
            return

        if not file_path.is_file() or file_path.name.startswith("."):
            return

        try:
            with open(file_path, "rb") as f:
                file_bytes = f.read()

            if not file_bytes:
                return

            file_hash = compute_sha256(file_bytes)

            # Avoid redundant uploads
            if self.file_cache.get(str(file_path)) == file_hash:
                return

            # AES-GCM encryption
            encrypted_data, aes_key = encrypt_aes_gcm(file_bytes)

            # RSA-OAEP key encryption
            encrypted_aes_key = encrypt_rsa_oaep(aes_key, self.public_key_pem)

            payload = {
                "endpoint_id": self.endpoint_id,
                "original_path": str(file_path.name),
                "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode("utf-8"),
                "file_hash": file_hash,
                "encrypted_data_b64": base64.b64encode(encrypted_data).decode("utf-8")
            }

            resp = requests.post(f"{self.server_url}/api/backup", json=payload, timeout=15)
            if resp.status_code == 200:
                result = resp.json()
                self.file_cache[str(file_path)] = file_hash
                print(f"[✓] Securely backed up '{file_path.name}' (v{result['version']}, SHA: {file_hash[:10]}...)")

        except Exception as e:
            if not self.paused:
                print(f"[!] Error backing up '{file_path.name}': {e}")


class SandboxChangeHandler(FileSystemEventHandler):
    """Watches sandbox directory and intercepts rapid modification bursts."""
    def __init__(self, agent: EndpointAgent):
        super().__init__()
        self.agent = agent

    def on_created(self, event):
        if not event.is_directory:
            self._process_event(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._process_event(event.src_path)

    def _process_event(self, path_str: str):
        # 1. Check rate heuristic immediately
        is_attack = self.agent.record_and_check_heuristic()
        if is_attack:
            self.agent.trigger_kill_switch()
            return

        # 2. Queue for asynchronous background upload
        self.agent.queue_backup(Path(path_str))


def start_agent():
    print("=" * 60)
    print("Project Akatya - Endpoint Monitoring Agent Starting...")
    print("=" * 60)

    agent = EndpointAgent()
    agent.initialize()

    # Initial backup pass for all clean files in sandbox
    print("\n[*] Performing initial synchronization of sandbox files...")
    for item in SANDBOX_DIR.iterdir():
        if item.is_file() and not item.name.startswith("."):
            agent.queue_backup(item)

    # Start Watchdog observer
    event_handler = SandboxChangeHandler(agent)
    observer = Observer()
    observer.schedule(event_handler, path=str(SANDBOX_DIR), recursive=False)
    observer.start()

    print(f"\n[✓] Agent is actively monitoring '{SANDBOX_DIR.resolve()}'")
    print("[*] Heuristic Kill-Switch ACTIVE (>= 4 file modifications in 1.5s)")
    print("[*] Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping observer...")
        observer.stop()
    observer.join()
    print("[✓] Agent terminated cleanly.")


if __name__ == "__main__":
    start_agent()
