import os
import sys
import time
import json
import base64
import socket
from pathlib import Path
import requests

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from utils.crypto import (
    encrypt_aes_gcm,
    encrypt_rsa_oaep,
    compute_sha256
)

# Configuration Defaults
CONFIG_FILE = Path("agent_config.json")
SANDBOX_DIR = Path("demo_sandbox")
DEFAULT_SERVER_URL = "http://127.0.0.1:8000"


class EndpointAgent:
    def __init__(self, server_url: str = DEFAULT_SERVER_URL):
        self.server_url = server_url.rstrip("/")
        self.endpoint_id = None
        self.public_key_pem = None
        self.file_cache = {}  # {filepath: last_hash} to avoid redundant backups
        self.paused = False   # Flag to freeze backups if ransomware is detected

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
        self.seed_sample_files()

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

            # Save configuration locally (Private key is NEVER sent to the agent)
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

    def seed_sample_files(self):
        """Creates realistic demo files if sandbox is empty for testing."""
        files = list(SANDBOX_DIR.glob("*"))
        if not files:
            print("[*] Demo sandbox is empty. Seeding initial files for testing...")
            sample_data = {
                "financial_q3.txt": "Confidential Q3 Financial Report\nRevenue: $4,500,000\nProfit Margin: 28%",
                "customer_records.csv": "id,name,email\n1,Alice,alice@example.com\n2,Bob,bob@example.com",
                "notes.txt": "Project Akatya Architecture Notes\nHybrid Cryptography + Heuristic Kill-Switch."
            }
            for name, content in sample_data.items():
                file_path = SANDBOX_DIR / name
                file_path.write_text(content)
            print("[✓] Seeded 3 sample files into ./demo_sandbox")

    def encrypt_and_backup(self, file_path: Path):
        """
        Hybrid Encryption Pipeline:
        1. Reads file bytes and computes clean SHA-256 hash.
        2. Encrypts file data using AES-GCM (random 256-bit AES key).
        3. Encrypts AES key using server's RSA Public Key (OAEP SHA-256).
        4. Uploads both to FastAPI server.
        """
        if self.paused:
            print(f"[!] Backup skipped (Agent is paused/threat locked): {file_path.name}")
            return

        if not file_path.is_file():
            return

        # Ignore hidden/system files
        if file_path.name.startswith("."):
            return

        try:
            with open(file_path, "rb") as f:
                file_bytes = f.read()

            if not file_bytes:
                return

            # Compute clean SHA-256 hash
            file_hash = compute_sha256(file_bytes)

            # Debounce check: don't backup if content hasn't changed
            if self.file_cache.get(str(file_path)) == file_hash:
                return

            # 1. AES-GCM encryption of file
            encrypted_data, aes_key = encrypt_aes_gcm(file_bytes)

            # 2. RSA-OAEP encryption of AES key
            encrypted_aes_key = encrypt_rsa_oaep(aes_key, self.public_key_pem)

            # 3. Base64 encode for JSON payload
            payload = {
                "endpoint_id": self.endpoint_id,
                "original_path": str(file_path.name),
                "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode("utf-8"),
                "file_hash": file_hash,
                "encrypted_data_b64": base64.b64encode(encrypted_data).decode("utf-8")
            }

            resp = requests.post(f"{self.server_url}/api/backup", json=payload, timeout=10)
            if resp.status_code == 200:
                result = resp.json()
                self.file_cache[str(file_path)] = file_hash
                print(f"[✓] Securely backed up '{file_path.name}' (Version {result['version']}, SHA-256: {file_hash[:12]}...)")
            else:
                print(f"[!] Backup failed for '{file_path.name}': {resp.text}")

        except Exception as e:
            print(f"[!] Error processing '{file_path.name}': {e}")


class SandboxChangeHandler(FileSystemEventHandler):
    """Watchdog event handler that forwards file modifications to the agent."""
    def __init__(self, agent: EndpointAgent):
        super().__init__()
        self.agent = agent
        self.last_events = {}

    def on_created(self, event):
        if not event.is_directory:
            self._handle_event(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._handle_event(event.src_path)

    def _handle_event(self, path_str: str):
        now = time.time()
        # Debounce to prevent multiple triggers from OS write flushes within 0.3s
        if path_str in self.last_events and (now - self.last_events[path_str]) < 0.3:
            return
        self.last_events[path_str] = now
        self.agent.encrypt_and_backup(Path(path_str))


def start_agent():
    print("=" * 60)
    print("Project Akatya - Endpoint Monitoring Agent Starting...")
    print("=" * 60)

    agent = EndpointAgent()
    agent.initialize()

    # Initial backup pass for all existing sandbox files
    print("\n[*] Performing initial synchronization of sandbox files...")
    for item in SANDBOX_DIR.iterdir():
        if item.is_file() and not item.name.startswith("."):
            agent.encrypt_and_backup(item)

    # Start Watchdog observer
    event_handler = SandboxChangeHandler(agent)
    observer = Observer()
    observer.schedule(event_handler, path=str(SANDBOX_DIR), recursive=False)
    observer.start()

    print(f"\n[✓] Agent is actively monitoring '{SANDBOX_DIR.resolve()}'")
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
