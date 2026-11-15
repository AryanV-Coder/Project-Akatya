import os
import sys
import time
from pathlib import Path

# SAFETY CONSTRAINT: Confinement strictly to demo_sandbox
SANDBOX_DIR = Path("demo_sandbox").resolve()


def run_ransomware_simulation():
    print("=" * 60)
    print("⚠️  PROJECT AKATYA - RANSOMWARE SIMULATOR (BENCHMARK)")
    print("=" * 60)
    print(f"[*] Target Directory strictly restricted to: {SANDBOX_DIR}")

    if not SANDBOX_DIR.exists():
        SANDBOX_DIR.mkdir(parents=True, exist_ok=True)

    # Ensure there are at least 15 target files to simulate a multi-file attack
    print("[*] Preparing test environment in demo_sandbox...")
    for i in range(1, 16):
        target = SANDBOX_DIR / f"work_file_{i}.txt"
        if not target.exists():
            target.write_text(f"Important company document #{i}\nFinancial and operational data: {i * 1000}")

    target_files = sorted([f for f in SANDBOX_DIR.iterdir() if f.is_file() and not f.name.startswith(".")])
    print(f"[*] Found {len(target_files)} target files in sandbox.")
    print("[*] Commencing rapid encryption attack (>5 modifications/second)...")
    print("[*] Attempting to encrypt all files before defense system reacts...\n")

    files_encrypted = 0
    try:
        for f in target_files:
            # Overwrite file with ransomware banner + encrypted noise
            encrypted_payload = (
                b"[LOCKED_BY_RANSOMWARE_AKATYA_TEST]\n"
                b"CRITICAL WARNING: Your sensitive documents have been encrypted.\n"
                b"Deposit 0.5 BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n"
                + os.urandom(256)
            )
            with open(f, "wb") as file_out:
                file_out.write(encrypted_payload)

            files_encrypted += 1
            print(f"[ATTACK] 🔒 Encrypted: {f.name} (File #{files_encrypted})")
            
            # Short sleep to fire 8-12 modifications/sec
            time.sleep(0.08)

        print(f"\n[!] Attack finished completely. Total files locked: {files_encrypted}")

    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user.")
    except Exception as e:
        print(f"\n[!] Attack interrupted by system: {e}")


if __name__ == "__main__":
    run_ransomware_simulation()
