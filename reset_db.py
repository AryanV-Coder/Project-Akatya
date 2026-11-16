import os
import sys
from utils.db import get_db_cursor

def reset_all_tables(include_endpoints: bool = True):
    """
    Truncates all tables in Supabase PostgreSQL.
    If include_endpoints is True, also resets endpoints and removes agent_config.json.
    """
    print("[*] Connecting to Supabase database...")
    try:
        with get_db_cursor() as cur:
            if include_endpoints:
                cur.execute("TRUNCATE TABLE incident_evidence, incidents, backups, endpoints CASCADE;")
                print("[✓] Successfully wiped all rows from: 'incident_evidence', 'incidents', 'backups', 'endpoints'.")

                # Remove local agent registration so it generates a fresh keypair & ID
                if os.path.exists("agent_config.json"):
                    os.remove("agent_config.json")
                    print("[✓] Removed local 'agent_config.json' for clean re-registration.")
            else:
                cur.execute("TRUNCATE TABLE incident_evidence, incidents, backups CASCADE;")
                print("[✓] Successfully wiped rows from: 'incident_evidence', 'incidents', 'backups' (endpoints preserved).")

    except Exception as e:
        print(f"[!] Error truncating database tables: {e}")
        sys.exit(1)

if __name__ == "__main__":
    # By default, wipe everything
    reset_all_tables(include_endpoints=True)

