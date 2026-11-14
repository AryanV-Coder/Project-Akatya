import base64
from pathlib import Path
from fastapi import APIRouter, HTTPException
from models.backup import BackupRequest, BackupResponse, BackupListResponse, BackupItem
from utils.db import get_db_cursor

router = APIRouter(tags=["Backups"])

VAULT_DIR = Path("vault_storage")
VAULT_DIR.mkdir(exist_ok=True)


@router.post("/api/backup", response_model=BackupResponse)
def upload_backup(payload: BackupRequest):
    """
    Receives an encrypted file from an endpoint:
    1. Verifies endpoint existence.
    2. Calculates next version for this file.
    3. Writes AES-encrypted file to server vault storage.
    4. Records metadata in Supabase PostgreSQL (backups table).
    """
    try:
        with get_db_cursor(commit=True) as cur:
            # Verify endpoint exists
            cur.execute("SELECT id FROM endpoints WHERE id = %s;", (payload.endpoint_id,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="Endpoint not found")

            # Determine next version
            cur.execute(
                "SELECT COALESCE(MAX(version), 0) FROM backups WHERE endpoint_id = %s AND original_path = %s;",
                (payload.endpoint_id, payload.original_path)
            )
            current_version = cur.fetchone()[0]
            new_version = current_version + 1

            # Decode and write encrypted payload to disk
            encrypted_bytes = base64.b64decode(payload.encrypted_data_b64)
            endpoint_vault = VAULT_DIR / payload.endpoint_id
            endpoint_vault.mkdir(parents=True, exist_ok=True)

            safe_filename = Path(payload.original_path).name
            storage_filename = f"v{new_version}_{safe_filename}.enc"
            disk_path = endpoint_vault / storage_filename

            with open(disk_path, "wb") as f:
                f.write(encrypted_bytes)

            # Insert metadata into Supabase
            insert_query = """
                INSERT INTO backups (endpoint_id, original_path, storage_path, encrypted_aes_key, file_hash, version)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id, version, backed_up_at;
            """
            cur.execute(
                insert_query,
                (payload.endpoint_id, payload.original_path, str(disk_path), payload.encrypted_aes_key, payload.file_hash, new_version)
            )
            row = cur.fetchone()

            return BackupResponse(
                backup_id=str(row[0]),
                endpoint_id=payload.endpoint_id,
                original_path=payload.original_path,
                version=row[1],
                backed_up_at=row[2].isoformat() if row[2] else None,
                status="Success"
            )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Backup failed: {str(e)}")


@router.get("/api/backups/{endpoint_id}", response_model=BackupListResponse)
def list_backups(endpoint_id: str):
    """Lists all backups for a given endpoint."""
    try:
        with get_db_cursor() as cur:
            cur.execute(
                "SELECT id, original_path, version, file_hash, backed_up_at FROM backups WHERE endpoint_id = %s ORDER BY backed_up_at DESC;",
                (endpoint_id,)
            )
            rows = cur.fetchall()
            backups = [
                BackupItem(
                    id=str(r[0]),
                    original_path=r[1],
                    version=r[2],
                    file_hash=r[3],
                    backed_up_at=r[4].isoformat() if r[4] else None
                )
                for r in rows
            ]
            return BackupListResponse(backups=backups)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch backups: {str(e)}")

