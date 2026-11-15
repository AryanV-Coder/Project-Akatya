import base64
from pathlib import Path
from fastapi import APIRouter, HTTPException
from models.backup import BackupRequest, BackupResponse, BackupListResponse, BackupItem
from utils.db import get_db_cursor
from utils.storage import upload_to_storage

router = APIRouter(tags=["Backups"])


@router.post("/api/backup", response_model=BackupResponse)
def upload_backup(payload: BackupRequest):
    """
    Receives an encrypted file from an endpoint:
    1. Verifies endpoint existence.
    2. Calculates next version for this file.
    3. Uploads AES-encrypted payload directly to Supabase Storage bucket 'akatya-backups'.
    4. Records metadata and storage path in Supabase PostgreSQL (backups table).
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

            # Decode encrypted bytes
            encrypted_bytes = base64.b64decode(payload.encrypted_data_b64)

            # Upload directly to Supabase Cloud Storage bucket (akatya-backups)
            safe_filename = Path(payload.original_path).name
            storage_object_name = f"{payload.endpoint_id}/v{new_version}_{safe_filename}.enc"
            storage_path_str = upload_to_storage(storage_object_name, encrypted_bytes)

            # Insert metadata into Supabase PostgreSQL
            insert_query = """
                INSERT INTO backups (endpoint_id, original_path, storage_path, encrypted_aes_key, file_hash, version)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id, version, backed_up_at;
            """
            cur.execute(
                insert_query,
                (payload.endpoint_id, payload.original_path, storage_path_str, payload.encrypted_aes_key, payload.file_hash, new_version)
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
