import base64
from fastapi import APIRouter, HTTPException
from utils.db import get_db_cursor
from utils.crypto import decrypt_rsa_oaep, decrypt_aes_gcm, compute_sha256
from utils.storage import download_from_storage

router = APIRouter(tags=["Recovery"])


@router.post("/api/recover/{endpoint_id}")
def recover_endpoint_files(endpoint_id: str):
    """
    Recovers the latest clean backup of all files for an endpoint:
    1. Fetches the endpoint's securely stored RSA Private Key from Supabase PostgreSQL.
    2. Queries the latest version of every backed-up file.
    3. Downloads the encrypted ciphertext directly from Supabase Storage bucket 'akatya-backups'.
    4. Decrypts AES key using the RSA Private Key.
    5. Decrypts file content using AES-GCM and verifies SHA-256 hash.
    6. Returns clean files payload.
    """
    try:
        with get_db_cursor() as cur:
            # 1. Fetch endpoint and its private key
            cur.execute("SELECT hostname, private_key FROM endpoints WHERE id = %s;", (endpoint_id,))
            ep = cur.fetchone()
            if not ep:
                raise HTTPException(status_code=404, detail="Endpoint not found")

            hostname, private_key_pem = ep[0], ep[1]

            # 2. Fetch latest version of each file for this endpoint
            latest_backups_query = """
                SELECT DISTINCT ON (original_path) 
                       id, original_path, storage_path, encrypted_aes_key, file_hash, version
                FROM backups
                WHERE endpoint_id = %s
                ORDER BY original_path, version DESC;
            """
            cur.execute(latest_backups_query, (endpoint_id,))
            rows = cur.fetchall()

            if not rows:
                return {
                    "endpoint_id": endpoint_id,
                    "hostname": hostname,
                    "message": "No backups found for this endpoint.",
                    "recovered_files": []
                }

            recovered_files = []
            for r in rows:
                backup_id, original_path, storage_path_str, enc_aes_key_b64, expected_hash, version = r

                try:
                    # Download encrypted file directly from Supabase Object Storage
                    encrypted_blob = download_from_storage(storage_path_str)

                    # Decrypt AES key with RSA Private Key
                    enc_aes_key = base64.b64decode(enc_aes_key_b64)
                    aes_key = decrypt_rsa_oaep(enc_aes_key, private_key_pem)

                    # Decrypt file content with AES-GCM
                    decrypted_bytes = decrypt_aes_gcm(encrypted_blob, aes_key)

                    # Verify SHA-256 integrity
                    calculated_hash = compute_sha256(decrypted_bytes)
                    hash_verified = (calculated_hash == expected_hash)

                    recovered_files.append({
                        "filename": original_path,
                        "version": version,
                        "storage_path": storage_path_str,
                        "hash_verified": hash_verified,
                        "sha256": calculated_hash,
                        "content_b64": base64.b64encode(decrypted_bytes).decode("utf-8")
                    })
                except Exception as file_err:
                    print(f"[!] Error recovering file '{original_path}': {file_err}")
                    continue

            return {
                "endpoint_id": endpoint_id,
                "hostname": hostname,
                "total_recovered": len(recovered_files),
                "recovered_files": recovered_files,
                "message": f"Successfully recovered {len(recovered_files)} clean file(s) from Supabase Cloud Storage."
            }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Recovery failed: {str(e)}")
