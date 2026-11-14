from pydantic import BaseModel
from typing import Optional, List


class BackupRequest(BaseModel):
    endpoint_id: str
    original_path: str
    encrypted_aes_key: str        # Base64-encoded RSA-encrypted AES key
    file_hash: str                # SHA-256 clean file hash
    encrypted_data_b64: str       # Base64-encoded encrypted file content


class BackupResponse(BaseModel):
    backup_id: str
    endpoint_id: str
    original_path: str
    version: int
    backed_up_at: Optional[str] = None
    status: str


class BackupItem(BaseModel):
    id: str
    original_path: str
    version: int
    file_hash: str
    backed_up_at: Optional[str] = None


class BackupListResponse(BaseModel):
    backups: List[BackupItem]

