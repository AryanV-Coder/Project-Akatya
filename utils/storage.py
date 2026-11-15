import os
import requests
from dotenv import load_dotenv

load_dotenv()

# Extract project reference from postgres username (e.g., 'postgres.oqmiprgsqhwcgrtqjjwf')
_user = os.getenv("user", "")
_project_ref = _user.split(".")[1] if "." in _user else ""

SUPABASE_URL = os.getenv("SUPABASE_URL", f"https://{_project_ref}.supabase.co")
SECRET_KEY = os.getenv("secret_key", "")
BUCKET_NAME = "akatya-backups"

STORAGE_BASE_URL = f"{SUPABASE_URL}/storage/v1"


def get_headers():
    return {
        "Authorization": f"Bearer {SECRET_KEY}",
        "apikey": SECRET_KEY,
        "x-upsert": "true"
    }


def upload_to_storage(object_path: str, data: bytes) -> str:
    """
    Uploads encrypted bytes directly to Supabase Storage bucket 'akatya-backups'.
    Returns the object path inside the bucket.
    """
    clean_path = object_path.lstrip("/")
    url = f"{STORAGE_BASE_URL}/object/{BUCKET_NAME}/{clean_path}"

    headers = {
        **get_headers(),
        "Content-Type": "application/octet-stream"
    }

    resp = requests.post(url, headers=headers, data=data, timeout=15)
    if resp.status_code not in (200, 201):
        raise RuntimeError(f"Failed to upload to Supabase Storage ({resp.status_code}): {resp.text}")

    return f"{BUCKET_NAME}/{clean_path}"


def download_from_storage(object_path: str) -> bytes:
    """
    Downloads encrypted bytes directly from Supabase Storage bucket 'akatya-backups'.
    """
    # Remove bucket prefix if included
    clean_path = object_path
    if clean_path.startswith(f"{BUCKET_NAME}/"):
        clean_path = clean_path[len(f"{BUCKET_NAME}/"):]
    clean_path = clean_path.lstrip("/")

    url = f"{STORAGE_BASE_URL}/object/authenticated/{BUCKET_NAME}/{clean_path}"
    resp = requests.get(url, headers=get_headers(), timeout=15)

    if resp.status_code != 200:
        raise RuntimeError(f"Failed to download from Supabase Storage ({resp.status_code}): {resp.text}")

    return resp.content

