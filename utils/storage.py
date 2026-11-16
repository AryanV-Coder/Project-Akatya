import os
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from dotenv import load_dotenv

load_dotenv()

# Extract project reference from postgres username (e.g., 'postgres.oqmiprgsqhwcgrtqjjwf')
_user = os.getenv("user", "")
_project_ref = _user.split(".")[1] if "." in _user else ""

SUPABASE_URL = os.getenv("SUPABASE_URL", f"https://{_project_ref}.supabase.co")
SECRET_KEY = os.getenv("secret_key", "")
BUCKET_NAME = "akatya-backups"

STORAGE_BASE_URL = f"{SUPABASE_URL}/storage/v1"

# Shared session with connection pool to prevent per-request TLS negotiation overhead
_session = requests.Session()
_adapter = HTTPAdapter(
    pool_connections=20,
    pool_maxsize=20,
    max_retries=Retry(total=3, backoff_factor=0.3, status_forcelist=[500, 502, 503, 504])
)
_session.mount("https://", _adapter)
_session.mount("http://", _adapter)


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

    resp = _session.post(url, headers=headers, data=data, timeout=20)
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
    resp = _session.get(url, headers=get_headers(), timeout=20)

    if resp.status_code != 200:
        raise RuntimeError(f"Failed to download from Supabase Storage ({resp.status_code}): {resp.text}")

    return resp.content


