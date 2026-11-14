from fastapi import APIRouter, HTTPException
from models.endpoint import RegisterRequest, EndpointResponse, EndpointListResponse, EndpointItem
from utils.crypto import generate_rsa_keypair
from utils.db import get_db_cursor

router = APIRouter(tags=["Endpoints"])


@router.post("/api/register", response_model=EndpointResponse)
def register_endpoint(payload: RegisterRequest):
    """
    Registers a target endpoint:
    1. Generates a unique 2048-bit RSA key pair.
    2. Stores the private and public key in Supabase PostgreSQL (endpoints table).
    3. Returns the public key and endpoint_id back to the agent.
    """
    try:
        private_pem, public_pem = generate_rsa_keypair()

        with get_db_cursor(commit=True) as cur:
            query = """
                INSERT INTO endpoints (hostname, public_key, private_key, status)
                VALUES (%s, %s, %s, 'Active')
                RETURNING id, hostname, public_key, status, created_at;
            """
            cur.execute(query, (payload.hostname, public_pem, private_pem))
            row = cur.fetchone()

            return EndpointResponse(
                endpoint_id=str(row[0]),
                hostname=row[1],
                public_key=row[2],
                status=row[3],
                created_at=row[4].isoformat() if row[4] else None,
                message="Endpoint successfully registered. Public key distributed."
            )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")


@router.get("/api/endpoints", response_model=EndpointListResponse)
def list_endpoints():
    """Returns all registered endpoints."""
    try:
        with get_db_cursor() as cur:
            cur.execute("SELECT id, hostname, public_key, status, created_at FROM endpoints ORDER BY created_at DESC;")
            rows = cur.fetchall()

            endpoints = [
                EndpointItem(
                    id=str(r[0]),
                    hostname=r[1],
                    public_key=r[2],
                    status=r[3],
                    created_at=r[4].isoformat() if r[4] else None
                )
                for r in rows
            ]
            return EndpointListResponse(endpoints=endpoints)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch endpoints: {str(e)}")

