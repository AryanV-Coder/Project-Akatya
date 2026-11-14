from pydantic import BaseModel
from typing import Optional, List


class RegisterRequest(BaseModel):
    hostname: str


class EndpointResponse(BaseModel):
    endpoint_id: str
    hostname: str
    public_key: str
    status: str
    created_at: Optional[str] = None
    message: Optional[str] = None


class EndpointItem(BaseModel):
    id: str
    hostname: str
    public_key: str
    status: str
    created_at: Optional[str] = None


class EndpointListResponse(BaseModel):
    endpoints: List[EndpointItem]

