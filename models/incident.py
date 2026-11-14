from pydantic import BaseModel
from typing import Optional, List


class EvidenceItem(BaseModel):
    corrupted_filepath: str
    corrupted_hash: str


class IncidentReportRequest(BaseModel):
    endpoint_id: str
    process_killed: bool = True
    evidence: List[EvidenceItem] = []


class IncidentResponse(BaseModel):
    incident_id: str
    endpoint_id: str
    attack_timestamp: str
    process_killed: bool
    evidence_count: int
    message: str


class IncidentItem(BaseModel):
    id: str
    endpoint_id: str
    hostname: Optional[str] = None
    attack_timestamp: str
    process_killed: bool
    report_generated: bool
    evidence_count: int = 0

