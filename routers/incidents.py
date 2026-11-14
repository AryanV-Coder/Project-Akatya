from fastapi import APIRouter, HTTPException
from typing import List, Dict, Any
from models.incident import (
    IncidentReportRequest, IncidentResponse, IncidentItem, EvidenceItem
)
from utils.db import get_db_cursor

router = APIRouter(tags=["Incidents"])


@router.post("/api/incident", response_model=IncidentResponse)
def report_incident(payload: IncidentReportRequest):
    """
    Logs a ransomware attack incident reported by an endpoint agent:
    1. Inserts incident into `incidents` table.
    2. Logs each corrupted file and its hash into `incident_evidence` table.
    """
    try:
        with get_db_cursor(commit=True) as cur:
            # Verify endpoint exists
            cur.execute("SELECT id FROM endpoints WHERE id = %s;", (payload.endpoint_id,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="Endpoint not found")

            # 1. Insert incident record
            incident_query = """
                INSERT INTO incidents (endpoint_id, process_killed, report_generated)
                VALUES (%s, %s, FALSE)
                RETURNING id, attack_timestamp, process_killed;
            """
            cur.execute(incident_query, (payload.endpoint_id, payload.process_killed))
            inc_row = cur.fetchone()
            incident_id = str(inc_row[0])
            attack_timestamp = inc_row[1].isoformat() if inc_row[1] else None

            # 2. Insert incident evidence
            for ev in payload.evidence:
                ev_query = """
                    INSERT INTO incident_evidence (incident_id, corrupted_filepath, corrupted_hash)
                    VALUES (%s, %s, %s);
                """
                cur.execute(ev_query, (incident_id, ev.corrupted_filepath, ev.corrupted_hash))

            return IncidentResponse(
                incident_id=incident_id,
                endpoint_id=payload.endpoint_id,
                attack_timestamp=attack_timestamp,
                process_killed=inc_row[2],
                evidence_count=len(payload.evidence),
                message="Ransomware incident logged and digital evidence recorded."
            )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to record incident: {str(e)}")


@router.get("/api/incidents", response_model=List[IncidentItem])
def list_incidents():
    """Lists all recorded incidents with endpoint details and evidence counts."""
    try:
        with get_db_cursor() as cur:
            query = """
                SELECT i.id, i.endpoint_id, e.hostname, i.attack_timestamp, i.process_killed, 
                       i.report_generated, COUNT(ev.id) as evidence_count
                FROM incidents i
                LEFT JOIN endpoints e ON i.endpoint_id = e.id
                LEFT JOIN incident_evidence ev ON i.id = ev.incident_id
                GROUP BY i.id, i.endpoint_id, e.hostname, i.attack_timestamp, i.process_killed, i.report_generated
                ORDER BY i.attack_timestamp DESC;
            """
            cur.execute(query)
            rows = cur.fetchall()

            incidents = [
                IncidentItem(
                    id=str(r[0]),
                    endpoint_id=str(r[1]),
                    hostname=r[2],
                    attack_timestamp=r[3].isoformat() if r[3] else None,
                    process_killed=r[4],
                    report_generated=r[5],
                    evidence_count=r[6]
                )
                for r in rows
            ]
            return incidents
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch incidents: {str(e)}")


@router.get("/api/incidents/{incident_id}")
def get_incident_details(incident_id: str):
    """Fetches complete incident metadata and its forensic evidence entries."""
    try:
        with get_db_cursor() as cur:
            cur.execute("""
                SELECT i.id, i.endpoint_id, e.hostname, i.attack_timestamp, i.process_killed, i.report_generated
                FROM incidents i
                JOIN endpoints e ON i.endpoint_id = e.id
                WHERE i.id = %s;
            """, (incident_id,))
            inc = cur.fetchone()
            if not inc:
                raise HTTPException(status_code=404, detail="Incident not found")

            cur.execute("""
                SELECT id, corrupted_filepath, corrupted_hash
                FROM incident_evidence
                WHERE incident_id = %s;
            """, (incident_id,))
            ev_rows = cur.fetchall()

            evidence = [
                {
                    "id": str(r[0]),
                    "corrupted_filepath": r[1],
                    "corrupted_hash": r[2]
                }
                for r in ev_rows
            ]

            return {
                "id": str(inc[0]),
                "endpoint_id": str(inc[1]),
                "hostname": inc[2],
                "attack_timestamp": inc[3].isoformat() if inc[3] else None,
                "process_killed": inc[4],
                "report_generated": inc[5],
                "evidence": evidence
            }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch incident details: {str(e)}")

