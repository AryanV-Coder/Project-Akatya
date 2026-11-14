from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from routers.endpoints import router as endpoints_router
from routers.backups import router as backups_router
from routers.incidents import router as incidents_router
from routers.recovery import router as recovery_router

app = FastAPI(
    title="Project Akatya - Ransomware-Resilient Backup Backend",
    description="Host-based Ransomware Defense, Asymmetric Cryptography Vault & Section 65B Legal Evidence API",
    version="1.0.0"
)

# Allow CORS for web dashboard communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register modular routers
app.include_router(endpoints_router)
app.include_router(backups_router)
app.include_router(incidents_router)
app.include_router(recovery_router)


@app.get("/")
def root():
    return {
        "project": "Project Akatya",
        "status": "Online",
        "architecture": "Modular FastAPI (models, routers, utils)",
        "modules": [
            "/api/register",
            "/api/endpoints",
            "/api/backup",
            "/api/backups/{endpoint_id}",
            "/api/incident",
            "/api/incidents",
            "/api/recover/{endpoint_id}"
        ]
    }


if __name__ == "__main__":
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)
