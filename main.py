from fastapi import FastAPI, Depends
import models
from database import engine
from sqlalchemy.orm import Session
from database import get_db
from github_client import fetch_dependabot_alerts
from sync_service import sync_dependabot_alerts
import os
import time
from nvd_client import fetch_cve_from_nvd
from cisa_client import fetch_kev_catalog
from rag_service import embed_and_store_cves
from rag_service import query_vulnerabilities_semantic
from pydantic import BaseModel
import contextlib
from mcp_server import mcp

models.Base.metadata.create_all(bind=engine)

# Build the MCP HTTP app and lifespan BEFORE creating the FastAPI app
mcp_app = mcp.streamable_http_app()

@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    async with mcp.session_manager.run():
        yield

# Create the app ONCE, with lifespan wired in from the start
app = FastAPI(title="VulnOps AI", lifespan=lifespan)


@app.get("/")
def read_root():
    return {"message": "VulnOps AI is running"}


@app.post("/sync/dependabot")
def sync_dependabot(db: Session = Depends(get_db)):
    alerts = fetch_dependabot_alerts()
    count = sync_dependabot_alerts(
        alerts,
        os.getenv("GITHUB_REPO_OWNER"),
        os.getenv("GITHUB_REPO_NAME"),
        db
    )
    return {"synced_findings": count, "total_alerts_received": len(alerts)}


@app.post("/sync/enrich")
def enrich_cves(db: Session = Depends(get_db)):
    kev_set = fetch_kev_catalog()
    cves = db.query(models.CVE).all()
    enriched_count = 0

    for cve in cves:
        exploitable_cve = cve.cve_id in kev_set
        cve.is_kev = exploitable_cve

        if cve.cvss_score is None:
            nvd_data = fetch_cve_from_nvd(cve.cve_id)
            if nvd_data and nvd_data["cvss_score"]:
                cve.cvss_score = nvd_data["cvss_score"]
            time.sleep(6)

        enriched_count += 1

    db.commit()
    return {"enriched": enriched_count, "kev_matches": sum(1 for c in cves if c.is_kev)}


@app.post("/sync/embed")
def sync_embed(db: Session = Depends(get_db)):
    return embed_and_store_cves(db)


class QuestionRequest(BaseModel):
    question: str

@app.post("/ask")
def ask_question(request: QuestionRequest):
    return query_vulnerabilities_semantic(request.question)


# Mount MCP LAST, after every other route is registered
app.mount("", mcp_app)