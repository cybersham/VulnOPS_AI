from fastapi import FastAPI,Depends
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

models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="VulnOps AI")

@app.get("/")
def read_root():
    return {"message": "VulnOps AI is running"}


from github_client import fetch_dependabot_alerts


# @app.get("/test-github")
# def test_github():
#     return fetch_dependabot_alerts()

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
def enrich_cves(db:Session = Depends(get_db)):
    kev_set = fetch_kev_catalog() #### CISA CATALOG CVE INFORMATION actively exploitable cves
    cves = db.query(models.CVE).all() ##### calling the DB table 
    enriched_count=0
    

    for cve in cves:
        exploitable_cve = cve.cve_id in kev_set  #### fetching the rows from the table cves 
        cve.is_kev = exploitable_cve #### her updating the db column CVE ID 
         
        # NVD lookup — only if we don't already have a CVSS score
        if cve.cvss_score is None:
            nvd_data = fetch_cve_from_nvd(cve.cve_id)
            if nvd_data and nvd_data["cvss_score"]:
                cve.cvss_score = nvd_data["cvss_score"]
            time.sleep(6)  # pace requests to respect NVD rate limits

        enriched_count += 1

    db.commit()
    return {"enriched": enriched_count, "kev_matches": sum(1 for c in cves if c.is_kev)}



   



