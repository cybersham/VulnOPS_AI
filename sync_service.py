from sqlalchemy.orm import Session
from datetime import datetime
import models


def sync_dependabot_alerts(alerts: list, repo_owner: str, repo_name: str, db: Session):
    # Get or create the repository row
    repo = db.query(models.Repository).filter(
        models.Repository.name == repo_name,
        models.Repository.owner == repo_owner
    ).first()

    if not repo:
        repo = models.Repository(
            name=repo_name,
            owner=repo_owner,
            url=f"https://github.com/{repo_owner}/{repo_name}"
        )
        db.add(repo)
        db.commit()
        db.refresh(repo)

    synced_count = 0

    for alert in alerts:
        advisory = alert.get("security_advisory", {})
        cve_id = advisory.get("cve_id")

        if not cve_id:
            continue  # some advisories use GHSA IDs only, skip for now

        # Get or create the CVE row
        cve = db.query(models.CVE).filter(models.CVE.cve_id == cve_id).first()
        if not cve:
            severity = advisory.get("severity", "").upper()
            cvss = advisory.get("cvss", {}).get("score")
            published = advisory.get("published_at")

            cve = models.CVE(
                cve_id=cve_id,
                description=advisory.get("summary", ""),
                cvss_score=cvss,
                severity=severity,
                published_date=datetime.fromisoformat(published.replace("Z", "+00:00")) if published else None
            )
            db.add(cve)
            db.commit()
            db.refresh(cve)

        # Get or create the Finding row (avoid duplicate findings for same cve+repo+package)
        package_name = alert.get("dependency", {}).get("package", {}).get("name", "unknown")

        existing_finding = db.query(models.Findings).filter(
            models.Findings.cve_id == cve.id,
            models.Findings.repository_id == repo.id,
            models.Findings.affected_package == package_name
        ).first()

        if not existing_finding:
            finding = models.Findings(
                cve_id=cve.id,
                repository_id=repo.id,
                affected_package=package_name,
                affected_version=alert.get("dependency", {}).get("manifest_path", ""),
                status=alert.get("state", "open")
            )
            db.add(finding)
            db.commit()
            synced_count += 1

    return synced_count