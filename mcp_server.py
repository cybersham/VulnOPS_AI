from mcp.server.fastmcp import FastMCP
from sqlalchemy.orm import Session
from database import sessionLocal
import models
from rag_service import query_vulnerabilities_semantic
from risk_engine import calculate_risk_score
import os 
from mcp.server.transport_security import TransportSecuritySettings

allowed_host = os.getenv("MCP_ALLOWED_HOST", "localhost:*")

mcp = FastMCP(
    "VulnOps AI",
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=["localhost:*", "127.0.0.1:*", allowed_host],
        allowed_origins=["http://localhost:*", "http://127.0.0.1:*", f"https://{allowed_host}"],
    )
)

def get_db_session() -> Session:
     return sessionLocal()

@mcp.tool()
def get_open_findings() -> list[dict]:
    """
    Returns all vulnerability findings that are currently open (unpatched),
    across all tracked repositories. Includes CVE ID, severity, CVSS score,
    affected package, and which repo it was found in.
    """
    db = get_db_session()
    try:
        findings = db.query(models.Findings).filter(models.Findings.status == "open").all()
        results = []
        for f in findings:
            results.append({
                "cve_id": f.cve.cve_id,
                "severity": f.cve.severity,
                "cvss_score": f.cve.cvss_score,
                "affected_package": f.affected_package,
                "repository": f.repository.name,
                "is_kev": f.cve.is_kev
            })
        return results
    finally:
        db.close()

@mcp.tool()
def get_kev_findings() -> list[dict]:
    """
    Returns all OPEN (unpatched) findings whose CVE is on CISA's Known Exploited
    Vulnerabilities (KEV) list — meaning these vulnerabilities are being actively
    exploited in the wild right now and still need remediation.
    """
    db = get_db_session()
    try:
        findings = db.query(models.Findings).join(models.CVE).filter(
            models.CVE.is_kev == True,
            models.Findings.status == "open"
        ).all()
        results = []
        for f in findings:
            results.append({
                "cve_id": f.cve.cve_id,
                "severity": f.cve.severity,
                "cvss_score": f.cve.cvss_score,
                "affected_package": f.affected_package,
                "repository": f.repository.name,
                "status": f.status
            })
        return results
    finally:
        db.close()




@mcp.tool()
def ask_vulnerability_question(question: str) -> dict:
    """
    Answers natural-language, fuzzy questions about vulnerabilities using
    semantic search (RAG) over CVE descriptions. Use this for open-ended or
    conceptual questions that don't map to an exact filter — for example,
    "are there any injection-related vulnerabilities" or "what's my biggest
    risk right now". For exact structured queries (all open findings, all
    KEV findings), prefer get_open_findings or get_kev_findings instead.
    """
    return query_vulnerabilities_semantic(question)



@mcp.tool()
def get_top_risks(limit: int = 10) -> list[dict]:
    """
    Returns findings ranked by computed business risk score (not raw CVSS),
    weighted across Business Criticality, EPSS exploitation probability,
    CISA KEV status, Internet Exposure, and Compensating Controls.
    Use this when asked about "top risks", "highest priority", or "which
    vulnerabilities matter most" — as opposed to get_open_findings, which
    returns everything unranked.
    """
    db = get_db_session()
    try:
        findings = db.query(models.Findings).filter(models.Findings.status == "open").all()

        scored = []
        for f in findings:
            score = calculate_risk_score(f, f.cve, f.repository)
            scored.append({
                "cve_id": f.cve.cve_id,
                "severity": f.cve.severity,
                "cvss_score": f.cve.cvss_score,
                "epss_score": f.cve.epss_score,
                "is_kev": f.cve.is_kev,
                "affected_package": f.affected_package,
                "source": f.source,
                "repository": f.repository.name,
                "risk_score": score
            })

        scored.sort(key=lambda x: x["risk_score"], reverse=True)
        return scored[:limit]
    finally:
        db.close()

if __name__ == "__main__":
    mcp.run(transport="stdio")


