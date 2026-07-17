from mcp.server.fastmcp import FastMCP
from sqlalchemy.orm import Session
from database import sessionLocal
import models
from rag_service import query_vulnerabilities_semantic

mcp = FastMCP("VulnOPS AI")

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

if __name__ == "__main__":
    mcp.run(transport="stdio")


