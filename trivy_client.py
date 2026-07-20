import json


# def parse_trivy_report(file_path: str) -> list[dict]:
#     with open(file_path) as f:
#         data = json.load(f)

#     parsed_vulns = []
#     for result in data.get("Results", []):
#         target = result.get("Target", "unknown")
#         for vuln in result.get("Vulnerabilities", []):
#             parsed_vulns.append({
#                 "cve_id": vuln.get("VulnerabilityID"),
#                 "package": vuln.get("PkgName"),
#                 "installed_version": vuln.get("InstalledVersion"),
#                 "severity": vuln.get("Severity"),
#                 "title": vuln.get("Title", ""),
#                 "description": vuln.get("Description", vuln.get("Title", "")),
#                 "target": target
#             })
#     return parsed_vulns

def parse_trivy_report(data: dict) -> list[dict]: ####Notice: it now takes data: dict (already-parsed JSON), not a file path string.
    parsed_vulns = []
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            parsed_vulns.append({
                "cve_id": vuln.get("VulnerabilityID"),
                "package": vuln.get("PkgName"),
                "installed_version": vuln.get("InstalledVersion"),
                "severity": vuln.get("Severity"),
                "description": vuln.get("Description", vuln.get("Title", ""))
            })
    return parsed_vulns