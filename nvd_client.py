import os
import time
import requests

NVD_API_KEY = os.getenv("NVD_API_KEY")
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_cve_from_nvd(cve_id: str):
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    params = {"cveId": cve_id}

    response = requests.get(NVD_BASE_URL, headers=headers, params=params)
    response.raise_for_status()
    data = response.json()

    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        return None

    cve_data = vulnerabilities[0]["cve"]

    # Try CVSS v3.1 first, fall back to v3.0
    metrics = cve_data.get("metrics", {})
    cvss_score = None
    if "cvssMetricV31" in metrics:
        cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
    elif "cvssMetricV30" in metrics:
        cvss_score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]

    return {"cvss_score": cvss_score}