import requests

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def fetch_kev_catalog():
    response = requests.get(KEV_URL)
    response.raise_for_status()
    data = response.json()
    # Return a set of CVE IDs for fast lookup
    return {entry["cveID"] for entry in data.get("vulnerabilities", [])}

