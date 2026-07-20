import requests

def fetch_epss_scores(cve_ids: list[str]) -> dict:
    """Returns {cve_id: epss_score} for a batch of CVE IDs."""
    ids_param = ",".join(cve_ids)
    url = f"https://api.first.org/data/v1/epss?cve={ids_param}"
    response = requests.get(url)
    response.raise_for_status()
    data = response.json()

    return {item["cve"]: float(item["epss"]) for item in data.get("data", [])}