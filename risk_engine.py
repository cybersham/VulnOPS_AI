def calculate_risk_score(finding, cve, repository) -> float:
    """
    Risk Score = 30% Business Criticality + 25% EPSS + 20% KEV
               + 15% Internet Exposure + 10% Compensating Controls
    All components normalized to a 0-100 scale before weighting.
    """
    business_criticality_score = (repository.business_criticality / 5) * 100
    epss_score = (cve.epss_score or 0) * 100  # EPSS is already 0-1, scale to 0-100
    kev_score = 100 if cve.is_kev else 0
    exposure_score = 100 if repository.internet_exposed else 0
    controls_score = 100 - ((repository.compensating_controls / 5) * 100)  # more controls = less risk

    risk_score = (
        0.30 * business_criticality_score +
        0.25 * epss_score +
        0.20 * kev_score +
        0.15 * exposure_score +
        0.10 * controls_score
    )

    return round(risk_score, 2)
