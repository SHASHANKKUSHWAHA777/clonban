"""
Scoring Engine (V3 — Phase 6)

Combines identity + similarity + dex-risk signals into three DIFFERENT
numbers, deliberately kept separate per the project brief:

  - clone_probability: how likely the candidate is a copy/impersonation
    of the original (similarity-driven; certificate mismatch is evidence,
    not proof)
  - malware_risk: how likely the candidate exhibits malicious behavior
    (finding-driven; independent of how similar it looks to the original)
  - confidence: how much we trust clone_probability, based on how much
    evidence was actually available (e.g. layout/string extraction failing
    should lower confidence, not silently get ignored)

Null handling (V3 rule: never silently convert unavailable to 0):
  - When a component score is null, it contributes 0.0 to the weighted
    sum but is NOT counted as "available" for confidence calculation.
  - The scoring engine uses 0.0 as a neutral value in the weighted
    average — this is an explicit scoring decision, not a silent
    conversion. The confidence score reflects the gap.

No accuracy numbers are invented; confidence reflects evidence coverage,
not a validated true-positive rate (project rule #6).
"""

DEFAULT_WEIGHTS = {
    "certificate": 0.15,
    "package": 0.10,
    "icon": 0.15,
    "strings": 0.15,
    "layout": 0.10,
    "dex": 0.20,
    "resources": 0.15,
}


def _normalize_weights(weights: dict) -> dict:
    total = sum(weights.values()) or 1.0
    return {k: v / total for k, v in weights.items()}


def _resolve_component_scores(identity: dict, similarity: dict, dex: dict) -> dict:
    """
    Resolve each component score, preferring V3 fields but falling back
    to legacy field names for backward compatibility.

    Returns a dict where values may be None (unavailable).
    """
    scores = {}

    # Certificate: V3 wants certificate_identity_score; legacy is certificate_score
    cert = identity.get("certificate_identity_score")
    if cert is None:
        cert = identity.get("certificate_score")
    scores["certificate"] = cert  # may be None

    # Package: V3 wants package_similarity; legacy is package_score
    pkg = identity.get("package_similarity")
    if pkg is None:
        pkg = identity.get("package_score")
    scores["package"] = pkg  # may be None

    # Similarity components (unchanged field names)
    scores["icon"] = similarity.get("icon_score") if similarity else None
    scores["strings"] = similarity.get("string_score") if similarity else None
    scores["layout"] = similarity.get("layout_score") if similarity else None
    scores["resources"] = similarity.get("resource_score") if similarity else None

    # DEX: V3 wants bytecode_similarity; legacy is dex_score
    dex_sim = dex.get("bytecode_similarity")
    if dex_sim is None:
        dex_sim = dex.get("dex_score")
    scores["dex"] = dex_sim  # may be None

    return scores


def compute_scores(identity: dict, similarity: dict, dex: dict, weights: dict | None = None) -> dict:
    weights = _normalize_weights(weights or DEFAULT_WEIGHTS)

    raw_component_scores = _resolve_component_scores(identity, similarity, dex)

    # For the weighted sum, treat None as 0.0 (neutral). This is an explicit
    # scoring decision — the confidence metric tracks the gap.
    component_scores = {
        k: round(v, 4) if v is not None else 0.0
        for k, v in raw_component_scores.items()
    }

    clone_probability = sum(component_scores[k] * weights[k] for k in weights)
    clone_probability = round(min(max(clone_probability, 0.0), 1.0), 4)

    # Malware risk: V3 wants malware_risk_score (int 0-100), legacy is malware_risk (float 0-1)
    mr_score = dex.get("malware_risk_score")
    if mr_score is not None:
        malware_risk = round(min(max(mr_score / 100.0, 0.0), 1.0), 4)
    else:
        malware_risk = round(min(max(dex.get("malware_risk") or 0.0, 0.0), 1.0), 4)

    # Confidence = evidence coverage: how many of the 7 components produced
    # a non-null signal, penalized further when the underlying extraction
    # reported a parse error.
    available = [v for v in raw_component_scores.values() if v is not None]
    non_zero = [v for v in available if v > 0]
    coverage = len(non_zero) / max(len(raw_component_scores), 1)

    parse_penalty = 0.0
    # Check both V3 "errors" and legacy "findings" for parse errors
    identity_errors = identity.get("errors", [])
    for err in identity_errors:
        if err.get("stage") in ("parse", "PARSE_ERROR"):
            parse_penalty = 0.5

    legacy_findings = identity.get("findings", [])
    for f in legacy_findings:
        if f.get("type") == "PARSE_ERROR":
            parse_penalty = 0.5
        if f.get("type") == "PARSE_FAILED":
            parse_penalty = 0.5

    # Also check V3 manifest_findings for parse errors
    for f in identity.get("manifest_findings", []):
        ftype = f.get("type") or f.get("finding")
        if ftype and "PARSE" in str(ftype).upper():
            parse_penalty = 0.5

    # Agreement: low variance among component scores means the signals
    # agree with each other, which is itself evidence of a trustworthy read.
    if available:
        mean = sum(available) / len(available)
        variance = sum((v - mean) ** 2 for v in available) / len(available)
        agreement = max(0.0, 1 - variance)
    else:
        agreement = 0.0

    confidence = round(max(0.0, min(1.0, (0.6 * coverage + 0.4 * agreement) - parse_penalty)), 4)

    verdict_summary = _build_verdict(clone_probability, malware_risk, confidence, identity, component_scores)

    return {
        "clone_probability": clone_probability,
        "malware_risk": malware_risk,
        "confidence": confidence,
        "weights_used": weights,
        "component_scores": component_scores,
        "verdict_summary": verdict_summary,
    }


def _build_verdict(clone_probability, malware_risk, confidence, identity, components) -> str:
    clone_band = "high" if clone_probability >= 0.75 else "moderate" if clone_probability >= 0.4 else "low"
    risk_band = "high" if malware_risk >= 0.6 else "moderate" if malware_risk >= 0.3 else "low"

    # Prefer V3 certificate_status, fall back to legacy certificate_match
    cert_status = identity.get("certificate_status")
    if cert_status == "SAME_SIGNER":
        cert_note = "matching signing certificate"
    elif cert_status == "DIFFERENT_SIGNER":
        cert_note = "a different signing certificate"
    else:
        cert_note = "a different signing certificate" if not identity.get("certificate_match") else "matching signing certificate"

    strongest = max(components, key=components.get)

    return (
        f"{clone_band.capitalize()} clone probability ({clone_probability:.0%}), driven mainly by "
        f"{strongest} similarity, despite {cert_note}. Malware risk is {risk_band} ({malware_risk:.0%}). "
        f"Confidence in this read is {confidence:.0%} based on available evidence coverage."
    )
