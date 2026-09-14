"""
Scoring Engine (Phase 6)

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

No accuracy numbers are invented; confidence reflects evidence coverage,
not a validated true-positive rate (project rule #6).
"""

DEFAULT_WEIGHTS = {
    "certificate": 0.12,
    "package": 0.08,
    "icon": 0.12,
    "strings": 0.13,
    "layout": 0.10,
    "dex": 0.18,
    "resources": 0.12,
    "manifest": 0.08,
    "permissions": 0.07,
}


def _normalize_weights(weights: dict) -> dict:
    total = sum(weights.values()) or 1.0
    return {k: v / total for k, v in weights.items()}


def compute_scores(identity: dict, similarity: dict, dex: dict, weights: dict | None = None) -> dict:
    weights = _normalize_weights(weights or DEFAULT_WEIGHTS)

    component_scores = {
        "certificate": identity.get("certificate_score") or 0.0,
        "package": identity.get("package_score") or 0.0,
        "icon": similarity.get("icon_score") or 0.0,
        "strings": similarity.get("string_score") or 0.0,
        "layout": similarity.get("layout_score") or 0.0,
        "dex": dex.get("dex_score") or 0.0,
        "resources": similarity.get("resource_score") or 0.0,
        "manifest": identity.get("manifest_score") or 0.0,
        "permissions": identity.get("permissions_score") or 0.0,
    }

    clone_probability = sum(component_scores[k] * weights.get(k, 0.0) for k in component_scores)
    clone_probability = round(min(max(clone_probability, 0.0), 1.0), 4)

    malware_risk = round(min(max(dex.get("malware_risk") or 0.0, 0.0), 1.0), 4)

    # Confidence = evidence coverage: how many of the 9 components produced
    # a non-zero, non-null signal, penalized further when the underlying
    # extraction reported a parse error.
    available = [v for v in component_scores.values() if v is not None]
    non_zero = [v for v in available if v > 0]
    coverage = len(non_zero) / max(len(component_scores), 1)

    parse_penalty = 0.0
    for f in identity.get("findings", []):
        if f.get("type") == "PARSE_ERROR":
            parse_penalty = 0.5

    # Agreement: low variance among component scores means the signals
    # agree with each other, which is itself evidence of a trustworthy read.
    mean = sum(available) / len(available) if available else 0.0
    variance = sum((v - mean) ** 2 for v in available) / len(available) if available else 0.0
    agreement = max(0.0, 1 - variance)

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

    cert_note = "matching signing certificate" if identity.get("certificate_match") else "a different signing certificate"
    strongest = max(components, key=components.get)

    return (
        f"{clone_band.capitalize()} clone probability ({clone_probability:.0%}), driven mainly by "
        f"{strongest} similarity, despite {cert_note}. Malware risk is {risk_band} ({malware_risk:.0%}). "
        f"Confidence in this read is {confidence:.0%} based on available evidence coverage."
    )
