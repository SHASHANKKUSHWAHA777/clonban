"""
Deterministic risk engine (Phase 7, 10).

Applies the exact Phase 1 rules to produce a reproducible malware risk score.

Rules:
  New BIND_ACCESSIBILITY_SERVICE        → +30
  New SMS capability (SEND_SMS/RECEIVE_SMS)   → +30
  New SYSTEM_ALERT_WINDOW              → +25
  New RECEIVE_BOOT_COMPLETED            → +15
  New exported component (max 2)       → +10 each
  New dangerous permission (max 4)      → +5  each

  Final: risk_score = min(100, sum(contributions))

Every score is reproducible directly from the findings list.
"""
import logging
from typing import Optional

logger = logging.getLogger("clonedetector.dexrisk.risk_engine")


def calculate_risk_score(findings: list) -> dict:
    """
    Given a list of risk findings (each with a "contribution" key),
    compute the final risk score.

    Returns:
      {
        "score": int,        # min(100, sum of contributions)
        "total_contributions": int,  # raw sum before cap
      }
    """
    total = sum(f.get("contribution", 0) for f in findings)
    score = min(100, total)
    return {"score": score, "total_contributions": total}


def merge_findings(permission_findings: list, component_findings: list, suspicious_comp_findings: list) -> list:
    """
    Merge findings from sub-analyzers into the final risk_findings list.

    Permission findings already have contributions.
    Component findings have contributions.
    Suspicious component detection findings have 0 contribution (for reporting only).
    """
    merged = []
    merged.extend(permission_findings)
    merged.extend(component_findings)
    merged.extend(suspicious_comp_findings)
    return merged
