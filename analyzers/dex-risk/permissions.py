"""
Permission difference engine (Phase 9).

Categorizes Android permissions and scores only NEW capabilities introduced
by the candidate relative to the baseline.

Deterministic Phase 1 rules:
  New BIND_ACCESSIBILITY_SERVICE        → +30
  New SMS capability (SEND_SMS/RECEIVE_SMS)   → +30
  New SYSTEM_ALERT_WINDOW              → +25
  New RECEIVE_BOOT_COMPLETED            → +15
  New exported component               → +10 (max 2 counted)
  New other dangerous permission       → +5  (max 4 counted)

  Final: risk_score = min(100, sum(contributions))
"""
import logging
from typing import Optional

logger = logging.getLogger("clonedetector.dexrisk.permissions")

# Permission category definitions.
# Normalization: strip "android.permission." prefix if present.
PERMISSION_PREFIX = "android.permission."

SMS_PERMISSIONS = {"SEND_SMS", "RECEIVE_SMS", "READ_SMS"}
ACCESSIBILITY_PERMISSIONS = {"BIND_ACCESSIBILITY_SERVICE"}
OVERLAY_PERMISSIONS = {"SYSTEM_ALERT_WINDOW"}
BOOT_PERMISSIONS = {"RECEIVE_BOOT_COMPLETED"}
DANGEROUS_OTHER = {
    "READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS",
    "READ_CALENDAR", "WRITE_CALENDAR",
    "READ_SMS", "WRITE_SMS",
    "CAMERA",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
    "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
    "RECORD_AUDIO",
    "READ_PHONE_STATE",
    "CALL_PHONE",
    "ADD_VOICEMAIL", "READ_VOICEMAIL", "WRITE_VOICEMAIL",
}

# Risk contributions (Phase 1 rules)
CONTRIB_ACCESSIBILITY = 30
CONTRIB_SMS = 30
CONTRIB_OVERLAY = 25
CONTRIB_BOOT = 15
CONTRIB_EXPORTED_COMPONENT = 10
CONTRIB_DANGEROUS_OTHER = 5

MAX_EXPORTED_COMPONENTS_COUNTED = 2
MAX_DANGEROUS_OTHER_COUNTED = 4


def normalize_permission(name: str) -> str:
    """Normalize an Android permission name by stripping the package prefix."""
    if not name:
        return name
    if name.startswith(PERMISSION_PREFIX):
        return name[len(PERMISSION_PREFIX):]
    return name


def categorize_permission(perm: str) -> str:
    """
    Categorize a normalized permission into a risk bucket.

    Returns one of:
      "SMS", "accessibility", "overlay", "boot", "dangerous", "other"
    """
    p = normalize_permission(perm)
    if p in SMS_PERMISSIONS:
        return "SMS"
    if p in ACCESSIBILITY_PERMISSIONS:
        return "accessibility"
    if p in OVERLAY_PERMISSIONS:
        return "overlay"
    if p in BOOT_PERMISSIONS:
        return "boot"
    if p in DANGEROUS_OTHER:
        return "dangerous"
    return "other"


def diff_permissions(baseline: list, candidate: list) -> tuple[list, list, list, list]:
    """
    Compute permission differences.

    Returns:
      (permissions_baseline, permissions_candidate, new_permissions, removed_permissions)
    All lists are sorted and deduplicated.
    """
    b = sorted(set(normalize_permission(p) for p in (baseline or [])))
    c = sorted(set(normalize_permission(p) for p in (candidate or [])))
    new = sorted(set(c) - set(b))
    removed = sorted(set(b) - set(c))
    return b, c, new, removed


def calculate_permission_risk(baseline_permissions: list, candidate_permissions: list) -> dict:
    """
    Compute the permission-based risk score.

    Only NEW permissions introduced by the candidate are scored.
    Returns:
      {
        "score": int,  # min(100, sum of contributions)
        "findings": [{"finding": str, "category": str, "severity": str,
                      "contribution": int, "baseline_present": bool,
                      "candidate_present": bool, "evidence": str}]
      }
    """
    b_norm = set(normalize_permission(p) for p in (baseline_permissions or []))
    c_norm = set(normalize_permission(p) for p in (candidate_permissions or []))
    new_perms = sorted(c_norm - b_norm)

    findings = []
    score = 0

    # 1. Accessibility service
    acc_new = [p for p in new_perms if p in ACCESSIBILITY_PERMISSIONS]
    if acc_new:
        for p in acc_new:
            findings.append({
                "finding": "NEW_BIND_ACCESSIBILITY_SERVICE",
                "category": "PERMISSION",
                "severity": "HIGH",
                "contribution": CONTRIB_ACCESSIBILITY,
                "baseline_present": False,
                "candidate_present": True,
                "evidence": f"android.permission.{p}",
            })
        score += CONTRIB_ACCESSIBILITY

    # 2. SMS capability
    sms_new = [p for p in new_perms if p in SMS_PERMISSIONS]
    if sms_new:
        for p in sms_new:
            findings.append({
                "finding": f"NEW_SMS_PERMISSION",
                "category": "PERMISSION",
                "severity": "HIGH",
                "contribution": CONTRIB_SMS,
                "baseline_present": False,
                "candidate_present": True,
                "evidence": f"android.permission.{p}",
            })
        score += CONTRIB_SMS

    # 3. Overlay permission
    overlay_new = [p for p in new_perms if p in OVERLAY_PERMISSIONS]
    if overlay_new:
        for p in overlay_new:
            findings.append({
                "finding": "NEW_SYSTEM_ALERT_WINDOW",
                "category": "PERMISSION",
                "severity": "HIGH",
                "contribution": CONTRIB_OVERLAY,
                "baseline_present": False,
                "candidate_present": True,
                "evidence": f"android.permission.{p}",
            })
        score += CONTRIB_OVERLAY

    # 4. Boot persistence
    boot_new = [p for p in new_perms if p in BOOT_PERMISSIONS]
    if boot_new:
        for p in boot_new:
            findings.append({
                "finding": "NEW_RECEIVE_BOOT_COMPLETED",
                "category": "PERMISSION",
                "severity": "MEDIUM",
                "contribution": CONTRIB_BOOT,
                "baseline_present": False,
                "candidate_present": True,
                "evidence": f"android.permission.{p}",
            })
        score += CONTRIB_BOOT

    # 5. Dangerous permissions not covered above (+5 each, max 4)
    scored_categories = SMS_PERMISSIONS | ACCESSIBILITY_PERMISSIONS | OVERLAY_PERMISSIONS | BOOT_PERMISSIONS
    dangerous_new = [p for p in new_perms
                     if categorize_permission(p) == "dangerous" and p not in scored_categories]
    counted = 0
    for p in dangerous_new:
        if counted >= MAX_DANGEROUS_OTHER_COUNTED:
            break
        findings.append({
            "finding": "NEW_DANGEROUS_PERMISSION",
            "category": "PERMISSION",
            "severity": "MEDIUM",
                "contribution": CONTRIB_DANGEROUS_OTHER,
            "baseline_present": False,
            "candidate_present": True,
            "evidence": f"android.permission.{p}",
        })
        score += CONTRIB_DANGEROUS_OTHER
        counted += 1

    # 6. Other (non-dangerous) new permissions — reported but 0 contribution
    other_new = [p for p in new_perms if categorize_permission(p) == "other"]
    for p in other_new:
        findings.append({
            "finding": "NEW_OTHER_PERMISSION",
            "category": "PERMISSION",
            "severity": "INFO",
            "contribution": 0,
            "baseline_present": False,
            "candidate_present": True,
            "evidence": f"android.permission.{p}",
        })

    score = min(100, score)

    return {"score": score, "findings": findings}


def normalize_permission_list(perms: list) -> list:
    """Normalize and deduplicate a list of permission names."""
    return sorted(set(normalize_permission(p) for p in (perms or [])))
