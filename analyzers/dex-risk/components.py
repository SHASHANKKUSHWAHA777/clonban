"""
Component analysis (Phase 8).

Extracts activities, services, receivers, providers from an APK with their
exported state and intent filters. Compares baseline vs candidate to detect:
  - newly introduced exported components
  - newly exported existing components
  - accessibility-related services
  - boot-related receivers

Each component is represented as:
  {"name": str, "type": str, "exported": bool | None, "permission": str | None,
   "intent_filters": list[dict]}
"""
import logging
from typing import Optional

from androguard.core.apk import APK

logger = logging.getLogger("clonedetector.dexrisk.components")


def extract_components(apk: APK) -> list[dict]:
    """
    Extract all components from a parsed APK with exported state.

    Returns a list of component dicts.
    """
    components = []
    if apk is None:
        return components

    comp_types = [
        ("activity", apk.get_activities),
        ("service", apk.get_services),
        ("receiver", apk.get_receivers),
        ("provider", apk.get_providers),
    ]

    for comp_type, getter in comp_types:
        try:
            names = getter() or []
            for name in names:
                exported = _get_component_exported(apk, comp_type, name)
                components.append({
                    "name": name,
                    "type": comp_type,
                    "exported": exported,
                    "permission": None,  # androguard doesn't expose per-component permission easily
                    "intent_filters": [],  # would require deeper manifest parsing
                })
        except Exception:
            logger.warning("Could not extract %s list", comp_type, exc_info=True)

    return components


def _get_component_exported(apk: APK, comp_type: str, name: str) -> Optional[bool]:
    """Try to determine exported state from the manifest."""
    try:
        manifest = apk.get_manifest()
        if manifest and isinstance(manifest, dict):
            apps = manifest.get("application", {})
            if isinstance(apps, dict):
                comps = apps.get(comp_type + "s", {})
                if isinstance(comps, list):
                    for comp in comps:
                        if isinstance(comp, dict):
                            comp_name = comp.get("name", "")
                            if comp_name == name:
                                exp = comp.get("exported")
                                if exp is not None:
                                    return str(exp).lower() in ("true", "1")
                            # Check for inner class suffix matching
                            if comp_name.endswith(name.split(".")[-1]):
                                exp = comp.get("exported")
                                if exp is not None:
                                    return str(exp).lower() in ("true", "1")
            elif isinstance(apps, list):
                for app in apps:
                    if isinstance(app, dict):
                        comps = app.get(comp_type + "s", {})
                        if isinstance(comps, list):
                            for comp in comps:
                                if isinstance(comp, dict) and comp.get("name") == name:
                                    exp = comp.get("exported")
                                    if exp is not None:
                                        return str(exp).lower() in ("true", "1")
    except Exception:
        pass
    return None


def compare_exported_components(baseline: list, candidate: list) -> list[dict]:
    """
    Detect newly exported components in the candidate relative to the baseline.

    Returns a list of finding dicts:
      {"finding": "NEW_EXPORTED_COMPONENT", "category": "COMPONENT",
       "severity": "MEDIUM", "contribution": 10, "component": name,
       "evidence": "exported=true", "baseline_present": bool,
       "candidate_present": true}

    Rules (Phase 8):
      - A component that is newly exported in candidate (was not exported or
        didn't exist in baseline) gets +10.
      - Maximum 2 newly-exported components are counted toward the score.
      - Report-only for components beyond the cap.
    """
    findings = []

    # Build baseline lookup by component name -> exported state
    baseline_map = {}
    for comp in baseline or []:
        baseline_map[comp.get("name")] = comp.get("exported")

    new_exported = []
    for comp in candidate or []:
        if not comp.get("exported"):
            continue
        name = comp.get("name")
        baseline_exported = baseline_map.get(name)

        # This component is exported in candidate.
        if baseline_exported is None:
            # Component didn't exist in baseline (or exported state unknown)
            new_exported.append((name, False))
        elif not baseline_exported:
            # Component existed in baseline but was NOT exported → now exported
            new_exported.append((name, True))

    # Apply cap: max 2 counted
    max_counted = 2
    for i, (name, was_not_exported) in enumerate(new_exported):
        if i >= max_counted:
            findings.append({
                "finding": "NEW_EXPORTED_COMPONENT_REPORT_ONLY",
                "category": "COMPONENT",
                "severity": "MEDIUM",
                "contribution": 0,
                "component": name,
                "evidence": "exported=true (beyond cap of 2 counted)",
                "baseline_present": False,
                "candidate_present": True,
            })
        else:
            findings.append({
                "finding": "NEW_EXPORTED_COMPONENT",
                "category": "COMPONENT",
                "severity": "MEDIUM",
                "contribution": 10,
                "component": name,
                "evidence": "exported=true" if was_not_exported else "exported=true (was not exported in baseline)",
                "baseline_present": False if was_not_exported else True,
                "candidate_present": True,
            })

    return findings


def detect_suspicious_components(components: list, permissions: list) -> list[dict]:
    """
    Detect accessibility-related services and boot-related receivers.
    These are reported as findings for downstream risk analysis.

    Returns finding dicts with no contribution (scored in risk_engine).
    """
    findings = []
    for comp in components:
        name = comp.get("name", "").lower()
        comp_type = comp.get("type", "")
        if "accessibility" in name or "accessibility" in str(comp.get("permission", "")).lower():
            findings.append({
                "finding": "ACCESSIBILITY_SERVICE_COMPONENT",
                "category": "COMPONENT",
                "severity": "HIGH",
                "contribution": 0,  # scored via permission rule, not duplicated
                "component": comp.get("name"),
                "evidence": f"Service name contains 'accessibility'",
                "baseline_present": True,
                "candidate_present": True,
            })
        if "boot" in name and comp_type == "receiver":
            findings.append({
                "finding": "BOOT_RECEIVER_COMPONENT",
                "category": "COMPONENT",
                "severity": "MEDIUM",
                "contribution": 0,  # scored via permission rule, not duplicated
                "component": comp.get("name"),
                "evidence": "Receiver related to boot completion",
                "baseline_present": True,
                "candidate_present": True,
            })
    return findings
