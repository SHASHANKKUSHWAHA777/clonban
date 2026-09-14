# Service Contracts (V3)

Every analyzer is a plain Python function today (in-process worker calls),
but returns a dict shaped exactly like what an independent ECS/Fargate
service would return over HTTP/SQS later. This is the seam for cloud
migration — the worker's `tasks.py` is the only place that would change.

## Common envelope

```json
{
  "job_id": "uuid",
  "service": "identity | similarity | dex-risk | scoring",
  "status": "completed | failed",
  "error": null,
  "results": { ... service-specific ... }
}
```

## identity.results

```json
{
  "service": "identity",
  "certificate_status": "SAME_SIGNER | DIFFERENT_SIGNER | UNKNOWN",
  "certificate_identity_score": 1.0,
  "certificate_identity_score": null,
  "package_similarity": 0.82,
  "package_match_state": "NEAR_MATCH | EXACT_MATCH | UNRELATED",
  "manifest_findings": [
    {"type": "PACKAGE_NEAR_MATCH", "severity": "INFO", "evidence": "...", "similarity": 0.82}
  ],
  "findings": [
    {"type": "CERT_MISMATCH", "severity": "medium", "evidence": "...", "source_apk": "both"}
  ],
  "baseline": {"package_name": "...", "app_label": "...", "version_name": "...", "version_code": "..."},
  "candidate": {"package_name": "...", "app_label": "...", "version_name": "...", "version_code": "..."},
  "permissions_baseline": [],
  "permissions_candidate": [],
  "new_permissions": [],
  "removed_permissions": [],
  "exported_components_baseline": [],
  "exported_components_candidate": [],
  "errors": [{"stage": "parse", "message": "..."}]
}
```

Legend:
  - SAME_SIGNER → 1.0, DIFFERENT_SIGNER → 0.0, UNKNOWN → null
  - DIFFERENT_SIGNER is evidence of re-signing, NOT automatic proof of cloning.
  - Unavailable numeric signals use `null`, never `0`.

## similarity.results (unchanged)

```json
{
  "icon_score": 0.97,
  "icon_phash_distance": 2,
  "string_score": 0.94,
  "layout_score": 0.91,
  "resource_score": 0.89,
  "diff_image_path": "/storage/reports/<job>/icon_diff.png",
  "findings": []
}
```

## dex-risk.results

```json
{
  "service": "dex-risk",
  "bytecode_similarity": 0.88,
  "malware_risk_score": 0,
  "risk_findings": [
    {"finding": "NEW_RECEIVE_SMS", "category": "PERMISSION",
     "severity": "HIGH", "contribution": 30,
     "baseline_present": false, "candidate_present": true,
     "evidence": "android.permission.RECEIVE_SMS"}
  ],
  "dex_files_baseline": ["classes.dex", "classes2.dex"],
  "dex_files_candidate": ["classes.dex"],
  "dex_count_baseline": 2,
  "dex_count_candidate": 1,
  "errors": [{"stage": "TLSH", "message": "..."}]
}
```

Deterministic risk rules (Phase 1):
  New BIND_ACCESSIBILITY_SERVICE → +30
  New SEND_SMS or RECEIVE_SMS    → +30
  New SYSTEM_ALERT_WINDOW        → +25
  New RECEIVE_BOOT_COMPLETED     → +15
  New exported component         → +10 (max 2 counted)
  New dangerous permission       → +5  (max 4 counted)
  Final: risk_score = min(100, sum(contributions))

## scoring.results

```json
{
  "clone_probability": 0.92,
  "malware_risk": 0.72,
  "confidence": 0.81,
  "weights_used": { "certificate": 0.15, "package": 0.10, ... },
  "component_scores": { "certificate": 0.10, "package": 0.82, ... },
  "verdict_summary": "High clone probability driven by icon/string/DEX similarity despite differing signing certificate."
}
```

All scores are floats in `[0, 1]`. `severity` is one of `low|medium|high`.
`malware_risk_score` is an integer in `[0, 100]`.
Nothing here claims an accuracy percentage that isn't backed by a
measurement on `tests/samples/` — see Rule #6 in the project brief.
