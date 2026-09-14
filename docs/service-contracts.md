# Service Contracts (Phase 15)

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
  "certificate_score": 0.10,
  "certificate_match": false,
  "package_score": 0.82,
  "manifest_score": 0.75,
  "permissions_score": 0.90,
  "findings": [
    {"type": "CERT_MISMATCH", "severity": "medium", "evidence": "..."}
  ],
  "apks": {
    "original": { "package_name": "...", "cert_sha256": "...", ... },
    "candidate": { "package_name": "...", "cert_sha256": "...", ... }
  }
}
```

## similarity.results

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
  "dex_score": 0.88,
  "malware_risk": 0.72,
  "class_count_original": 512,
  "class_count_candidate": 498,
  "method_count_original": 3040,
  "method_count_candidate": 2991,
  "ssdeep_score": 0.81,
  "api_call_similarity": 0.85,
  "findings": [
    {"type": "ACCESSIBILITY_SERVICE", "severity": "medium", "evidence": "...", "source_apk": "candidate"}
  ]
}
```

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
Nothing here claims an accuracy percentage that isn't backed by a
measurement on `tests/samples/` — see Rule #6 in the project brief.
