# APK Clone / Impersonation Detector — Local MVP

Static-analysis system that compares an **original** and a **candidate**
Android APK and reports:

- Clone Probability
- Malware Risk
- Confidence
- Per-signal evidence (certificate, package, icon, strings, layout, DEX, resources)
- Structured risk findings with severity
- Downloadable JSON / HTML / PDF reports

Runs entirely on your laptop with Docker Compose. No AWS required for this
version — see `docs/cloud-migration.md` for the later migration plan.

## What's built so far (Phases 1–9 of the brief)

| Phase | Status |
|---|---|
| 1. Repo structure + Docker Compose | ✅ |
| 2. FastAPI upload/API | ✅ |
| 3. Identity Analyzer | ✅ |
| 4. Visual/Resource Similarity Analyzer | ✅ (layout diffing is best-effort, see limitation below) |
| 5. DEX/Risk Analyzer | ✅ |
| 6. Scoring Engine | ✅ |
| 7. PostgreSQL storage | ✅ |
| 8. Frontend dashboard | ✅ |
| 9. Report generation (JSON/HTML/PDF) | ✅ |
| 10. End-to-end testing | ⚠️ unit tests included; integration test needs your own sample APKs (binaries aren't committed) |

## Prerequisites

- Docker + Docker Compose v2 (`docker compose version`)
- ~4GB free disk for images/containers
- No Android SDK, emulator, or physical device needed — this is static analysis only

## Run it

```bash
cd android-clone-detector
cp .env.example .env
docker compose up --build
```

Then open **http://localhost:3000**, upload an original APK and a candidate
APK, click **Analyze APKs**, and watch the pipeline stages complete.

- Frontend: http://localhost:3000
- Backend API + docs: http://localhost:8000/docs
- Postgres: localhost:5432 (user/db from `.env`)
- MinIO console (optional, unused by default): http://localhost:9001

First build takes a few minutes — androguard/weasyprint pull in native
dependencies. Subsequent `docker compose up` runs are fast.

### Troubleshooting: `npm error ... package.json` / `ModuleNotFoundError: No module named 'app'`

These both mean the same thing: the container started before Docker's bind
mount of `./frontend` or `./backend` into `/app` was actually populated (a
known Docker Desktop timing quirk right after a fresh unzip + first
`--build`, especially on Windows/Mac). The images build correctly — it's
only the *runtime* mount that raced. The `docker-entrypoint.sh` scripts in
`backend/` and `frontend/` now wait for the source files to appear (up to
30s) before starting, so a first `--build` run may pause briefly instead of
crash-looping. If it still fails after that wait:

1. Confirm Docker Desktop → Settings → Resources → File Sharing includes the
   drive/folder this project lives in (Windows especially).
2. `docker compose down -v --remove-orphans`, then `docker compose up --build --force-recreate`.
3. On Windows, prefer keeping the project inside the WSL2 filesystem
   (`\\wsl$\...`) or under `C:\Users\...` rather than a synced folder
   (OneDrive/Dropbox), which can delay file visibility to Docker.

## API

- `POST /api/analyze` — multipart upload, fields `original` and `candidate` (both `.apk`) → `{job_id, status}`
- `GET /api/analyze/{job_id}/status` — lightweight polling endpoint for progress
- `GET /api/analyze/{job_id}` — full structured result once available
- `GET /api/reports/{job_id}` — report file metadata
- `GET /api/reports/{job_id}/download?fmt=pdf|html|json` — download a report
- `GET /api/health` — DB + Redis connectivity check

Full contract shapes: `docs/service-contracts.md`.

## Running tests

```bash
# from repo root, using the backend's virtualenv/deps (or inside the backend container)
pip install -r backend/requirements.txt pytest --break-system-packages
pytest tests/unit -v

# integration test needs real sample APKs you provide yourself — see tests/samples/README.md
pytest tests/integration -v
```

## Project structure

```
android-clone-detector/
├── frontend/          Next.js + Tailwind dashboard
├── backend/            FastAPI app, DB models, worker, report generation
├── analyzers/
│   ├── identity/        package/manifest/certificate comparison
│   ├── similarity/       icon phash, string TF-IDF, layout, resources
│   └── dex-risk/          DEX structural similarity + suspicious API findings
├── scoring/             combines analyzer outputs into 3 headline scores
├── storage/             local filesystem: apks/, reports/, tmp/ (gitignored)
├── tests/
│   ├── unit/             pure-function tests, no APKs needed
│   ├── integration/      full pipeline test (needs your own sample APKs)
│   └── samples/           where you drop test APKs (not committed)
├── docs/                security posture, service contracts, migration plan
└── docker-compose.yml
```

## Known limitations (honest, not hidden)

- **Layout similarity** is a coarse view-tag-frequency signature, not a true
  tree-edit-distance diff — heavily restructured layouts can under-score.
  This is reflected in Confidence, not silently ignored.
- **ssdeep** fuzzy hashing requires `libfuzzy-dev` at the OS level; if that
  install fails on your platform, `dex_score` falls back to the API-call
  Jaccard similarity alone (still obfuscation-resistant, just one signal
  instead of two — see `analyzers/dex-risk/analyzer.py`).
- **PDF generation** depends on WeasyPrint's system libraries (Pango/Cairo).
  If it fails in your environment, JSON and HTML reports are still produced;
  the failure is logged, not swallowed.
- No numbers here are validated accuracy claims — `confidence` measures
  *evidence coverage and agreement*, not a benchmarked true-positive rate.
  Don't quote it as a false-positive/negative rate to judges without running
  your own sample set through `tests/integration`.
- The worker container is long-lived and shared across jobs (see
  `docs/security.md` for the sandboxing trade-off accepted for the MVP).

## Next steps (not built yet)

- Phase 10: run the full sample matrix (`tests/samples/`) and tune the
  default weights in `.env` based on real results, not guesses.
- Cloud migration (`docs/cloud-migration.md`): S3, SQS, RDS, ECS/Fargate,
  ECR, CloudWatch — deliberately deferred until the local MVP is stable.
