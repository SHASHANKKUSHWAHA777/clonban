# Security posture (MVP)

Uploaded APKs are **untrusted input**. This MVP does static analysis only.

What's implemented now:
- No APK is ever executed, installed, or run — including on the host machine
  or an emulator. Androguard parses APK/DEX structure without executing code.
- Analysis runs inside the `worker` container, separate from the `backend`
  API container that talks to the internet-facing frontend.
- Each analysis job gets a unique working/storage directory
  (`storage/apks/<job_id>/`, `storage/tmp/<job_id>/`) — no shared scratch space
  between jobs.
- Extracted APK contents in `storage/tmp/<job_id>/` are deleted after the
  pipeline finishes (`storage.cleanup_job_tmp`), win or fail.
- Uploads are validated: `.apk` extension required, size-capped via
  `MAX_UPLOAD_SIZE_MB`, empty files rejected.
- The Docker image runs analysis as a non-root user (`analyzer`, uid 1000),
  not root.
- One analyzer failing (corrupt APK, parser exception) does not crash the
  API or the rest of the pipeline — see `_safe_run` in `app/worker/tasks.py`;
  the job continues with a neutral score and a findings entry explaining the
  gap, and confidence is reduced accordingly rather than silently hidden.
- `ANALYSIS_TIMEOUT_SECONDS` bounds how long a single job may run via the RQ
  job timeout.

What's intentionally deferred past the MVP (documented, not hidden):
- Per-job container isolation (a fresh sandboxed container per analysis) —
  today all jobs share the long-lived `worker` container. For a hackathon
  demo this is an acceptable trade-off; before handling untrusted APKs from
  the public internet, move to a one-container-per-job or gVisor/firecracker
  sandbox.
- Network egress lock-down for the worker container (`internal: true` on a
  dedicated Docker network) — noted as a TODO in `docker-compose.yml`.
- Antivirus/YARA scanning of the raw APK before static analysis begins.
- Resource (CPU/memory) cgroup limits on the worker container — add
  `deploy.resources.limits` when moving to Compose v2 resource constraints
  or to the ECS task definition in the cloud migration.

Never install or execute an unknown APK on a developer's personal phone as
part of testing this project — use an emulator/AVD you're prepared to wipe,
or skip on-device testing entirely and rely on the static pipeline.
