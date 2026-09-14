# Cloud migration plan (Phase 16 — NOT implemented yet)

This is a plan, not code. Do not implement any of this until the local MVP
is stable and demoed — see project rule #4.

| Local (today) | AWS (later) | Migration note |
|---|---|---|
| `./storage` filesystem | S3 | `app/services/storage.py` is already the only place that touches file paths — add an `S3Storage` class implementing the same `save_apk/job_report_dir/...` interface as `LocalStorage`, gated by `STORAGE_BACKEND=s3` |
| Redis + RQ | SQS | `app/api/routes.py` enqueues via `Queue("analysis", connection=redis...)`; swap for `boto3` SQS `send_message` behind the same call site |
| PostgreSQL (Docker) | RDS PostgreSQL | Same `DATABASE_URL` env var — just point it at an RDS endpoint; SQLAlchemy code doesn't change |
| Docker Compose | ECS/Fargate | Each service (`backend`, `worker`, `frontend`) already has its own Dockerfile — becomes its own ECS task definition |
| Local images | ECR | `docker build` + `docker push` to an ECR repo per service, unchanged Dockerfiles |
| Container logs | CloudWatch | Fargate's awslogs driver picks up stdout/stderr automatically — no app code change since we already log to stdout |
| `.env` file | AWS Secrets Manager / SSM Parameter Store + ECS task env | `app/core/config.py` reads from env vars either way |

## What NOT to change during migration

- The analyzer function signatures (`analyze(original_path, candidate_path) -> dict`)
  and the JSON contracts in `docs/service-contracts.md` — these are the seam
  that makes analyzers swappable between in-process worker calls and
  independent Fargate services later, per project rule #15.
- The scoring engine's weight-normalization behavior.

## Suggested migration order

1. RDS (swap `DATABASE_URL`, verify migrations still apply)
2. S3 (implement `S3Storage`, dual-write during cutover, verify report
   downloads work via presigned URLs)
3. SQS (swap the queue backend; RQ's polling model differs from SQS's
   pull-based consumer — the worker's `run.py` needs a rewrite here, not
   just a config change)
4. ECR + ECS/Fargate task definitions per service
5. CloudWatch (should mostly be automatic once on Fargate)
6. VPC/IAM hardening — least-privilege roles per task, private subnets for
   `worker`/`postgres`, only `frontend`/`backend` behind a public ALB
