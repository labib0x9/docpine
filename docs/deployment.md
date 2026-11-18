# Deployment

## Local development

```bash
cp .env.example .env
docker compose up -d --build
```

The compose stack starts PostgreSQL, applies migrations, starts RabbitMQ with user `docpine`, then builds and starts the API, worker, and frontend. The frontend image is built from the local `../docpine-console` directory with its standalone Next.js Dockerfile. Only `docpine-worker` mounts the host Docker socket. The API health check polls `GET /healthz`.

Seed labs before accepting runs:

```sql
INSERT INTO labs (name, tests)
VALUES
  ('smoke', ARRAY['echo hello', 'test -f README.md']),
  ('go', ARRAY['go version']);
```

## GitHub OAuth

Create a GitHub OAuth application whose callback URL exactly matches `GITHUB_CALLBACK_URL`, for example `https://labs.example.com/v1/auth/callback` in production or `http://localhost:8080/v1/auth/callback` locally.

Set:

```dotenv
GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...
GITHUB_CALLBACK_URL=https://labs.example.com/v1/auth/callback
GITHUB_FORCE_SECURE=true
ALLOWED_ORIGINS=https://labs.example.com
```

`GITHUB_FORCE_SECURE=true` is required when the API is served over HTTPS; otherwise browsers reject the `session` and `oauth_state` cookies.

## Environment reference

| Variable | Required | Used by | Notes |
| --- | --- | --- | --- |
| `COOKIE_SECRET` | yes | API, worker | Session token signing secret; use a long random value |
| `GITHUB_CLIENT_ID` | for login | API | OAuth application client id |
| `GITHUB_CLIENT_SECRET` | for login | API | OAuth application secret |
| `GITHUB_CALLBACK_URL` | for login | API | Must match the GitHub application setting |
| `GITHUB_FORCE_SECURE` | production | API | Set `true` behind HTTPS |
| `ALLOWED_ORIGINS` | browser clients | API | Comma-separated origins; credentials are allowed |
| `DATABASE_URL` | yes | API, worker | PostgreSQL DSN |
| `RABBITMQ_URL` | yes | API, worker | AMQP URL; compose uses `docpine:docpine` |
| `RABBITMQ_QUEUE` | no | API, worker | Job queue, default `docpine.lab.runs` |
| `RABBITMQ_EVENTS_EXCHANGE` | no | API, worker | Fanout exchange, default `docpine.lab.events` |
| `LAB_RUNNER_IMAGE` | no | worker | Default `alpine:3.20`; must provide required toolchains |
| `LAB_RUN_TIMEOUT` | no | worker | Default `10m` |
| `LAB_MEMORY` | no | worker | Bytes, default `268435456` |
| `LAB_CPU_SHARES` | no | worker | Default `0` |
| `TURNSTILE_SECRET` | no | API | Empty disables verification |
| `TURNSTILE_SITE_KEY` | frontend only | frontend build | Inlined into the frontend build |
| `NEXT_PUBLIC_API_BASE` | no | frontend build | API origin, default `http://localhost:8080` |
| `NEXT_PUBLIC_SSE_BASE` | no | frontend build | SSE origin, default `NEXT_PUBLIC_API_BASE` |
| `LOG_DIR`, `LOG_LEVEL` | no | API, worker | File logging and level |

Legacy sandbox variables (`RUNTIME_NAME`, `IMAGE`, `NETWORK_MODE`, `SANDBOX_MEMORY`, `SESSION_TTL`, `MAX_SESSIONS`, `RATE_LIMIT_*`, Firecracker/gVisor paths) are ignored.

## PostgreSQL and migrations

Compose applies migrations with `migrate/migrate:v4.17.1` before the API and worker start. To run them manually:

```bash
migrate -path ./migrations -database "$DATABASE_URL" up
```

Roll back with:

```bash
migrate -path ./migrations -database "$DATABASE_URL" down 1
```

Back up the database before schema changes. `lab_result.results` stores full command output, so plan retention accordingly.

## RabbitMQ

Compose creates the `docpine` user through `RABBITMQ_DEFAULT_USER` and `RABBITMQ_DEFAULT_PASS`. Override `RABBITMQ_USER` and `RABBITMQ_PASSWORD` in `.env` for production. The job queue is durable and messages are persistent.

The worker publishes run events to the durable fanout exchange `RABBITMQ_EVENTS_EXCHANGE`. Every API instance binds its own exclusive queue to that exchange and mirrors events into its local SSE hub. API and worker must use the same exchange name.

The management UI is published on port `15672`. Restrict or remove that port outside development.

## Docker runner

Only the worker service connects to Docker through `/var/run/docker.sock`. This grants root-equivalent control of the host, so run the worker only on trusted hosts or isolate it with a dedicated daemon. The API container has no Docker socket mount and no Docker client.

The worker copies cloned files into each container through the Docker API; no shared host path is needed. Images are pulled automatically when missing. If labs need compilers or interpreters, set `LAB_RUNNER_IMAGE` to a custom image that contains them.

## Turnstile

Set `TURNSTILE_SECRET` on the API and `TURNSTILE_SITE_KEY` for the frontend build. When the secret is empty, verification is skipped for local development.

Clients send the token in the `CF-Turnstile-Response` header, the `cf-turnstile-response` query parameter, or a form field. Missing tokens return `428`; failed verification returns `400`.

## Reverse proxy and TLS

Terminate TLS at your proxy and forward `/v1` and `/healthz` to the API. SSE uses long-lived HTTP responses on `/v1/labs/{id}/runs/{runID}/events`, so disable aggressive response buffering for that path. Set `GITHUB_FORCE_SECURE=true` and proxy `CF-Connecting-IP` if you rely on Cloudflare for client IP information.

Optional Cloudflare Tunnel setup:

```bash
cloudflared tunnel login
cloudflared tunnel create docpine
cloudflared tunnel route dns docpine labs.example.com
cloudflared tunnel run docpine
```

Point the tunnel at `http://localhost:3000` for the frontend and route `/v1` and `/healthz` to `http://localhost:8080`.

## Health checks

- API: `GET /healthz` returns `{"status":"ok"}`.
- PostgreSQL: compose uses `pg_isready`.
- RabbitMQ: compose uses `rabbitmq-diagnostics ping`.
- Worker: no HTTP endpoint; watch container logs and RabbitMQ queue depth.

The frontend waits for the backend health check before starting.

## Scaling

The API and worker scale independently. Add worker replicas to consume jobs in parallel; each worker still mounts a Docker socket and uses prefetch 1. Add API replicas behind a load balancer; each replica receives all events from the RabbitMQ fanout exchange and serves SSE from its local hub.

For complete SSE replay after API restarts, add a durable event log and hydrate hub history from it. Partition the job queue by run id only if strict per-run ordering matters more than throughput.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Login redirects but no session | `GITHUB_CALLBACK_URL`, `GITHUB_FORCE_SECURE`, and cookie domain |
| `428 turnstile token is required` | Token header/query/form and `TURNSTILE_SECRET` |
| Runs stay `queued` | RabbitMQ credentials, job queue name, and worker logs/container status |
| Worker cannot create containers | Docker socket mount on worker, Docker daemon availability, `git` in worker image |
| Clone failures | GitHub repo normalization and outbound HTTPS from the worker |
| Test failures with missing tools | `LAB_RUNNER_IMAGE` contents |
| SSE connects but no output | Event exchange name shared by API and worker; hub history belongs to the API replica serving the request |
| CORS failures | `ALLOWED_ORIGINS` must contain the exact browser origin |
