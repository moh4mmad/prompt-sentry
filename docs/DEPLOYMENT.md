# Production deployment

PromptSentry's production profile uses PostgreSQL for shared audit events, Redis for distributed rate limiting, and a server-side dashboard proxy so backend credentials never reach browser JavaScript.

## Docker Compose

Create a private environment file and replace every value:

```bash
cp production.env.example production.env
chmod 600 production.env
docker compose --env-file production.env \
  -f docker-compose.yml -f docker-compose.prod.yml up --build -d
```

The production overlay refuses to start without API, dashboard, database, and dashboard-login credentials. The dashboard is protected with HTTP Basic authentication. Put TLS in front of ports 8100 and 3100 using your ingress or load balancer; Basic authentication must not be used over plain HTTP.

## Required production settings

- `APP_ENVIRONMENT=production` enables fail-fast configuration validation.
- `DOCS_ENABLED=false` disables public OpenAPI documentation, and `ENABLE_HSTS=true` emits HSTS behind your TLS ingress.
- `AUDIT_LOG_SINK=postgres` and `DATABASE_URL` provide audit history shared by every API replica.
- `RATE_LIMIT_BACKEND=redis` and `REDIS_URL` provide a shared limiter. It fails closed unless `RATE_LIMIT_FAIL_OPEN=true` is deliberately selected.
- `API_KEY` protects `/v1/*`; `DASHBOARD_API_KEY` separately protects `/dashboard/*`.
- `DASHBOARD_USERNAME` and `DASHBOARD_PASSWORD` protect the dashboard and its same-origin API proxy.
- `AUDIT_INCLUDE_REDACTED_INPUT=false` prevents prompt bodies from being retained; a SHA-256 input hash remains available for correlation.

## Proxies and health checks

Only configure `TRUSTED_PROXY_CIDRS` for networks controlled by your load balancer. Forwarded client IP headers from other peers are ignored.

- `/health` is a liveness check and has no dependency calls.
- `/ready` verifies PostgreSQL and Redis and returns `503` when either is unavailable.
- The dashboard exposes `/api/health` without login solely for its container health check.

For a multi-host deployment, use managed PostgreSQL and Redis, apply `migrations/001_create_audit_events.sql` as a controlled release step, and place both services on private networks. The included idempotent startup schema creation is intended to make Compose and first deployments safe.
