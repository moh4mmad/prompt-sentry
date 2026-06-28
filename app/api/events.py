"""Read-only endpoints for the monitoring dashboard."""

from __future__ import annotations

from collections import Counter
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.middleware.cors import CORSMiddleware  # noqa: F401 — imported by main
from fastapi.responses import JSONResponse

from app.core.security import require_dashboard_api_key
from app.logging.audit import AuditLogger

router = APIRouter(
    prefix="/dashboard",
    tags=["dashboard"],
    dependencies=[Depends(require_dashboard_api_key)],
)


@router.get("/events")
def get_events(request: Request, limit: int = Query(default=200, ge=1, le=2000)) -> JSONResponse:
    settings = request.app.state.settings
    events = AuditLogger(settings).read_events(limit)
    return JSONResponse(content={"events": events, "total": len(events)})


@router.get("/stats")
def get_stats(request: Request, limit: int = Query(default=1000, ge=1, le=10000)) -> JSONResponse:
    settings = request.app.state.settings
    events: list[dict[str, Any]] = AuditLogger(settings).read_events(limit)

    action_counts: Counter[str] = Counter()
    attack_counts: Counter[str] = Counter()
    severity_counts: Counter[str] = Counter()
    risk_buckets: Counter[str] = Counter()
    total = len(events)
    blocked = 0
    alerted = 0
    risk_sum = 0.0
    risk_n = 0

    for e in events:
        action = str(e.get("action", "unknown"))
        action_counts[action] += 1
        if action == "block":
            blocked += 1
        elif action == "alert":
            alerted += 1

        for at in e.get("attack_types", []):
            attack_counts[str(at)] += 1

        sev = e.get("severity")
        if sev:
            severity_counts[str(sev)] += 1

        rs = e.get("risk_score")
        if rs is not None:
            try:
                r = float(rs)
                risk_sum += r
                risk_n += 1
                bucket = f"{int(r * 10) / 10:.1f}"
                risk_buckets[bucket] += 1
            except (ValueError, TypeError):
                pass

    return JSONResponse(
        content={
            "total": total,
            "blocked": blocked,
            "alerted": alerted,
            "detection_rate": round((blocked + alerted) / total, 4) if total else 0.0,
            "avg_risk_score": round(risk_sum / risk_n, 4) if risk_n else 0.0,
            "action_counts": dict(action_counts),
            "attack_counts": dict(attack_counts),
            "severity_counts": dict(severity_counts),
            "risk_buckets": dict(sorted(risk_buckets.items())),
        }
    )
