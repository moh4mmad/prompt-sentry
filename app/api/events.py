"""Read-only endpoints for the monitoring dashboard."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Query
from fastapi.middleware.cors import CORSMiddleware  # noqa: F401 — imported by main
from fastapi.responses import JSONResponse

from app.core.config import get_settings

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


def _read_events(path: Path, limit: int) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records[-limit:]


@router.get("/events")
def get_events(limit: int = Query(default=200, ge=1, le=2000)) -> JSONResponse:
    settings = get_settings()
    events = _read_events(Path(settings.audit_log_path), limit)
    return JSONResponse(content={"events": events, "total": len(events)})


@router.get("/stats")
def get_stats(limit: int = Query(default=1000, ge=1, le=10000)) -> JSONResponse:
    settings = get_settings()
    events = _read_events(Path(settings.audit_log_path), limit)

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
