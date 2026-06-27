from typing import Annotated

from fastapi import APIRouter, Depends

from app.core.config import Settings, get_settings
from app.core.security import require_api_key
from app.logging.audit import AuditLogger
from app.middleware.firewall import PromptSentry
from app.models.schemas import (
    RedTeamRunRequest,
    RedTeamRunResponse,
    SecurityRequest,
    SecurityResponse,
    Source,
    ToolCallReviewRequest,
    ToolCallReviewResponse,
)
from app.redteam.runner import RedTeamRunner

router = APIRouter(prefix="/v1", dependencies=[Depends(require_api_key)])

SettingsDep = Annotated[Settings, Depends(get_settings)]


def get_firewall(settings: SettingsDep) -> PromptSentry:
    return PromptSentry(settings=settings, audit_logger=AuditLogger(settings))


FirewallDep = Annotated[PromptSentry, Depends(get_firewall)]


@router.post("/inspect", response_model=SecurityResponse)
def inspect_input(request: SecurityRequest, firewall: FirewallDep) -> SecurityResponse:
    return firewall.inspect(request)


@router.post("/scan-content", response_model=SecurityResponse)
def scan_content(request: SecurityRequest, firewall: FirewallDep) -> SecurityResponse:
    return firewall.inspect(request)


@router.post("/review-tool-call", response_model=ToolCallReviewResponse)
def review_tool_call(
    request: ToolCallReviewRequest,
    firewall: FirewallDep,
) -> ToolCallReviewResponse:
    return firewall.review_tool_call(request)


@router.post("/verify-output", response_model=SecurityResponse)
def verify_output(request: SecurityRequest, firewall: FirewallDep) -> SecurityResponse:
    output_request = request.model_copy(update={"source": Source.MODEL_OUTPUT})
    return firewall.inspect(output_request)


@router.post("/red-team/run", response_model=RedTeamRunResponse)
def run_red_team(
    request: RedTeamRunRequest,
    firewall: FirewallDep,
) -> RedTeamRunResponse:
    return RedTeamRunner(firewall).run(request)
