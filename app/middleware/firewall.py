from app.core.config import Settings
from app.logging.audit import AuditLogger
from app.middleware.inspection import InspectionService
from app.models.schemas import SecurityRequest, SecurityResponse, ToolCallReviewRequest, ToolCallReviewResponse
from app.policies.tool_calls import ToolCallPolicy


class PromptSentry:
    def __init__(self, settings: Settings, audit_logger: AuditLogger | None = None) -> None:
        self.settings = settings
        self.audit_logger = audit_logger or AuditLogger(settings)
        self.inspection_service = InspectionService(settings=settings, audit_logger=self.audit_logger)
        self.tool_call_policy = ToolCallPolicy(settings=settings, audit_logger=self.audit_logger)

    def inspect(self, request: SecurityRequest) -> SecurityResponse:
        return self.inspection_service.inspect(request)

    def review_tool_call(self, request: ToolCallReviewRequest) -> ToolCallReviewResponse:
        return self.tool_call_policy.review(request)
