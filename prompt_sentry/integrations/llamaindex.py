from __future__ import annotations

from copy import deepcopy
from typing import Any

from prompt_sentry.client import AsyncPromptSentryClient, PromptSentryClient
from prompt_sentry.exceptions import PromptSentryBlocked
from prompt_sentry.models import SecurityContext

try:
    from llama_index.core.postprocessor.types import BaseNodePostprocessor
    from llama_index.core.schema import QueryBundle, TransformComponent
except ImportError:  # pragma: no cover
    BaseNodePostprocessor = object  # type: ignore[assignment,misc]
    QueryBundle = None  # type: ignore[assignment,misc]
    TransformComponent = object  # type: ignore[assignment,misc]


class PromptSentryIngestionTransform(TransformComponent):  # type: ignore[misc]
    sentry: Any
    context: Any = None

    def __init__(self, sentry: PromptSentryClient, context: SecurityContext | None = None, **kwargs: Any) -> None:
        if QueryBundle is None:
            raise ImportError("Install prompt-sentry[llamaindex] to use PromptSentryIngestionTransform")
        super().__init__(
            sentry=sentry,
            context=(context or SecurityContext()).with_updates(framework="llamaindex"),
            **kwargs,
        )

    def __call__(self, nodes: list[Any], **_: Any) -> list[Any]:
        return _protect_nodes(nodes, self.sentry, self.context)


class PromptSentryNodePostprocessor(BaseNodePostprocessor):  # type: ignore[misc]
    sentry: Any
    context: Any = None

    def __init__(self, sentry: PromptSentryClient, context: SecurityContext | None = None, **kwargs: Any) -> None:
        if QueryBundle is None:
            raise ImportError("Install prompt-sentry[llamaindex] to use PromptSentryNodePostprocessor")
        super().__init__(
            sentry=sentry,
            context=(context or SecurityContext()).with_updates(framework="llamaindex"),
            **kwargs,
        )

    def _postprocess_nodes(self, nodes: list[Any], query_bundle: Any | None = None) -> list[Any]:
        context = self.context
        if query_bundle is not None:
            query = getattr(query_bundle, "query_str", str(query_bundle))
            self.sentry.protect_text(query, source="user_prompt", context=context)
        return _protect_nodes(nodes, self.sentry, context)


class PromptSentryQueryEngine:
    def __init__(self, query_engine: Any, sentry: PromptSentryClient, context: SecurityContext | None = None) -> None:
        self.query_engine = query_engine
        self.sentry = sentry
        self.context = (context or SecurityContext()).with_updates(framework="llamaindex")

    def query(self, query: str) -> Any:
        safe_query = self.sentry.protect_text(str(query), source="user_prompt", context=self.context)
        response = self.query_engine.query(safe_query)
        text = getattr(response, "response", str(response))
        safe = self.sentry.verify_output(str(text), context=self.context)
        if hasattr(response, "response"):
            response.response = safe
            return response
        return safe



class AsyncPromptSentryQueryEngine:
    def __init__(
        self,
        query_engine: Any,
        sentry: AsyncPromptSentryClient,
        context: SecurityContext | None = None,
    ) -> None:
        self.query_engine = query_engine
        self.sentry = sentry
        self.context = (context or SecurityContext()).with_updates(framework="llamaindex")

    async def aquery(self, query: str) -> Any:
        safe_query = await self.sentry.protect_text(str(query), source="user_prompt", context=self.context)
        response = await self.query_engine.aquery(safe_query)
        text = getattr(response, "response", str(response))
        safe = await self.sentry.verify_output(str(text), context=self.context)
        if hasattr(response, "response"):
            response.response = safe
            return response
        return safe


def _protect_nodes(nodes: list[Any], sentry: PromptSentryClient, context: SecurityContext) -> list[Any]:
    safe_nodes = []
    for item in nodes:
        node = getattr(item, "node", item)
        text = node.get_content() if hasattr(node, "get_content") else str(node)
        metadata = getattr(node, "metadata", {}) or {}
        node_context = context.with_updates(
            metadata={
                **context.metadata,
                "document_id": getattr(node, "node_id", None),
                "document_url": metadata.get("url"),
            }
        )
        try:
            safe = sentry.protect_text(text, source="retrieved_document", context=node_context)
        except PromptSentryBlocked:
            continue
        clone = deepcopy(item)
        clone_node = getattr(clone, "node", clone)
        if safe != text:
            if hasattr(clone_node, "set_content"):
                clone_node.set_content(safe)
            elif hasattr(clone_node, "text"):
                clone_node.text = safe
        safe_nodes.append(clone)
    return safe_nodes
