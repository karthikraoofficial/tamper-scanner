"""Provider-neutral contract for model-backed document assessment."""

from __future__ import annotations

import json
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

Verdict = Literal["likely_untouched", "suspicious", "inconclusive"]
Confidence = Literal["low", "medium", "high"]


class AssessmentResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verdict: Verdict
    confidence: Confidence
    evidence_ids: list[str] = Field(default_factory=list)
    rationale: str = Field(min_length=1, max_length=2000)
    review_required: bool


class DocumentAssessor(Protocol):
    @property
    def name(self) -> str: ...

    def assess(self, evidence_bundle: dict[str, object]) -> AssessmentResponse: ...


class ScriptedAssessor:
    """Deterministic adapter for replay, route, and evaluation tests."""

    name = "scripted"
    model_version = "scripted"
    prompt_version = "scripted-v1"

    def __init__(self, response: AssessmentResponse) -> None:
        self._response = response

    def assess(self, evidence_bundle: dict[str, object]) -> AssessmentResponse:
        del evidence_bundle
        return self._response


class OpenAIAssessor:
    """OpenAI Responses adapter; credentials and client construction stay outside this module."""

    def __init__(self, client: Any, model: str, prompt_version: str = "assessment-v1") -> None:
        self._client = client
        self._model = model
        self.prompt_version = prompt_version
        self.model_version = model

    @property
    def name(self) -> str:
        return f"openai:{self._model}"

    def assess(self, evidence_bundle: dict[str, object]) -> AssessmentResponse:
        bounded_bundle = {"evidence": evidence_bundle.get("evidence", [])}
        response = self._client.responses.parse(
            model=self._model,
            input=[
                {
                    "role": "system",
                    "content": (
                        "Assess PDF tamper evidence as decision support. "
                        "Never claim proof of fraud. Cite only supplied evidence IDs. "
                        "Check balance arithmetic and consistency between transaction balances, "
                        "opening balance, and closing balance. Treat contradictions as suspicious "
                        "or inconclusive and require human review."
                    ),
                },
                {"role": "user", "content": json.dumps(bounded_bundle, sort_keys=True)},
            ],
            text_format=AssessmentResponse,
        )
        parsed = getattr(response, "output_parsed", None)
        if isinstance(parsed, AssessmentResponse):
            return parsed
        return AssessmentResponse.model_validate(parsed)
