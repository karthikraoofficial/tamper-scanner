"""The deterministic assessment seam used by the application and harness."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from .llm import AssessmentResponse

Verdict = Literal["likely_untouched", "suspicious", "inconclusive"]


@dataclass(frozen=True)
class Evidence:
    id: str
    category: str
    severity: Literal["info", "warning", "critical"]
    explanation: str


@dataclass(frozen=True)
class Assessment:
    document_sha256: str
    verdict: Verdict
    evidence: tuple[Evidence, ...]
    assessor: str
    review_required: bool
    confidence: str = "low"
    rationale: str = ""
    forensic_tool: str = ""
    model_version: str = ""
    prompt_version: str = ""
    page_count: int = 0


class Assessor(Protocol):
    @property
    def name(self) -> str: ...

    def assess(self, evidence_bundle: dict[str, object]) -> AssessmentResponse: ...


class Inspector(Protocol):
    def inspect(self, document: bytes) -> Any: ...


class FakeAssessor:
    """Deterministic placeholder used until a reviewed forensic adapter exists."""

    name = "fake"

    def assess(self, evidence_bundle: dict[str, object]) -> AssessmentResponse:
        del evidence_bundle
        return AssessmentResponse(
            verdict="inconclusive",
            confidence="low",
            evidence_ids=[],
            rationale="The deterministic first slice cannot establish document authenticity.",
            review_required=True,
        )


class AssessmentRunner:
    """Turn document bytes into a stable, auditable assessment record."""

    def __init__(self, assessor: Assessor, inspector: Inspector, trace=None) -> None:
        self._assessor = assessor
        self._inspector = inspector
        self._trace = trace

    def assess(self, document: bytes) -> Assessment:
        self._record_trace("forensics.started", {})
        report = self._inspector.inspect(document)
        self._record_trace(
            "forensics.completed",
            {"page_count": report.page_count, "signal_count": len(report.signals), "tool": report.tool},
        )
        evidence_bundle = {
            "page_count": report.page_count,
            "metadata": report.metadata,
            "forensic_tool": report.tool,
            "evidence": [
                {
                    "id": item.id,
                    "category": item.category,
                    "severity": item.severity,
                    "explanation": item.explanation,
                }
                for item in report.signals
            ],
        }
        self._record_trace("assessor.started", {"assessor": self._assessor.name})
        model_result = self._assessor.assess(evidence_bundle)
        self._record_trace(
            "assessor.completed",
            {"verdict": model_result.verdict, "confidence": model_result.confidence},
        )
        cited_ids = set(model_result.evidence_ids)
        forensic_ids = {item.id for item in report.signals}
        if not cited_ids.issubset(forensic_ids):
            raise ValueError("The assessor cited evidence that was not present in the evidence bundle.")
        critical_evidence = tuple(item for item in report.signals if item.severity == "critical")
        verdict = "suspicious" if critical_evidence else model_result.verdict
        review_required = model_result.review_required or bool(critical_evidence)
        rationale = model_result.rationale
        if critical_evidence and model_result.verdict == "likely_untouched":
            rationale = (
                "Deterministic forensic evidence requires review, so the model's likely untouched "
                "suggestion was overridden. "
                + rationale
            )
        assessment = Assessment(
            document_sha256=hashlib.sha256(document).hexdigest(),
            verdict=verdict,
            evidence=report.signals,
            assessor=self._assessor.name,
            review_required=review_required,
            confidence=model_result.confidence,
            rationale=rationale,
            forensic_tool=report.tool,
            model_version=getattr(self._assessor, "model_version", self._assessor.name),
            prompt_version=getattr(self._assessor, "prompt_version", ""),
            page_count=report.page_count,
        )
        self._record_trace(
            "assessment.completed",
            {"verdict": assessment.verdict, "review_required": assessment.review_required},
        )
        return assessment

    def _record_trace(self, name: str, attributes: dict[str, object]) -> None:
        if self._trace is not None:
            self._trace.record(name, attributes)
