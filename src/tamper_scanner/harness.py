"""Replayable evaluation and redacted observability primitives."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .llm import AssessmentResponse, DocumentAssessor, Verdict


@dataclass(frozen=True)
class EvalCase:
    id: str
    evidence_bundle: dict[str, object]
    expected_verdict: Verdict
    expected_evidence_ids: set[str] = field(default_factory=set)
    split: str = "holdout"
    feedback_correct: bool | None = None


@dataclass(frozen=True)
class EvalResult:
    case_id: str
    verdict_correct: bool
    evidence_coverage: float


@dataclass(frozen=True)
class HoldoutReport:
    total_cases: int
    accuracy: float
    evidence_coverage: float
    promotable: bool
    blockers: tuple[str, ...]


def evaluate(case: EvalCase, assessor: DocumentAssessor) -> EvalResult:
    response = assessor.assess(case.evidence_bundle)
    expected = case.expected_evidence_ids
    cited = set(response.evidence_ids)
    coverage = len(expected & cited) / len(expected) if expected else 1.0
    return EvalResult(
        case_id=case.id,
        verdict_correct=response.verdict == case.expected_verdict,
        evidence_coverage=coverage,
    )


def run_holdout(
    cases: list[EvalCase],
    assessor: DocumentAssessor,
    *,
    minimum_accuracy: float = 1.0,
    minimum_evidence_coverage: float = 1.0,
) -> HoldoutReport:
    holdout_cases = [case for case in cases if case.split == "holdout"]
    if not holdout_cases:
        raise ValueError("At least one holdout eval case is required.")
    results = [evaluate(case, assessor) for case in holdout_cases]
    accuracy = sum(result.verdict_correct for result in results) / len(results)
    evidence_coverage = sum(result.evidence_coverage for result in results) / len(results)
    blockers: list[str] = []
    if accuracy < minimum_accuracy:
        blockers.append("accuracy")
    if evidence_coverage < minimum_evidence_coverage:
        blockers.append("evidence_coverage")
    return HoldoutReport(
        total_cases=len(results),
        accuracy=accuracy,
        evidence_coverage=evidence_coverage,
        promotable=not blockers,
        blockers=tuple(blockers),
    )


class TraceRecorder:
    """Keep structured events while excluding raw document and prompt fields."""

    _sensitive_fields = frozenset({"document", "document_text", "prompt", "response", "account_number"})

    def __init__(self) -> None:
        self.events: list[dict[str, object]] = []

    def record(self, name: str, attributes: dict[str, Any]) -> None:
        self.events.append(
            {
                "name": name,
                "attributes": {
                    key: value for key, value in attributes.items() if key not in self._sensitive_fields
                },
            },
        )
