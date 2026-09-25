from tamper_scanner.harness import EvalCase, TraceRecorder, evaluate
from tamper_scanner.llm import AssessmentResponse, ScriptedAssessor


def test_eval_reports_verdict_and_evidence_accuracy() -> None:
    assessor = ScriptedAssessor(
        AssessmentResponse(
            verdict="suspicious",
            confidence="high",
            evidence_ids=["signal-1"],
            rationale="The signal requires human review.",
            review_required=True,
        ),
    )
    case = EvalCase(
        id="synthetic-suspicious-1",
        evidence_bundle={"evidence": [{"id": "signal-1"}]},
        expected_verdict="suspicious",
        expected_evidence_ids={"signal-1"},
    )

    result = evaluate(case, assessor)

    assert result.verdict_correct is True
    assert result.evidence_coverage == 1.0


def test_trace_recorder_does_not_store_sensitive_payloads() -> None:
    trace = TraceRecorder()

    trace.record("assessment", {"document_text": "account 123456", "verdict": "inconclusive"})

    assert trace.events == [{"name": "assessment", "attributes": {"verdict": "inconclusive"}}]
