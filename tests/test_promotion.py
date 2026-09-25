from tamper_scanner.harness import EvalCase, run_holdout
from tamper_scanner.llm import AssessmentResponse, ScriptedAssessor


def test_holdout_suite_promotes_a_non_regressing_assessor() -> None:
    assessor = ScriptedAssessor(
        AssessmentResponse(
            verdict="suspicious",
            confidence="high",
            evidence_ids=["signal-1"],
            rationale="Review the signal.",
            review_required=True,
        ),
    )
    cases = [
        EvalCase(
            id="holdout-1",
            evidence_bundle={"evidence": [{"id": "signal-1"}]},
            expected_verdict="suspicious",
            expected_evidence_ids={"signal-1"},
            split="holdout",
        ),
    ]

    report = run_holdout(cases, assessor)

    assert report.promotable is True
    assert report.accuracy == 1.0


def test_holdout_suite_blocks_regression() -> None:
    assessor = ScriptedAssessor(
        AssessmentResponse(
            verdict="likely_untouched",
            confidence="high",
            evidence_ids=[],
            rationale="No issue.",
            review_required=False,
        ),
    )
    cases = [
        EvalCase(
            id="holdout-1",
            evidence_bundle={"evidence": [{"id": "signal-1"}]},
            expected_verdict="suspicious",
            expected_evidence_ids={"signal-1"},
            split="holdout",
        ),
    ]

    report = run_holdout(cases, assessor)

    assert report.promotable is False
    assert "accuracy" in report.blockers
