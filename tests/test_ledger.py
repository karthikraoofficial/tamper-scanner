import json

from tamper_scanner.assessment import Assessment, Evidence
from tamper_scanner.ledger import AssessmentLedger


def assessment() -> Assessment:
    return Assessment(
        document_sha256="abc123",
        verdict="suspicious",
        evidence=(Evidence("signal-1", "balance_consistency", "critical", "Mismatch"),),
        assessor="scripted",
        review_required=True,
        confidence="high",
        rationale="Review required.",
        forensic_tool="pypdf",
        model_version="test-model",
        prompt_version="prompt-v1",
        page_count=3,
    )


def test_ledger_persists_run_trace_and_reviewer_label(tmp_path) -> None:
    ledger = AssessmentLedger(tmp_path / "ledger.db")

    ledger.record_run(
        "run-1",
        assessment(),
        [{"name": "forensics.completed", "attributes": {"signal_count": 1}}],
    )
    ledger.set_reviewer_label("run-1", "suspicious", "Balance mismatch confirmed", correct=True)

    stored = ledger.get_run("run-1")

    assert stored["reviewer_label"] == "suspicious"
    assert stored["reviewer_correct"] is True
    assert stored["evidence"][0]["id"] == "signal-1"
    assert stored["traces"][0]["name"] == "forensics.completed"
    assert "response" not in json.dumps(stored)


def test_ledger_exposes_reviewed_cases_for_learning(tmp_path) -> None:
    ledger = AssessmentLedger(tmp_path / "ledger.db")
    ledger.record_run("run-1", assessment(), [])
    ledger.set_reviewer_label(
        "run-1",
        "likely_untouched",
        "Reviewer corrected the model",
        correct=False,
    )

    cases = ledger.reviewed_eval_cases()

    assert cases[0].id == "run-1"
    assert cases[0].expected_verdict == "likely_untouched"
    assert cases[0].split == "historical"
    assert cases[0].feedback_correct is False