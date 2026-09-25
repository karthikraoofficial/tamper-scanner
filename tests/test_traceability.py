from tamper_scanner.assessment import AssessmentRunner, Evidence
from tamper_scanner.harness import TraceRecorder
from tamper_scanner.llm import AssessmentResponse


class Inspector:
    tool = "test"

    def inspect(self, document):
        return type("Report", (), {"page_count": 1, "metadata": {}, "tool": self.tool, "signals": ()})()


class Assessor:
    name = "test-assessor"
    model_version = "test-model"
    prompt_version = "test-prompt"

    def assess(self, evidence_bundle):
        return AssessmentResponse(
            verdict="inconclusive",
            confidence="low",
            evidence_ids=[],
            rationale="Needs review.",
            review_required=True,
        )


def test_runner_records_decision_stages_without_sensitive_payloads() -> None:
    trace = TraceRecorder()

    AssessmentRunner(Assessor(), Inspector(), trace=trace).assess(b"pdf")

    names = [event["name"] for event in trace.events]
    assert names == [
        "forensics.started",
        "forensics.completed",
        "assessor.started",
        "assessor.completed",
        "assessment.completed",
    ]