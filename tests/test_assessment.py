from tamper_scanner.assessment import AssessmentRunner, Evidence, FakeAssessor
from tamper_scanner.forensics import ForensicReport


def test_runner_returns_a_replayable_structured_assessment() -> None:
    class TestInspector:
        tool = "test"

        def inspect(self, document: bytes) -> ForensicReport:
            del document
            return ForensicReport(
                page_count=1,
                metadata={},
                signals=(Evidence("assessment-limit", "assessment_limit", "warning", "test"),),
                tool=self.tool,
            )

    runner = AssessmentRunner(assessor=FakeAssessor(), inspector=TestInspector())

    assessment = runner.assess(b"%PDF-1.7\nsynthetic statement")

    assert assessment.verdict == "inconclusive"
    assert assessment.document_sha256 == "d9040991889da1eb40e31110095f2e67409736c6823f7bde5bfc2afe1a6393bd"
    assert assessment.assessor == "fake"
    assert assessment.evidence[0].category == "assessment_limit"
    assert assessment.review_required is True
    assert assessment.forensic_tool == "test"


def test_runner_passes_forensic_evidence_to_the_assessor() -> None:
    class RecordingAssessor:
        name = "recording"

        def __init__(self) -> None:
            self.bundle = None

        def assess(self, evidence_bundle: dict[str, object]):
            self.bundle = evidence_bundle
            return FakeAssessor().assess(b"ignored")

    assessor = RecordingAssessor()
    class TestInspector:
        tool = "test"

        def inspect(self, document: bytes) -> ForensicReport:
            del document
            return ForensicReport(
                page_count=1,
                metadata={},
                signals=(Evidence("signal-1", "test", "info", "test"),),
                tool=self.tool,
            )

    runner = AssessmentRunner(assessor=assessor, inspector=TestInspector())

    runner.assess(b"%PDF-1.7\nsynthetic statement")

    assert assessor.bundle["forensic_tool"] == "test"
    assert isinstance(assessor.bundle["evidence"], list)


def test_runner_does_not_allow_untouched_verdict_with_critical_mismatch() -> None:
    class TestInspector:
        tool = "test"

        def inspect(self, document: bytes):
            del document
            return type(
                "Report",
                (),
                {
                    "page_count": 1,
                    "metadata": {},
                    "tool": self.tool,
                    "signals": (Evidence("balance-mismatch", "balance_consistency", "critical", "Mismatch"),),
                },
            )()

    class UnsafeAssessor:
        name = "unsafe-test"

        def assess(self, evidence_bundle):
            del evidence_bundle
            from tamper_scanner.llm import AssessmentResponse

            return AssessmentResponse(
                verdict="likely_untouched",
                confidence="high",
                evidence_ids=[],
                rationale="Looks normal.",
                review_required=False,
            )

    assessment = AssessmentRunner(UnsafeAssessor(), TestInspector()).assess(b"pdf")

    assert assessment.verdict == "suspicious"
    assert assessment.review_required is True
