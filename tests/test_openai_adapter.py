from types import SimpleNamespace

from tamper_scanner.llm import AssessmentResponse, OpenAIAssessor


class FakeResponses:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def parse(self, **kwargs: object) -> SimpleNamespace:
        self.calls.append(kwargs)
        return SimpleNamespace(
            output_parsed=AssessmentResponse(
                verdict="inconclusive",
                confidence="low",
                evidence_ids=[],
                rationale="The evidence is insufficient.",
                review_required=True,
            ),
        )


def test_openai_adapter_uses_structured_output_and_bounded_evidence() -> None:
    responses = FakeResponses()
    assessor = OpenAIAssessor(client=SimpleNamespace(responses=responses), model="test-model")

    result = assessor.assess(
        {
            "evidence": [{"id": "signal-1", "explanation": "metadata mismatch"}],
            "extracted_text": "not sent by this adapter",
        },
    )

    assert result.verdict == "inconclusive"
    assert assessor.name == "openai:test-model"
    assert responses.calls[0]["model"] == "test-model"
    assert "extracted_text" not in str(responses.calls[0]["input"])
