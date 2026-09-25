import pytest

from tamper_scanner.llm import AssessmentResponse, ScriptedAssessor


def test_scripted_assessor_returns_schema_validated_response() -> None:
    assessor = ScriptedAssessor(
        AssessmentResponse(
            verdict="suspicious",
            confidence="medium",
            evidence_ids=["metadata-mismatch"],
            rationale="The evidence contains a metadata inconsistency.",
            review_required=True,
        ),
    )

    result = assessor.assess({"evidence": [{"id": "metadata-mismatch"}]})

    assert result.verdict == "suspicious"
    assert result.evidence_ids == ["metadata-mismatch"]
    assert result.review_required is True


def test_response_rejects_unknown_verdict() -> None:
    with pytest.raises(ValueError):
        AssessmentResponse.model_validate(
            {
                "verdict": "fraud",
                "confidence": "high",
                "evidence_ids": [],
                "rationale": "bad",
                "review_required": True,
            },
        )
