import pytest

from tamper_scanner.config import assessor_from_environment


def test_default_configuration_uses_deterministic_assessor() -> None:
    assessor = assessor_from_environment({}, client_factory=None)

    assert assessor.name == "fake"


def test_openai_configuration_requires_api_key() -> None:
    with pytest.raises(ValueError, match="OPENAI_API_KEY"):
        assessor_from_environment({"TAMPER_SCANNER_ASSESSOR": "openai"}, client_factory=None)


def test_openai_configuration_defaults_to_capable_model() -> None:
    assessor = assessor_from_environment(
        {"TAMPER_SCANNER_ASSESSOR": "openai", "OPENAI_API_KEY": "test-key"},
        client_factory=lambda key: object(),
    )

    assert assessor.model_version == "gpt-4.1"
