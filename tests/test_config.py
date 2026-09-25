import pytest

from tamper_scanner.config import assessor_from_environment, password_from_environment


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


def test_password_is_optional_for_local_use() -> None:
    assert password_from_environment({"TAMPER_SCANNER_ASSESSOR": "openai"}) is None


def test_password_is_read_from_environment() -> None:
    assert password_from_environment({"TAMPER_SCANNER_PASSWORD": "s3cret"}) == "s3cret"


def test_hosted_openai_assessor_requires_password() -> None:
    with pytest.raises(ValueError, match="TAMPER_SCANNER_PASSWORD"):
        password_from_environment({"VERCEL": "1", "TAMPER_SCANNER_ASSESSOR": "openai"})


def test_hosted_deterministic_assessor_does_not_require_password() -> None:
    assert password_from_environment({"VERCEL": "1"}) is None
