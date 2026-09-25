"""Explicit construction of assessment adapters from deployment configuration."""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from typing import Any

from .assessment import FakeAssessor
from .llm import DocumentAssessor, OpenAIAssessor


def assessor_from_environment(
    environment: Mapping[str, str] | None = None,
    client_factory: Callable[[str], Any] | None = None,
) -> DocumentAssessor:
    values = environment if environment is not None else os.environ
    kind = values.get("TAMPER_SCANNER_ASSESSOR", "fake").lower()
    if kind == "fake":
        return FakeAssessor()
    if kind != "openai":
        raise ValueError("TAMPER_SCANNER_ASSESSOR must be 'fake' or 'openai'.")

    api_key = values.get("OPENAI_API_KEY")
    if not api_key:
        raise ValueError("OPENAI_API_KEY is required for the OpenAI assessor.")
    model = values.get("OPENAI_MODEL", "gpt-4.1")
    prompt_version = values.get("TAMPER_SCANNER_PROMPT_VERSION", "assessment-v1")
    if client_factory is None:
        from openai import OpenAI

        client = OpenAI(api_key=api_key)
    else:
        client = client_factory(api_key)
    return OpenAIAssessor(client=client, model=model, prompt_version=prompt_version)
