# ADR 0001: First Vertical Slice

## Status

Accepted

## Decision

The first application slice will run locally through a FastAPI interface and use a deterministic fake assessor. The public seam is an `AssessmentRunner` that accepts PDF bytes and returns a structured assessment. PDF inspection and model assessment remain replaceable adapters.

The production LLM adapter will be added only after the deterministic route, evidence schema, and reviewer feedback loop have executable tests.

## Rationale

This gives the harness a reproducible end-to-end path without requiring cloud credentials or sending sensitive documents to a provider. It also keeps the model's judgment separate from deterministic PDF observations.

## Consequences

- The first result is useful for wiring and evaluation, but is not a production fraud decision.
- Fake assessment outputs can be replayed in CI.
- The future OpenAI adapter must satisfy the same assessor interface and schema.
