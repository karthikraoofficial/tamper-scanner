# Traceability Workflow

Each assessment run has a stable ID and a redacted append-only decision trail:

1. `forensics.started`
2. `forensics.completed`
3. `assessor.started`
4. `assessor.completed`
5. `assessment.completed`
6. `review.completed`, when a reviewer labels the result
7. `assessment.deleted`, when the source artifact is deleted

The SQLite ledger stores structured evidence, verdict, rationale, confidence, document fingerprint, page count, forensic tool, assessor, model version, prompt version, reviewer label, reviewer notes, and trace attributes. It intentionally excludes document bytes, extracted account data, prompts, and raw model responses.

Deleting an assessment removes it from normal result retrieval and deletes its encrypted PDF artifact, but preserves the redacted ledger record and trace for auditability and historical evals.

The main inspection endpoints are `GET /assessments/{id}/trace` and `GET /diagnostics/summary`. The visual dashboard is available at `/traceability`; it lists recent runs and lets a reviewer select a run to inspect its ordered events.

## Decision feedback

The review interface records `reviewer_correct` for every reviewed decision. An incorrect result must include `corrected_verdict`; optional notes explain the correction. The ledger preserves both the original model verdict and the corrected human verdict. Historical eval cases use the corrected verdict as ground truth, which makes previous false positives and false negatives measurable on later assessor or prompt versions.