# User Stories: Operational Assessment Workflow

## US-001: Submit a statement for assessment

**As an analyst**, I want to upload a PDF bank statement, **so that** the application creates an assessment run without requiring a command-line workflow.

**Acceptance criteria**

- A PDF upload returns an assessment ID.
- The assessment records the document SHA-256 hash.
- Empty and non-PDF uploads are rejected with a clear error.
- The response does not expose the document bytes.
- The assessment is persisted in the local ledger and survives an application restart.
- The uploaded artifact is retained only when encrypted retention is configured.

## US-002: Review a structured result

**As an analyst**, I want to see a three-way verdict and its evidence, **so that** I can decide whether human review is needed.

**Acceptance criteria**

- The result is one of `likely_untouched`, `suspicious`, or `inconclusive`.
- Evidence has stable IDs, categories, severity, and explanations.
- The result identifies the assessor, model version, prompt version, forensic tool, page count, and review state.
- The UI presents a readable verdict, rationale, evidence cards, processing details, and user-friendly error states.
- Critical deterministic evidence can override an unsafe `likely_untouched` model result and require human review.

## US-003: Record reviewer feedback

**As a reviewer**, I want to mark the application's decision as Correct or Incorrect, **so that** the system can measure mistakes and improve against historical cases.

**Acceptance criteria**

- A reviewer can mark a decision Correct without entering a replacement verdict.
- A reviewer marking a decision Incorrect must select the corrected verdict.
- Reviewer notes are optional and persisted with the assessment.
- After successful submission, the UI shows `Thanks for your feedback` and removes the feedback controls.
- The feedback action is appended to the assessment trace and survives an application restart.

## US-004: Inspect the decision trail

**As an analyst or reviewer**, I want to inspect every stage of an assessment, **so that** I can understand how the result was produced.

**Acceptance criteria**

- The trace includes forensic start/completion, assessor start/completion, assessment completion, review, and deletion events where applicable.
- Trace events contain structured metadata but never raw PDF bytes, prompts, raw model responses, or account identifiers.
- `GET /assessments/{id}/trace` exposes the trace for a persisted run.
- `GET /diagnostics/summary` exposes recent runs, verdict counts, reviewed counts, and stored eval reports.
- The traceability dashboard lists recent runs and lets a reviewer inspect an ordered decision trail.

## US-005: Learn from reviewed history

**As a system owner**, I want reviewed decisions to become regression eval cases, **so that** future assessor or prompt changes can be measured against previous mistakes.

**Acceptance criteria**

- Correct feedback preserves the application's verdict as expected ground truth.
- Incorrect feedback uses the corrected reviewer verdict as ground truth while retaining the original model result for error analysis.
- `POST /evals/run` replays the configured assessor against reviewed historical cases.
- The evaluation dashboard displays accuracy, evidence coverage, promotion status, historical reports, and model/prompt versions.
- The eval report records accuracy, evidence coverage, assessor, model version, prompt version, and blockers.
- Promotion is blocked when configured accuracy or evidence-coverage thresholds are missed.
- Reviewer feedback does not silently modify model weights or production prompts.
