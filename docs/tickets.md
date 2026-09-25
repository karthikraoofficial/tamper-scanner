# Tracer-Bullet Tickets

Status reflects the current implementation as of 2026-09-16. The SQLite ledger is the persisted decision-trail seam; reviewed feedback is supervised eval data, not automatic model training.

## TS-001: Deterministic assessment seam

**User stories:** US-001, US-002

**Blocks:** TS-002, TS-003

**Done:** PDF bytes become a typed assessment through `AssessmentRunner`; tests cover hash, evidence, verdict, and assessor metadata.

## TS-002: Local upload and result routes

**User stories:** US-001, US-002

**Blocked by:** TS-001

**Done:** FastAPI exposes upload and assessment retrieval with validation errors and no document bytes in responses.

## TS-003: Reviewer feedback route

**User stories:** US-003

**Blocked by:** TS-002

**Done:** Reviewers can mark a decision Correct or Incorrect. Incorrect decisions require a corrected verdict; optional notes, correctness, and corrected labels are persisted and returned.

## TS-004: PDF forensic adapter

**User stories:** US-002

**Blocked by:** TS-001

**Done:** `PdfInspector` uses pypdf to produce normalized metadata, page counts, text-layer signals, and encrypted-document warnings behind a testable seam.

## TS-005: Production assessor adapter

**User stories:** US-002

**Blocked by:** TS-001, TS-004

**Done:** The provider-neutral `DocumentAssessor`, strict `AssessmentResponse`, deterministic scripted adapter, injected-client OpenAI Responses adapter, environment configuration, and model/prompt version recording are implemented and tested. Credentialed provider tests remain intentionally outside the default suite.

## TS-006: Replayable eval and redacted traces

**User stories:** US-002, US-003

**Done:** Eval cases measure verdict correctness and evidence coverage; `run_holdout` supports configurable promotion thresholds; reviewed ledger cases feed the live `/evals/run` endpoint; reports are persisted with assessor/model/prompt versions.

**Remaining:** Larger labeled fixture datasets, calibration, suspicious-case recall, false-positive rate, abstention metrics, and automated CI promotion enforcement.

## TS-007: Wire forensic evidence into assessment workflow

**User stories:** US-001, US-002

**Blocked by:** TS-004, TS-005

**Done:** The runner inspects uploaded PDFs, builds a bounded evidence bundle, calls the configured assessor, validates cited evidence IDs, and returns model output with forensic tool metadata. The browser route uses this runner with the deterministic assessor by default or OpenAI when explicitly configured.

## TS-008: Durable encrypted retention

**User stories:** US-001, US-003

**Blocked by:** TS-007

**Done:** `EncryptedArtifactStore` uses Fernet ciphertext, requires a non-empty key, validates artifact IDs, and supports explicit deletion. The configured web app saves and deletes artifacts. Unconfigured local mode intentionally disables retention.

Deletion is a soft delete in the ledger: normal assessment retrieval and recent-run listings hide the run, while the redacted trace remains available for audit and historical evals.

## TS-009: Configure production assessor

**User stories:** US-002

**Blocked by:** TS-005, TS-007

**Done:** Environment configuration constructs the fake assessor by default or the OpenAI assessor explicitly, requires `OPENAI_API_KEY` for OpenAI mode, and records model/prompt versions in each assessment. The adapter remains injected and credential-isolated in tests.

## TS-010: Holdout promotion gates

**User stories:** US-002, US-003

**Done:** `run_holdout` evaluates only cases marked `holdout`, reports accuracy and evidence coverage, and blocks promotion whenever configured thresholds are missed. Default thresholds require no holdout regression.

The live application uses configurable defaults of 0.8 for accuracy and evidence coverage through `TAMPER_SCANNER_MIN_EVAL_ACCURACY` and `TAMPER_SCANNER_MIN_EVIDENCE_COVERAGE`.

## TS-011: Persisted assessment ledger

**User stories:** US-001, US-003, US-004, US-005

**Done:** SQLite `AssessmentLedger` persists assessment metadata, structured evidence, reviewer feedback, redacted traces, historical eval cases, and eval reports. It excludes PDF bytes and raw model payloads.

## TS-012: Operational traceability endpoints

**User stories:** US-004

**Done:** The application exposes `GET /assessments/{id}/trace` and `GET /diagnostics/summary`. Assessment, review, and deletion events are appended to the ledger trace.

## TS-013: Correct/Incorrect feedback loop

**User stories:** US-003, US-005

**Done:** The UI provides Correct and Incorrect controls, requires a corrected verdict for incorrect feedback, confirms `Thanks for your feedback`, hides controls after submission, and feeds corrected labels into historical evals.

## TS-014: Visual evaluation dashboard

**User stories:** US-005

**Done:** `/evals` displays current accuracy, evidence coverage, promotion status, historical case count, model/prompt versions, prior reports, and a Run evaluation action.

## TS-015: Visual traceability dashboard

**User stories:** US-004

**Done:** `/traceability` displays run counts, verdict distribution, reviewer status, recent assessment history, and an interactive ordered trace for a selected run.

## Documentation rule

Every implementation ticket must update the relevant markdown in the same change. At minimum, check [user-stories.md](specs/user-stories.md), this ticket map, [README.md](../README.md), and the relevant operational guide under `docs/`. New user-visible behavior is not complete until its user story, acceptance criteria, ticket status, usage documentation, and test evidence are current.
