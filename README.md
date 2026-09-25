# Tamper Scanner

Tamper Scanner is an early local browser application for reviewable bank statement PDF assessment. It currently includes deterministic PDF observations, a schema-validated model-assessment seam, replayable eval primitives, and redacted structured traces. It does not yet make a production tamper determination.

## Setup

Create and activate a virtual environment, then install the project with its test tools:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -e ".[test]"
```

## Usage

Start the local browser application:

```powershell
tamper-scanner-web
```

Open `http://127.0.0.1:9027`, upload a PDF, and review the structured result. Set `TAMPER_SCANNER_PORT` to override the default if needed. The default browser route uses the deterministic assessor; set `TAMPER_SCANNER_ASSESSOR=openai` to use the configured OpenAI assessor.

The default assessor is deterministic and offline. To explicitly enable the OpenAI assessor, configure the provider before starting the app:

```powershell
$env:TAMPER_SCANNER_ASSESSOR = "openai"
$env:OPENAI_API_KEY = "replace-with-a-secret"
$env:OPENAI_MODEL = "gpt-4.1"
$env:TAMPER_SCANNER_PROMPT_VERSION = "assessment-v1"
tamper-scanner-web
```

The assessment response records the assessor, model version, and prompt version. Missing `OPENAI_API_KEY` fails closed when the OpenAI assessor is selected.

## Evals and traceability

Every assessment is recorded in the local SQLite ledger at `.tamper-scanner-ledger.db`. The ledger stores the document fingerprint, forensic evidence, verdict, rationale, assessor/model/prompt versions, reviewer correction, and redacted stage events. It never stores the uploaded PDF, raw prompt, or raw model response.

Operational endpoints:

- `GET /assessments/{id}/trace` shows the decision stages for one run.
- `GET /diagnostics/summary` shows recent runs, verdict distribution, reviewed count, and eval reports.
- `POST /assessments/{id}/review` records a reviewer label and notes as an audit event.
- `POST /evals/run` replays the current assessor against reviewed historical cases and stores the report.

Visual dashboards:

- `http://127.0.0.1:9027/evals` shows evaluation metrics, historical reports, model/prompt versions, and a Run evaluation action.
- `http://127.0.0.1:9027/traceability` shows recent assessment runs and an interactive decision trail for each run.

After each assessment, use **Correct** when the application verdict is right. Use **Incorrect** to select the corrected verdict and optionally add a note. Incorrect decisions become labeled regression cases; the next eval run checks whether the configured assessor repeats them.

Promotion defaults are `80%` verdict accuracy and `80%` evidence citation coverage. Configure them with `TAMPER_SCANNER_MIN_EVAL_ACCURACY` and `TAMPER_SCANNER_MIN_EVIDENCE_COVERAGE`. A failed report is not promotable and must be reviewed before changing the production assessor or prompt.

To enable encrypted artifact retention, set `TAMPER_SCANNER_ENCRYPTION_KEY` before starting the application. Uploaded PDFs are written as Fernet ciphertext under `.tamper-scanner-artifacts` and are removed by the assessment deletion endpoint. Leave the variable unset to run without document retention.

Set `TAMPER_SCANNER_PASSWORD` to require HTTP Basic authentication on every route (any username, this password). Set `TAMPER_SCANNER_DATA_DIR` to change where the ledger and artifacts are stored.

## Vercel demo deployment

`api/index.py` serves the app on Vercel with data under `/tmp`, which is ephemeral and not shared between instances, so history, reviews, and evals are not durable there. When hosted with `TAMPER_SCANNER_ASSESSOR=openai`, the app refuses to start unless `TAMPER_SCANNER_PASSWORD` is set, so the OpenAI key cannot be used anonymously.

Create a baseline for a directory:

```powershell
tamper-scanner baseline .\data .\manifest.json
```

Check the directory against that baseline:

```powershell
tamper-scanner scan .\data .\manifest.json
```

The scan exits with code `0` when no changes are found and `1` when files were added, changed, or removed.

Run tests with `py -m pytest`.

## Engineering workflow

The implementation is organized as small tracer-bullet tickets in [docs/tickets.md](docs/tickets.md), with user stories in [docs/specs/user-stories.md](docs/specs/user-stories.md). Public seams are tested red-green before adapters are expanded. The shared domain vocabulary and safety contract live in [CONTEXT.md](CONTEXT.md).

Real bank statements, provider credentials, and raw model traces must not be committed. Holdout promotion requires every configured threshold to pass; a regression report is non-promotable by default. See [docs/evals/README.md](docs/evals/README.md) for the evaluation policy.
