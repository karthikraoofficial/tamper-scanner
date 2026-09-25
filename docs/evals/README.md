# Evaluation Harness

Eval cases are synthetic or redacted and contain an evidence bundle, an expected three-way verdict, and expected evidence IDs. Cases are evaluated through the provider-neutral `DocumentAssessor` seam.

The initial harness reports verdict accuracy and evidence citation coverage. Future suites should add abstention rate, suspicious-case recall, false-positive rate, calibration by document class, and holdout splits by statement template or source.

Use `run_holdout` with cases marked `split="holdout"` to produce a `HoldoutReport`. Promotion is allowed only when accuracy and evidence coverage meet their configured thresholds. The library defaults are both `1.0`; the live application uses configurable `0.8` thresholds so any material regression blocks promotion until it is reviewed.

In the running application, reviewer labels are persisted in the assessment ledger and replayed through `POST /evals/run`. The visual dashboard is available at `/evals` and includes a Run evaluation action, current metrics, historical reports, and model/prompt versions. The live defaults are 0.8 accuracy and 0.8 evidence coverage, configurable through environment variables. Each report stores the assessor, model version, prompt version, timestamp, metrics, and blockers.

Reviewer-approved cases may become exemplars only after redaction and deduplication. A prompt or model change must run against a holdout set and receive an explicit promotion record before production use.

The live reviewer controls create two kinds of learning signal: correct decisions reinforce the existing expected verdict, while incorrect decisions replace it with the reviewer's corrected verdict and retain the original output for error analysis. This is supervised evaluation feedback, not automatic model-weight updates.

Raw PDFs, account numbers, prompts, and model responses must not be stored in traces or committed as fixtures.
