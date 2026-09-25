# Domain Context

## Document
A bank statement PDF submitted for assessment. A document is identified by its SHA-256 hash and is never itself a verdict.

## Assessment
A single attempt to evaluate one document using a pinned forensic tool version, prompt version, and model configuration.

## Forensic signal
A deterministic observation about the PDF, such as metadata inconsistency, a changed page structure, or an absent text layer. A signal is evidence, not proof of tampering.

## Evidence bundle
The bounded, structured set of forensic signals and selected document facts provided to an assessor.

## Verdict
The assessment's decision-support outcome: `likely_untouched`, `suspicious`, or `inconclusive`.

## Reviewer label
A human's later judgment of an assessment. Reviewer labels are the source of truth for eval cases and exemplars.

## Exemplar
A redacted, reviewer-approved assessment used to improve retrieval context or assessment prompts.

## Eval case
A versioned, labeled document scenario used to measure forensic and LLM behavior without silently changing production behavior.

## Assessment run
The auditable record tying a document, evidence bundle, assessor output, versions, and timestamps together.

## Decision feedback
A reviewer's explicit Correct or Incorrect judgment. An Incorrect judgment includes the corrected verdict and becomes supervised ground truth for historical evals; it does not change model weights automatically.

## Decision trail
The ordered, redacted events describing how an assessment was produced, reviewed, or deleted.

## Eval report
A versioned measurement of an assessor against reviewed cases, including verdict accuracy, evidence coverage, model/prompt versions, and promotion blockers.

## Safety contract
Tamper Scanner is decision support, not proof of fraud or a legal conclusion. Every verdict must expose uncertainty, evidence references, version information, and a human-review path.
