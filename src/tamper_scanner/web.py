"""FastAPI adapter for the first local assessment workflow."""

from __future__ import annotations

import os
from dataclasses import asdict
from pathlib import Path
from typing import Literal
from uuid import uuid4

from fastapi import FastAPI, File, HTTPException, UploadFile, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from .assessment import Assessment, AssessmentRunner
from .config import assessor_from_environment
from .forensics import PdfInspector
from .harness import TraceRecorder, run_holdout
from .ledger import AssessmentLedger
from .storage import EncryptedArtifactStore


class ReviewRequest(BaseModel):
    correct: bool | None = None
    label: Literal["likely_untouched", "suspicious", "inconclusive"] | None = None
    corrected_verdict: Literal["likely_untouched", "suspicious", "inconclusive"] | None = None
    notes: str = ""


def create_app(
    encryption_key: str | None = None,
    artifact_root: Path | None = None,
    ledger_path: Path | None = None,
    assessor=None,
) -> FastAPI:
    application = FastAPI(title="Tamper Scanner")
    configured_assessor = assessor or assessor_from_environment()
    ledger = AssessmentLedger(ledger_path or Path(".tamper-scanner-ledger.db"))
    artifact_store = None
    if encryption_key:
        artifact_store = EncryptedArtifactStore(
            artifact_root or Path(".tamper-scanner-artifacts"),
            encryption_key,
        )
    assessments: dict[str, dict[str, object]] = {}

    @application.get("/", response_class=HTMLResponse)
    def home() -> str:
        return """<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Tamper Scanner</title>
    <style>
        :root { color-scheme: light; font-family: system-ui, sans-serif; color: #17212b; background: #eef3f5; }
        * { box-sizing: border-box; }
        body { margin: 0; }
        main { width: min(960px, calc(100% - 32px)); margin: 48px auto; }
        header { margin-bottom: 24px; }
        h1 { margin: 0 0 8px; font-size: clamp(2rem, 5vw, 3.4rem); letter-spacing: -0.04em; }
        h2, h3 { margin-top: 0; }
        .muted { color: #5d6b75; }
        .panel { background: #fff; border: 1px solid #d6e0e4; border-radius: 8px; padding: 24px; box-shadow: 0 8px 24px #17304212; }
        form { display: flex; flex-wrap: wrap; align-items: end; gap: 16px; }
        label { display: grid; gap: 8px; font-weight: 700; }
        input[type=file] { max-width: 100%; padding: 10px; border: 1px solid #aebdc5; border-radius: 5px; background: #f8fafb; }
        button { border: 0; border-radius: 5px; padding: 11px 18px; background: #126782; color: #fff; font: inherit; font-weight: 700; cursor: pointer; }
        button:hover { background: #0d5268; }
        button:disabled { opacity: .6; cursor: wait; }
        #result { display: none; margin-top: 24px; }
        .result-header { display: flex; justify-content: space-between; align-items: start; gap: 16px; border-bottom: 1px solid #d6e0e4; padding-bottom: 20px; }
        .verdict { display: inline-flex; padding: 7px 11px; border-radius: 999px; font-weight: 800; font-size: .9rem; }
        .verdict.untouched { color: #075d3c; background: #d9f2e6; }
        .verdict.suspicious { color: #8b3d00; background: #ffe5c7; }
        .verdict.inconclusive { color: #5d4a00; background: #fff3bf; }
        .summary { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin: 20px 0; }
        .stat { padding: 14px; background: #f3f7f8; border-radius: 6px; }
        .stat-label { display: block; color: #5d6b75; font-size: .8rem; text-transform: uppercase; letter-spacing: .06em; }
        .stat-value { display: block; margin-top: 5px; font-weight: 800; }
        .rationale { border-left: 4px solid #126782; padding: 4px 0 4px 16px; line-height: 1.6; }
        .evidence-list { display: grid; gap: 10px; }
        .evidence { padding: 16px; border: 1px solid #d6e0e4; border-left: 5px solid #8aa1aa; border-radius: 5px; }
        .evidence.warning { border-left-color: #d48722; }
        .evidence.critical { border-left-color: #bb3b35; }
        .evidence-title { display: flex; justify-content: space-between; gap: 12px; font-weight: 800; }
        .evidence p { margin: 8px 0 0; line-height: 1.5; }
        dl { display: grid; grid-template-columns: minmax(140px, .35fr) 1fr; gap: 8px 20px; margin: 0; }
        dt { color: #5d6b75; }
        dd { margin: 0; overflow-wrap: anywhere; }
        .error { color: #8f211e; background: #fff0ef; border: 1px solid #e2aaa7; }
        @media (max-width: 640px) { main { margin: 24px auto; } .summary { grid-template-columns: 1fr; } .result-header { display: block; } }
    </style>
</head>
<body>
    <main>
        <header>
            <h1>Tamper Scanner</h1>
            <p class="muted">Review structural signals in a bank statement PDF.</p>
            <nav><a href="/evals">Evaluation dashboard</a>&nbsp;&nbsp;<a href="/traceability">Traceability dashboard</a></nav>
        </header>
        <section class="panel">
            <form id="upload" enctype="multipart/form-data">
                <label for="document">Upload statement
                    <input id="document" name="document" type="file" accept="application/pdf" required>
                </label>
                <button id="submit" type="submit">Assess PDF</button>
            </form>
        </section>
        <section id="result" class="panel" aria-live="polite" aria-busy="false"></section>
    </main>
    <script>
        const form = document.querySelector('#upload');
        const result = document.querySelector('#result');
        const submit = document.querySelector('#submit');
        const verdictLabels = {
            likely_untouched: 'Likely untouched',
            suspicious: 'Suspicious',
            inconclusive: 'Inconclusive'
        };
        const confidenceLabels = { low: 'Low confidence', medium: 'Medium confidence', high: 'High confidence' };

        function text(element, value) {
            element.textContent = value ?? 'Not available';
        }

        function addDetail(container, label, value) {
            const name = document.createElement('dt');
            const detail = document.createElement('dd');
            text(name, label);
            text(detail, value);
            container.append(name, detail);
        }

        function renderAssessment(assessment) {
            result.replaceChildren();
            result.className = 'panel';
            result.style.display = 'block';
            result.setAttribute('aria-busy', 'false');

            const header = document.createElement('div');
            header.className = 'result-header';
            const heading = document.createElement('div');
            const title = document.createElement('h2');
            text(title, 'Assessment result');
            const verdict = document.createElement('span');
            const verdictKey = assessment.verdict || 'inconclusive';
            verdict.className = `verdict ${verdictKey.replace('likely_', '')}`;
            text(verdict, verdictLabels[verdictKey] || 'Assessment unavailable');
            heading.append(title, verdict);
            const review = document.createElement('p');
            review.className = 'muted';
            text(review, assessment.review_required ? 'Human review recommended' : 'No additional review requested');
            header.append(heading, review);
            result.append(header);

            const summary = document.createElement('div');
            summary.className = 'summary';
            [['Confidence', confidenceLabels[assessment.confidence] || 'Not available'],
             ['Pages', assessment.page_count || 'Not reported'],
             ['Storage', assessment.retention_enabled ? 'Encrypted retention enabled' : 'Document not retained']]
                .forEach(([label, value]) => {
                    const stat = document.createElement('div');
                    stat.className = 'stat';
                    const statLabel = document.createElement('span');
                    statLabel.className = 'stat-label';
                    const statValue = document.createElement('span');
                    statValue.className = 'stat-value';
                    text(statLabel, label);
                    text(statValue, value);
                    stat.append(statLabel, statValue);
                    summary.append(stat);
                });
            result.append(summary);

            const rationaleHeading = document.createElement('h3');
            text(rationaleHeading, 'Assessment rationale');
            const rationale = document.createElement('p');
            rationale.className = 'rationale';
            text(rationale, assessment.rationale);
            result.append(rationaleHeading, rationale);

            const evidenceHeading = document.createElement('h3');
            text(evidenceHeading, 'Evidence');
            result.append(evidenceHeading);
            const evidenceList = document.createElement('div');
            evidenceList.className = 'evidence-list';
            if (!assessment.evidence || assessment.evidence.length === 0) {
                const empty = document.createElement('p');
                empty.className = 'muted';
                text(empty, 'No deterministic evidence was reported. Treat the result as inconclusive.');
                evidenceList.append(empty);
            } else {
                assessment.evidence.forEach((item) => {
                    const card = document.createElement('article');
                    card.className = `evidence ${item.severity || 'info'}`;
                    const cardTitle = document.createElement('div');
                    cardTitle.className = 'evidence-title';
                    const category = document.createElement('span');
                    const severity = document.createElement('span');
                    text(category, (item.category || 'Signal').replaceAll('_', ' '));
                    text(severity, item.severity || 'info');
                    cardTitle.append(category, severity);
                    const explanation = document.createElement('p');
                    text(explanation, item.explanation);
                    card.append(cardTitle, explanation);
                    evidenceList.append(card);
                });
            }
            result.append(evidenceList);

            const detailsHeading = document.createElement('h3');
            text(detailsHeading, 'Processing details');
            const details = document.createElement('dl');
            addDetail(details, 'Document fingerprint', assessment.document_sha256);
            addDetail(details, 'Assessor', assessment.assessor);
            addDetail(details, 'Model version', assessment.model_version);
            addDetail(details, 'Prompt version', assessment.prompt_version);
            addDetail(details, 'Forensic tool', assessment.forensic_tool);
            addDetail(details, 'Assessment ID', assessment.assessment_id);
            addDetail(details, 'Reviewer label', assessment.reviewer_label || 'Not reviewed');
            result.append(detailsHeading, details);

            const feedbackHeading = document.createElement('h3');
            text(feedbackHeading, 'Was this decision correct?');
            const feedback = document.createElement('div');
            feedback.className = 'feedback';
            if (assessment.reviewer_correct !== null && assessment.reviewer_correct !== undefined) {
                const thanks = document.createElement('p');
                thanks.className = 'muted';
                text(thanks, 'Thanks for your feedback');
                feedback.append(thanks);
                result.append(feedbackHeading, feedback);
                return;
            }
            const correctButton = document.createElement('button');
            const incorrectButton = document.createElement('button');
            correctButton.type = 'button';
            incorrectButton.type = 'button';
            text(correctButton, 'Correct');
            text(incorrectButton, 'Incorrect');
            correctButton.addEventListener('click', () => submitFeedback(assessment, true));
            incorrectButton.addEventListener('click', () => showCorrectionForm(assessment, feedback));
            feedback.append(correctButton, incorrectButton);
            result.append(feedbackHeading, feedback);
        }

        async function submitFeedback(assessment, correct, correctedVerdict = null, notes = '') {
            const response = await fetch(`/assessments/${assessment.assessment_id}/review`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({correct, corrected_verdict: correctedVerdict, notes})
            });
            const data = await response.json();
            if (!response.ok) { showError(data.detail); return; }
            renderAssessment(data);
        }

        function showCorrectionForm(assessment, container) {
            container.replaceChildren();
            const label = document.createElement('label');
            text(label, 'Correct verdict');
            const select = document.createElement('select');
            [['likely_untouched', 'Likely untouched'], ['suspicious', 'Suspicious'], ['inconclusive', 'Inconclusive']]
                .forEach(([value, name]) => {
                    const option = document.createElement('option');
                    option.value = value;
                    text(option, name);
                    select.append(option);
                });
            const notes = document.createElement('input');
            notes.type = 'text';
            notes.placeholder = 'Optional review note';
            const submit = document.createElement('button');
            submit.type = 'button';
            text(submit, 'Save correction');
            submit.addEventListener('click', () => submitFeedback(assessment, false, select.value, notes.value));
            label.append(select, notes, submit);
            container.append(label);
        }

        function showError(message) {
            result.replaceChildren();
            result.className = 'panel error';
            result.style.display = 'block';
            result.setAttribute('aria-busy', 'false');
            const heading = document.createElement('h2');
            text(heading, 'Assessment could not be completed');
            const detail = document.createElement('p');
            text(detail, message || 'The PDF could not be assessed.');
            result.append(heading, detail);
        }

        form.addEventListener('submit', async (event) => {
            event.preventDefault();
            result.replaceChildren();
            result.className = 'panel';
            result.style.display = 'block';
            result.setAttribute('aria-busy', 'true');
            const loading = document.createElement('p');
            loading.className = 'muted';
            text(loading, 'Assessing PDF...');
            result.append(loading);
            submit.disabled = true;
            try {
                const response = await fetch('/assessments', {method: 'POST', body: new FormData(form)});
                const data = await response.json();
                if (!response.ok) { showError(data.detail); return; }
                const assessmentResponse = await fetch(`/assessments/${data.assessment_id}`);
                const assessment = await assessmentResponse.json();
                if (!assessmentResponse.ok) { showError(assessment.detail); return; }
                renderAssessment(assessment);
            } catch (error) {
                showError('The application could not be reached. Check that the server is running and try again.');
            } finally {
                submit.disabled = false;
            }
        });
    </script>
</body>
</html>"""

    @application.get("/evals", response_class=HTMLResponse)
    def eval_dashboard() -> str:
        return _dashboard_page(
            title="Evaluation dashboard",
            subtitle="Measure whether assessor and prompt changes improve reviewed decisions.",
            body="""
<section class="metrics" id="metrics"><div class="metric"><span>Verdict accuracy</span><strong id="accuracy">-</strong></div><div class="metric"><span>Evidence coverage</span><strong id="coverage">-</strong></div><div class="metric"><span>Promotion status</span><strong id="promotion">-</strong></div><div class="metric"><span>Historical cases</span><strong id="cases">-</strong></div></section>
<section class="panel"><div class="section-heading"><div><h2>Latest evaluation</h2><p class="muted">Run the configured assessor against reviewer-labeled historical cases.</p></div><button id="run-eval">Run evaluation</button></div><div id="eval-status" class="muted">Loading evaluation history...</div><div id="reports" class="report-list"></div></section>
<section class="panel"><h2>How learning is measured</h2><p>Reviewer corrections become regression cases. Accuracy measures verdict agreement, while evidence coverage measures whether the assessor cites the signals expected by reviewers. A failed threshold blocks promotion; no model weights are changed automatically.</p></section>
<script>
const statusEl = document.querySelector('#eval-status');
const percent = value => value === null || value === undefined ? '-' : `${Math.round(value * 100)}%`;
function renderEval(data) {
  const reports = data.eval_reports || [];
  const latest = reports[0]?.report;
  document.querySelector('#accuracy').textContent = percent(latest?.accuracy);
  document.querySelector('#coverage').textContent = percent(latest?.evidence_coverage);
  document.querySelector('#promotion').textContent = latest ? (latest.promotable ? 'Promotable' : 'Blocked') : 'Not run';
  document.querySelector('#cases').textContent = latest?.total_cases ?? '0';
  statusEl.textContent = reports.length ? `Latest report: ${reports[0].model_version} / ${reports[0].prompt_version}` : 'No evaluation reports yet.';
  const list = document.querySelector('#reports'); list.replaceChildren();
  reports.forEach(item => { const article = document.createElement('article'); article.className = 'report'; const title = document.createElement('strong'); title.textContent = `${item.created_at} · ${item.assessor}`; const detail = document.createElement('span'); detail.textContent = `Accuracy ${percent(item.report.accuracy)} · Evidence ${percent(item.report.evidence_coverage)} · ${item.report.promotable ? 'Promotable' : 'Blocked'}`; article.append(title, detail); list.append(article); });
}
async function loadEvals() { const response = await fetch('/diagnostics/summary'); renderEval(await response.json()); }
document.querySelector('#run-eval').addEventListener('click', async () => { statusEl.textContent = 'Running evaluation...'; const response = await fetch('/evals/run', {method: 'POST'}); if (!response.ok) { const error = await response.json(); statusEl.textContent = error.detail || 'Evaluation failed.'; return; } await loadEvals(); });
loadEvals();
</script>""",
        )

    @application.get("/traceability", response_class=HTMLResponse)
    def traceability_dashboard() -> str:
        return _dashboard_page(
            title="Traceability dashboard",
            subtitle="Inspect every persisted decision stage and reviewer correction.",
            body="""
<section class="metrics" id="summary"><div class="metric"><span>Total runs</span><strong id="run-count">-</strong></div><div class="metric"><span>Reviewed</span><strong id="reviewed-count">-</strong></div><div class="metric"><span>Suspicious</span><strong id="suspicious-count">-</strong></div><div class="metric"><span>Inconclusive</span><strong id="inconclusive-count">-</strong></div></section>
<section class="panel"><h2>Recent assessments</h2><div id="runs" class="run-list">Loading assessment history...</div></section>
<section class="panel"><h2>Decision trail</h2><p id="trace-placeholder" class="muted">Select an assessment to inspect its trace.</p><div id="trace"></div></section>
<script>
function renderRuns(data) { document.querySelector('#run-count').textContent = data.run_count; document.querySelector('#reviewed-count').textContent = data.reviewed_count; document.querySelector('#suspicious-count').textContent = data.verdicts.suspicious; document.querySelector('#inconclusive-count').textContent = data.verdicts.inconclusive; const list = document.querySelector('#runs'); list.replaceChildren(); if (!data.recent_runs.length) { list.textContent = 'No assessments yet.'; return; } data.recent_runs.forEach(run => { const button = document.createElement('button'); button.className = 'run'; button.type = 'button'; button.textContent = `${run.id} · ${run.verdict} · ${run.model_version || run.assessor} · ${run.reviewer_label ? 'reviewed' : 'awaiting review'}`; button.addEventListener('click', () => loadTrace(run.id)); list.append(button); }); }
async function loadTrace(id) { const response = await fetch(`/assessments/${id}/trace`); const data = await response.json(); const trace = document.querySelector('#trace'); document.querySelector('#trace-placeholder').textContent = `Assessment ${id}`; trace.replaceChildren(); data.traces.forEach(event => { const row = document.createElement('article'); row.className = 'trace-event'; const name = document.createElement('strong'); name.textContent = event.name; const time = document.createElement('time'); time.textContent = event.recorded_at; const attributes = document.createElement('span'); attributes.textContent = Object.entries(event.attributes || {}).map(([key, value]) => `${key}: ${value}`).join(' · '); row.append(name, time, attributes); trace.append(row); }); }
async function loadSummary() { renderRuns(await (await fetch('/diagnostics/summary')).json()); }
loadSummary();
</script>""",
        )

    def _dashboard_page(title: str, subtitle: str, body: str) -> str:
        return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{title}</title><style>
:root {{ color-scheme: light; font-family: system-ui, sans-serif; color: #17212b; background: #eef3f5; }} * {{ box-sizing: border-box; }} body {{ margin: 0; }} main {{ width: min(1100px, calc(100% - 32px)); margin: 40px auto; }} h1 {{ margin: 0 0 8px; font-size: clamp(2rem, 5vw, 3rem); letter-spacing: -0.04em; }} h2 {{ margin-top: 0; }} .muted {{ color: #5d6b75; }} nav {{ display: flex; flex-wrap: wrap; gap: 16px; margin-top: 18px; }} nav a {{ color: #126782; font-weight: 700; }} .panel {{ background: #fff; border: 1px solid #d6e0e4; border-radius: 8px; padding: 24px; margin-top: 20px; box-shadow: 0 8px 24px #17304212; }} .metrics {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-top: 24px; }} .metric {{ background: #126782; color: #fff; border-radius: 7px; padding: 18px; }} .metric span, .metric strong {{ display: block; }} .metric span {{ opacity: .8; font-size: .8rem; text-transform: uppercase; letter-spacing: .06em; }} .metric strong {{ margin-top: 8px; font-size: 1.7rem; }} button {{ border: 0; border-radius: 5px; padding: 11px 16px; background: #126782; color: #fff; font: inherit; font-weight: 700; cursor: pointer; }} .section-heading {{ display: flex; justify-content: space-between; align-items: start; gap: 16px; }} .report-list, .run-list, #trace {{ display: grid; gap: 10px; margin-top: 18px; }} .report, .trace-event {{ display: grid; gap: 5px; padding: 14px; border: 1px solid #d6e0e4; border-radius: 5px; }} .report span, .trace-event span, .trace-event time {{ color: #5d6b75; font-size: .9rem; }} .run {{ text-align: left; background: #f3f7f8; color: #17212b; border: 1px solid #d6e0e4; }} .run:hover {{ background: #dcecef; }} @media (max-width: 700px) {{ .metrics {{ grid-template-columns: repeat(2, 1fr); }} .section-heading {{ display: block; }} .section-heading button {{ margin-top: 12px; }} }} @media (max-width: 430px) {{ .metrics {{ grid-template-columns: 1fr; }} }}
</style></head><body><main><header><h1>{title}</h1><p class="muted">{subtitle}</p><nav><a href="/">Assessment</a>&nbsp;&nbsp;<a href="/evals">Evaluation dashboard</a>&nbsp;&nbsp;<a href="/traceability">Traceability dashboard</a></nav></header>{body}</main></body></html>"""


    def _response(
        assessment_id: str,
        assessment: Assessment,
        reviewer_label: str | None = None,
        reviewer_correct: bool | None = None,
    ) -> dict[str, object]:
        result = asdict(assessment)
        result["assessment_id"] = assessment_id
        result["evidence"] = [asdict(item) for item in assessment.evidence]
        result["reviewer_label"] = reviewer_label
        result["reviewer_correct"] = reviewer_correct
        result["retention_enabled"] = artifact_store is not None
        return result


    @application.post("/assessments", status_code=status.HTTP_201_CREATED)
    async def create_assessment(document: UploadFile = File(...)) -> dict[str, str]:
        content = await document.read()
        if document.content_type != "application/pdf" or not content.startswith(b"%PDF-"):
            raise HTTPException(status_code=415, detail="Only PDF uploads are supported.")

        try:
            trace = TraceRecorder()
            assessment = AssessmentRunner(
                assessor=configured_assessor,
                inspector=PdfInspector(),
                trace=trace,
            ).assess(content)
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        assessment_id = uuid4().hex
        if artifact_store is not None:
            artifact_store.save(assessment_id, content)
        ledger.record_run(assessment_id, assessment, trace.events)
        assessments[assessment_id] = {"assessment": assessment, "reviewer_label": None}
        return {"assessment_id": assessment_id}


    @application.get("/assessments/{assessment_id}")
    def get_assessment(assessment_id: str) -> dict[str, object]:
        record = assessments.get(assessment_id)
        if record is None:
            try:
                stored = ledger.get_run(assessment_id)
            except KeyError as error:
                raise HTTPException(status_code=404, detail="Assessment not found.") from error
            if stored["deleted_at"] is not None:
                raise HTTPException(status_code=404, detail="Assessment not found.")
            return stored
        return _response(
            assessment_id,
            record["assessment"],
            record["reviewer_label"],
            record.get("reviewer_correct"),
        )

    @application.get("/assessments/{assessment_id}/trace")
    def get_trace(assessment_id: str) -> dict[str, object]:
        try:
            stored = ledger.get_run(assessment_id)
        except KeyError as error:
            raise HTTPException(status_code=404, detail="Assessment not found.") from error
        return {"assessment_id": assessment_id, "traces": stored["traces"]}


    @application.post("/assessments/{assessment_id}/review")
    def review_assessment(assessment_id: str, review: ReviewRequest) -> dict[str, object]:
        record = assessments.get(assessment_id)
        if record is None:
            try:
                stored = ledger.get_run(assessment_id)
            except KeyError as error:
                raise HTTPException(status_code=404, detail="Assessment not found.") from error
            if stored["deleted_at"] is not None:
                raise HTTPException(status_code=404, detail="Assessment not found.") from None
            label = review.corrected_verdict or review.label or stored["verdict"]
            correct = review.correct if review.correct is not None else label == stored["verdict"]
            if not correct and review.corrected_verdict is None and review.label is None:
                raise HTTPException(status_code=422, detail="An incorrect decision requires a corrected verdict.")
            ledger.set_reviewer_label(assessment_id, label, review.notes, correct=correct)
            ledger.append_trace(
                assessment_id,
                "review.completed",
                {"correct": correct, "label": label, "has_notes": bool(review.notes)},
            )
            stored["reviewer_label"] = label
            stored["reviewer_correct"] = correct
            stored["reviewer_notes"] = review.notes
            return stored
        current_verdict = record["assessment"].verdict
        label = review.corrected_verdict or review.label or current_verdict
        correct = review.correct if review.correct is not None else label == current_verdict
        if not correct and review.corrected_verdict is None and review.label is None:
            raise HTTPException(status_code=422, detail="An incorrect decision requires a corrected verdict.")
        record["reviewer_label"] = label
        record["reviewer_correct"] = correct
        try:
            ledger.set_reviewer_label(assessment_id, label, review.notes, correct=correct)
            ledger.append_trace(
                assessment_id,
                "review.completed",
                {"correct": correct, "label": label, "has_notes": bool(review.notes)},
            )
        except KeyError as error:
            raise HTTPException(status_code=404, detail="Assessment not found.") from error
        return _response(assessment_id, record["assessment"], label, correct)

    @application.get("/diagnostics/summary")
    def diagnostics_summary() -> dict[str, object]:
        runs = ledger.list_runs()
        return {
            "run_count": len(runs),
            "reviewed_count": sum(1 for run in runs if run["reviewer_label"]),
            "verdicts": {
                verdict: sum(1 for run in runs if run["verdict"] == verdict)
                for verdict in ("likely_untouched", "suspicious", "inconclusive")
            },
            "recent_runs": runs,
            "eval_reports": ledger.list_eval_reports(),
        }

    @application.post("/evals/run")
    def run_evals() -> dict[str, object]:
        cases = ledger.reviewed_eval_cases()
        if not cases:
            raise HTTPException(status_code=422, detail="At least one reviewed assessment is required.")
        historical_cases = [
            type(case)(
                id=case.id,
                evidence_bundle=case.evidence_bundle,
                expected_verdict=case.expected_verdict,
                expected_evidence_ids=case.expected_evidence_ids,
                split="holdout",
                feedback_correct=case.feedback_correct,
            )
            for case in cases
        ]
        minimum_accuracy = float(os.getenv("TAMPER_SCANNER_MIN_EVAL_ACCURACY", "0.8"))
        minimum_evidence_coverage = float(os.getenv("TAMPER_SCANNER_MIN_EVIDENCE_COVERAGE", "0.8"))
        report = run_holdout(
            historical_cases,
            configured_assessor,
            minimum_accuracy=minimum_accuracy,
            minimum_evidence_coverage=minimum_evidence_coverage,
        )
        payload = {
            "total_cases": report.total_cases,
            "accuracy": report.accuracy,
            "evidence_coverage": report.evidence_coverage,
            "promotable": report.promotable,
            "blockers": list(report.blockers),
        }
        ledger.save_eval_report(
            configured_assessor.name,
            getattr(configured_assessor, "model_version", configured_assessor.name),
            getattr(configured_assessor, "prompt_version", ""),
            payload,
        )
        return payload

    @application.delete("/assessments/{assessment_id}", status_code=status.HTTP_204_NO_CONTENT)
    def delete_assessment(assessment_id: str) -> None:
        if assessments.pop(assessment_id, None) is None:
            try:
                ledger.get_run(assessment_id)
            except KeyError as error:
                raise HTTPException(status_code=404, detail="Assessment not found.") from error
        if artifact_store is not None:
            artifact_store.delete(assessment_id)
        try:
            ledger.delete_run(assessment_id)
            ledger.append_trace(assessment_id, "assessment.deleted", {})
        except KeyError as error:
            raise HTTPException(status_code=404, detail="Assessment not found.") from error

    return application


def app_from_environment() -> FastAPI:
    data_dir = Path(os.getenv("TAMPER_SCANNER_DATA_DIR", "."))
    return create_app(
        os.getenv("TAMPER_SCANNER_ENCRYPTION_KEY"),
        artifact_root=data_dir / ".tamper-scanner-artifacts",
        ledger_path=data_dir / ".tamper-scanner-ledger.db",
    )


app = app_from_environment()


def run() -> None:
    import uvicorn

    port = int(os.getenv("TAMPER_SCANNER_PORT", "9027"))
    uvicorn.run("tamper_scanner.web:app", host="127.0.0.1", port=port, reload=False)
