"""SQLite ledger for auditable assessment runs and historical eval cases."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .assessment import Assessment
from .harness import EvalCase


class AssessmentLedger:
    """Persist the decision trail without retaining source documents or raw model payloads."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS runs (
                    id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    document_sha256 TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    confidence TEXT NOT NULL,
                    rationale TEXT NOT NULL,
                    assessor TEXT NOT NULL,
                    model_version TEXT NOT NULL,
                    prompt_version TEXT NOT NULL,
                    forensic_tool TEXT NOT NULL,
                    page_count INTEGER NOT NULL,
                    review_required INTEGER NOT NULL,
                    evidence_json TEXT NOT NULL,
                    reviewer_label TEXT,
                    reviewer_notes TEXT,
                    reviewer_correct INTEGER,
                    corrected_verdict TEXT,
                    deleted_at TEXT
                );
                CREATE TABLE IF NOT EXISTS traces (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    recorded_at TEXT NOT NULL,
                    name TEXT NOT NULL,
                    attributes_json TEXT NOT NULL,
                    FOREIGN KEY(run_id) REFERENCES runs(id)
                );
                CREATE TABLE IF NOT EXISTS eval_reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    assessor TEXT NOT NULL,
                    model_version TEXT NOT NULL,
                    prompt_version TEXT NOT NULL,
                    report_json TEXT NOT NULL
                );
                """
            )
            columns = {row[1] for row in connection.execute("PRAGMA table_info(runs)")}
            for column in ("deleted_at", "reviewer_correct", "corrected_verdict"):
                if column not in columns:
                    connection.execute(f"ALTER TABLE runs ADD COLUMN {column} TEXT")

    def record_run(self, run_id: str, assessment: Assessment, traces: list[dict[str, object]]) -> None:
        now = _now()
        evidence = [
            {
                "id": item.id,
                "category": item.category,
                "severity": item.severity,
                "explanation": item.explanation,
            }
            for item in assessment.evidence
        ]
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO runs
                (id, created_at, document_sha256, verdict, confidence, rationale,
                 assessor, model_version, prompt_version, forensic_tool, page_count,
                 review_required, evidence_json, reviewer_label, reviewer_notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)
                """,
                (
                    run_id,
                    now,
                    assessment.document_sha256,
                    assessment.verdict,
                    assessment.confidence,
                    assessment.rationale,
                    assessment.assessor,
                    assessment.model_version,
                    assessment.prompt_version,
                    assessment.forensic_tool,
                    assessment.page_count,
                    int(assessment.review_required),
                    json.dumps(evidence, sort_keys=True),
                ),
            )
            connection.execute("DELETE FROM traces WHERE run_id = ?", (run_id,))
            connection.executemany(
                "INSERT INTO traces (run_id, recorded_at, name, attributes_json) VALUES (?, ?, ?, ?)",
                [
                    (run_id, now, event["name"], json.dumps(event["attributes"], sort_keys=True))
                    for event in traces
                ],
            )

    def set_reviewer_label(
        self,
        run_id: str,
        label: str,
        notes: str = "",
        *,
        correct: bool | None = None,
    ) -> None:
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE runs SET reviewer_label = ?, reviewer_notes = ?, reviewer_correct = ?, corrected_verdict = ? WHERE id = ?",
                (label, notes, None if correct is None else int(correct), label if correct is False else None, run_id),
            )
            if cursor.rowcount == 0:
                raise KeyError(run_id)

    def append_trace(self, run_id: str, name: str, attributes: dict[str, object]) -> None:
        with self._connect() as connection:
            exists = connection.execute("SELECT 1 FROM runs WHERE id = ?", (run_id,)).fetchone()
            if exists is None:
                raise KeyError(run_id)
            connection.execute(
                "INSERT INTO traces (run_id, recorded_at, name, attributes_json) VALUES (?, ?, ?, ?)",
                (run_id, _now(), name, json.dumps(attributes, sort_keys=True)),
            )

    def get_run(self, run_id: str) -> dict[str, object]:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
            if row is None:
                raise KeyError(run_id)
            traces = connection.execute(
                "SELECT recorded_at, name, attributes_json FROM traces WHERE run_id = ? ORDER BY id",
                (run_id,),
            ).fetchall()
        result = dict(row)
        result["evidence"] = json.loads(result.pop("evidence_json"))
        result["review_required"] = bool(result["review_required"])
        if result["reviewer_correct"] is not None:
            result["reviewer_correct"] = bool(int(result["reviewer_correct"]))
        result["traces"] = [
            {"recorded_at": item[0], "name": item[1], "attributes": json.loads(item[2])}
            for item in traces
        ]
        return result

    def delete_run(self, run_id: str) -> None:
        with self._connect() as connection:
            cursor = connection.execute("UPDATE runs SET deleted_at = ? WHERE id = ?", (_now(), run_id))
            if cursor.rowcount == 0:
                raise KeyError(run_id)

    def reviewed_eval_cases(self) -> list[EvalCase]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT id, evidence_json, reviewer_label, reviewer_correct, corrected_verdict FROM runs WHERE reviewer_label IS NOT NULL ORDER BY created_at"
            ).fetchall()
        return [
            EvalCase(
                id=row[0],
                evidence_bundle={"evidence": json.loads(row[1])},
                expected_verdict=row[4] or row[2],
                expected_evidence_ids={item["id"] for item in json.loads(row[1])},
                split="historical",
                feedback_correct=None if row[3] is None else bool(int(row[3])),
            )
            for row in rows
        ]

    def save_eval_report(self, assessor: str, model_version: str, prompt_version: str, report: object) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO eval_reports (created_at, assessor, model_version, prompt_version, report_json) VALUES (?, ?, ?, ?, ?)",
                (_now(), assessor, model_version, prompt_version, json.dumps(report, sort_keys=True)),
            )

    def list_runs(self, limit: int = 50) -> list[dict[str, object]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT id, created_at, document_sha256, verdict, confidence, assessor, model_version, prompt_version, reviewer_label FROM runs WHERE deleted_at IS NULL ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def list_eval_reports(self, limit: int = 20) -> list[dict[str, object]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT id, created_at, assessor, model_version, prompt_version, report_json FROM eval_reports ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            {
                "id": row[0],
                "created_at": row[1],
                "assessor": row[2],
                "model_version": row[3],
                "prompt_version": row[4],
                "report": json.loads(row[5]),
            }
            for row in rows
        ]

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path)
        connection.row_factory = sqlite3.Row
        return connection


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
