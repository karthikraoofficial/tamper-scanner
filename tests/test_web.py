from io import BytesIO

from fastapi.testclient import TestClient
from pypdf import PdfWriter

from tamper_scanner.web import app, app_from_environment, create_app


client = TestClient(app)


def pdf_bytes() -> bytes:
    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    output = BytesIO()
    writer.write(output)
    return output.getvalue()


def test_home_page_exposes_upload_workflow() -> None:
    response = client.get("/")

    assert response.status_code == 200
    assert "Upload statement" in response.text
    assert "multipart/form-data" in response.text
    assert "Assessment result" in response.text
    assert "Likely untouched" in response.text
    assert "Evaluation dashboard</a>&nbsp;&nbsp;<a href=\"/traceability\">Traceability dashboard" in response.text
    assert "JSON.stringify(await assessment.json()" not in response.text
    assert "Evidence" in response.text
    assert "Thanks for your feedback" in response.text


def test_eval_dashboard_exposes_eval_metrics_and_run_action() -> None:
    response = client.get("/evals")

    assert response.status_code == 200
    assert "Evaluation dashboard" in response.text
    assert "Verdict accuracy" in response.text
    assert "Evidence coverage" in response.text
    assert "Run evaluation" in response.text


def test_traceability_dashboard_exposes_run_history_and_trace_view() -> None:
    response = client.get("/traceability")

    assert response.status_code == 200
    assert "Traceability dashboard" in response.text
    assert "Decision trail" in response.text
    assert "Recent assessments" in response.text


def test_upload_and_retrieve_assessment() -> None:
    response = client.post(
        "/assessments",
        files={"document": ("statement.pdf", pdf_bytes(), "application/pdf")},
    )

    assert response.status_code == 201
    assessment_id = response.json()["assessment_id"]

    result = client.get(f"/assessments/{assessment_id}")

    assert result.status_code == 200
    assert result.json()["verdict"] == "inconclusive"
    assert result.json()["review_required"] is True
    assert "document" not in result.json()


def test_assessment_trace_is_persisted_and_visible(tmp_path) -> None:
    configured_client = TestClient(create_app(artifact_root=tmp_path / "artifacts", ledger_path=tmp_path / "ledger.db"))
    created = configured_client.post(
        "/assessments",
        files={"document": ("statement.pdf", pdf_bytes(), "application/pdf")},
    )
    assessment_id = created.json()["assessment_id"]

    trace = configured_client.get(f"/assessments/{assessment_id}/trace")

    assert trace.status_code == 200
    assert [event["name"] for event in trace.json()["traces"]] == [
        "forensics.started",
        "forensics.completed",
        "assessor.started",
        "assessor.completed",
        "assessment.completed",
    ]


def test_reviewer_feedback_is_available_to_eval_workflow(tmp_path) -> None:
    configured_client = TestClient(create_app(artifact_root=tmp_path / "artifacts", ledger_path=tmp_path / "ledger.db"))
    created = configured_client.post(
        "/assessments",
        files={"document": ("statement.pdf", pdf_bytes(), "application/pdf")},
    )
    assessment_id = created.json()["assessment_id"]
    configured_client.post(
        f"/assessments/{assessment_id}/review",
        json={"label": "suspicious", "notes": "Confirmed by reviewer"},
    )

    evaluation = configured_client.post("/evals/run")

    assert evaluation.status_code == 200
    assert evaluation.json()["total_cases"] == 1


def test_data_directory_is_configurable_from_environment(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("TAMPER_SCANNER_DATA_DIR", str(tmp_path / "data"))
    configured_client = TestClient(app_from_environment())

    created = configured_client.post(
        "/assessments",
        files={"document": ("statement.pdf", pdf_bytes(), "application/pdf")},
    )

    assert created.status_code == 201
    assert (tmp_path / "data" / ".tamper-scanner-ledger.db").exists()


def test_persisted_run_can_be_reviewed_after_app_restart(tmp_path) -> None:
    ledger_path = tmp_path / "ledger.db"
    first_client = TestClient(create_app(ledger_path=ledger_path))
    created = first_client.post(
        "/assessments",
        files={"document": ("statement.pdf", pdf_bytes(), "application/pdf")},
    )
    assessment_id = created.json()["assessment_id"]

    restarted_client = TestClient(create_app(ledger_path=ledger_path))
    response = restarted_client.post(
        f"/assessments/{assessment_id}/review",
        json={"label": "likely_untouched", "notes": "Reviewed after restart"},
    )

    assert response.status_code == 200
    assert response.json()["reviewer_label"] == "likely_untouched"


def test_diagnostics_exposes_run_summary(tmp_path) -> None:
    configured_client = TestClient(create_app(artifact_root=tmp_path / "artifacts", ledger_path=tmp_path / "ledger.db"))

    response = configured_client.get("/diagnostics/summary")

    assert response.status_code == 200
    assert response.json()["run_count"] == 0


def test_reviewer_can_label_an_assessment() -> None:
    created = client.post(
        "/assessments",
        files={"document": ("statement.pdf", pdf_bytes(), "application/pdf")},
    )
    assessment_id = created.json()["assessment_id"]

    response = client.post(
        f"/assessments/{assessment_id}/review",
        json={"correct": False, "corrected_verdict": "suspicious", "notes": "Balance mismatch confirmed"},
    )

    assert response.status_code == 200
    assert response.json()["reviewer_label"] == "suspicious"
    assert response.json()["reviewer_correct"] is False


def test_reviewer_can_mark_decision_correct() -> None:
    created = client.post(
        "/assessments",
        files={"document": ("statement.pdf", pdf_bytes(), "application/pdf")},
    )
    assessment_id = created.json()["assessment_id"]

    response = client.post(
        f"/assessments/{assessment_id}/review",
        json={"correct": True},
    )

    assert response.status_code == 200
    assert response.json()["reviewer_correct"] is True


def test_incorrect_feedback_requires_corrected_verdict(tmp_path) -> None:
    configured_client = TestClient(create_app(ledger_path=tmp_path / "ledger.db"))
    created = configured_client.post(
        "/assessments",
        files={"document": ("statement.pdf", pdf_bytes(), "application/pdf")},
    )

    response = configured_client.post(
        f"/assessments/{created.json()['assessment_id']}/review",
        json={"correct": False},
    )

    assert response.status_code == 422


def test_assessment_can_be_deleted() -> None:
    created = client.post(
        "/assessments",
        files={"document": ("statement.pdf", pdf_bytes(), "application/pdf")},
    )
    assessment_id = created.json()["assessment_id"]

    response = client.delete(f"/assessments/{assessment_id}")

    assert response.status_code == 204
    assert client.get(f"/assessments/{assessment_id}").status_code == 404


def test_configured_app_encrypts_uploaded_artifact_and_deletes_it(tmp_path) -> None:
    configured_client = TestClient(create_app("retention-key", tmp_path))

    created = configured_client.post(
        "/assessments",
        files={"document": ("statement.pdf", pdf_bytes(), "application/pdf")},
    )
    assessment_id = created.json()["assessment_id"]

    assert configured_client.get(f"/assessments/{assessment_id}").json()["retention_enabled"] is True
    encrypted_file = tmp_path / f"{assessment_id}.bin"
    assert encrypted_file.exists()
    assert b"%PDF-" not in encrypted_file.read_bytes()

    assert configured_client.delete(f"/assessments/{assessment_id}").status_code == 204
    assert not encrypted_file.exists()


def test_upload_rejects_non_pdf_content() -> None:
    response = client.post(
        "/assessments",
        files={"document": ("notes.txt", b"not a pdf", "text/plain")},
    )

    assert response.status_code == 415
