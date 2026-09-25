from io import BytesIO

from pypdf import PdfWriter
from pypdf.generic import DecodedStreamObject, DictionaryObject, NameObject

from tamper_scanner.forensics import PdfInspector


def synthetic_pdf() -> bytes:
    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    writer.add_metadata({"/Producer": "Synthetic Test Bank", "/Creator": "Test Fixture"})
    output = BytesIO()
    writer.write(output)
    return output.getvalue()


def pdf_with_statement_text() -> bytes:
    writer = PdfWriter()
    page = writer.add_blank_page(width=612, height=792)
    page[NameObject("/Resources")] = DictionaryObject(
        {
            NameObject("/Font"): DictionaryObject(
                {NameObject("/F1"): DictionaryObject({NameObject("/Type"): NameObject("/Font"), NameObject("/Subtype"): NameObject("/Type1"), NameObject("/BaseFont"): NameObject("/Helvetica")})},
            ),
        },
    )
    stream = DecodedStreamObject()
    stream.set_data(
        b"BT /F1 10 Tf 40 740 Td (Opening Balance 22,24,087.56) Tj 0 -20 Td (08/09/2026 Deposit 2,627.00 25,01,399.86) Tj 0 -20 Td (Closing Balance 22,01,399.86) Tj ET"
    )
    page[NameObject("/Contents")] = stream
    output = BytesIO()
    writer.write(output)
    return output.getvalue()


def test_inspector_returns_structured_pdf_signals() -> None:
    report = PdfInspector().inspect(synthetic_pdf())

    assert report.page_count == 1
    assert report.metadata["producer"] == "Synthetic Test Bank"
    assert report.metadata["creator"] == "Test Fixture"
    assert report.tool == "pypdf"
    assert any(signal.category == "text_layer" for signal in report.signals)


def test_inspector_flags_latest_balance_mismatch() -> None:
    report = PdfInspector().inspect(pdf_with_statement_text())

    mismatch = [signal for signal in report.signals if signal.category == "balance_consistency"]

    assert len(mismatch) == 1
    assert mismatch[0].severity == "critical"


def test_inspector_chooses_latest_transaction_by_date() -> None:
    report = PdfInspector().inspect(
        pdf_with_statement_text().replace(
            b"08/09/2026 Deposit 2,627.00 25,01,399.86",
            b"08/09/2026 Deposit 2,627.00 22,01,399.86",
        )
    )

    assert not [signal for signal in report.signals if signal.category == "balance_consistency"]


def test_inspector_ignores_page_header_numbers() -> None:
    report = PdfInspector().inspect(
        pdf_with_statement_text().replace(
            b"Opening Balance 22,24,087.56",
            b"15/09/2026 12:15 am 1 Page 1 of 3\nOpening Balance 22,24,087.56",
        )
    )

    mismatch = [signal for signal in report.signals if signal.category == "balance_consistency"]

    assert len(mismatch) == 1
    assert "25,01,399.86" in mismatch[0].explanation
