"""Deterministic observations extracted from PDF structure."""

from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
import re
from datetime import datetime

from pypdf import PdfReader
from pypdf.errors import PdfReadError

from .assessment import Evidence


@dataclass(frozen=True)
class ForensicReport:
    page_count: int
    metadata: dict[str, str | None]
    signals: tuple[Evidence, ...]
    tool: str


class PdfInspector:
    """Inspect a PDF and return bounded observations without deciding authenticity."""

    tool = "pypdf"

    def inspect(self, document: bytes) -> ForensicReport:
        try:
            reader = PdfReader(BytesIO(document), strict=False)
        except (PdfReadError, ValueError, OSError) as error:
            raise ValueError("The uploaded document could not be parsed as a PDF.") from error

        if reader.is_encrypted:
            return ForensicReport(
                page_count=0,
                metadata={"producer": None, "creator": None, "creation_date": None, "modification_date": None},
                signals=(
                    Evidence(
                        id="encrypted-document",
                        category="encrypted_document",
                        severity="warning",
                        explanation="The PDF is encrypted and could not be inspected without a password.",
                    ),
                ),
                tool=self.tool,
            )

        metadata = reader.metadata or {}
        normalized_metadata = {
            "producer": _metadata_value(metadata, "/Producer"),
            "creator": _metadata_value(metadata, "/Creator"),
            "creation_date": _metadata_value(metadata, "/CreationDate"),
            "modification_date": _metadata_value(metadata, "/ModDate"),
        }
        signals: list[Evidence] = []
        text_pages = 0
        page_texts: list[str] = []
        for page_number, page in enumerate(reader.pages, start=1):
            page_text = page.extract_text()
            page_texts.append(page_text)
            if page_text.strip():
                text_pages += 1
            else:
                signals.append(
                    Evidence(
                        id=f"page-{page_number}-no-text-layer",
                        category="text_layer",
                        severity="info",
                        explanation=f"Page {page_number} has no extractable text layer; it may be image-only.",
                    ),
                )

        if text_pages == len(reader.pages) and reader.pages:
            signals.append(
                Evidence(
                    id="text-layer-present",
                    category="text_layer",
                    severity="info",
                    explanation="Every page contains extractable text.",
                ),
            )

        signals.extend(_balance_consistency_signals("\n".join(page_texts)))

        return ForensicReport(
            page_count=len(reader.pages),
            metadata=normalized_metadata,
            signals=tuple(signals),
            tool=self.tool,
        )


def _metadata_value(metadata: object, key: str) -> str | None:
    value = metadata.get(key) if hasattr(metadata, "get") else None
    return str(value) if value is not None else None


_AMOUNT = r"(?:\d{1,3}(?:,\d{2})*,\d{3}|\d{1,3}(?:,\d{3})+|\d+)(?:\.\d{2})?"


def _amount(value: str) -> float:
    return float(value.replace(",", ""))


def _balance_consistency_signals(text: str) -> list[Evidence]:
    closing_match = re.search(r"Closing\s+Balance\s*(?:₹\s*)?([\d,]+\.\d{2})", text, re.IGNORECASE)
    if not closing_match:
        return []

    closing_value = _amount(closing_match.group(1))
    transaction_balances: list[tuple[datetime, str]] = []
    for line in text.splitlines():
        date_match = re.match(r"\s*(\d{2}/\d{2}/\d{4})", line)
        if date_match and "Closing Balance" not in line and "page" not in line.lower():
            matches = re.findall(_AMOUNT, line)
            decimal_matches = [match for match in matches if "." in match]
            if len(decimal_matches) >= 2:
                transaction_balances.append(
                    (datetime.strptime(date_match.group(1), "%d/%m/%Y"), decimal_matches[-1])
                )
    if not transaction_balances:
        return []

    _, latest_balance = max(transaction_balances, key=lambda item: item[0])
    latest_value = _amount(latest_balance)
    if latest_value == closing_value:
        return []

    return [
        Evidence(
            id="latest-balance-mismatch",
            category="balance_consistency",
            severity="critical",
            explanation=(
                "The latest transaction balance does not match the statement closing balance: "
                f"latest transaction shows {latest_balance}, while closing balance shows "
                f"{closing_match.group(1)}."
            ),
        ),
    ]
