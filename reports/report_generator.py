"""Generate a PDF summary from persisted authorized-scope scan data."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from html import escape
from io import BytesIO
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from database.db import (
    DB_PATH,
    get_baseline,
    get_findings,
    get_observations_by_scan,
    get_scan_history,
    initialize_database,
    list_assets,
)


def _text(value: Any) -> str:
    if value is None:
        return "—"
    if isinstance(value, (dict, list, tuple)):
        value = json.dumps(value, sort_keys=True, default=str)
    return escape(str(value)).replace("\n", "<br/>")


def generate_pdf_report(
    output_path: str | Path | None = None,
    db_path: str | Path = DB_PATH,
) -> bytes:
    """Build and return the report bytes, optionally persisting them to disk."""
    initialize_database(db_path)
    assets = list_assets(db_path)
    scans = get_scan_history(limit=50, db_path=db_path)
    successful_scans = [scan for scan in scans if scan["scan_status"] == "completed"]
    latest = successful_scans[0] if successful_scans else None
    observations = (
        get_observations_by_scan(latest["id"], db_path=db_path) if latest else []
    )
    findings = get_findings(db_path=db_path)
    baseline = get_baseline(db_path=db_path)
    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=16 * mm,
        leftMargin=16 * mm,
        topMargin=17 * mm,
        bottomMargin=17 * mm,
        title="Authorized Attack-Surface Inventory and Change Monitor",
        author="Attack Surface Monitor",
    )
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="CoverTitle",
            parent=styles["Title"],
            alignment=TA_CENTER,
            textColor=colors.HexColor("#15324b"),
            fontSize=20,
            leading=25,
            spaceAfter=12,
        )
    )
    styles.add(
        ParagraphStyle(
            name="SectionHeading",
            parent=styles["Heading2"],
            textColor=colors.HexColor("#15324b"),
            spaceBefore=12,
            spaceAfter=6,
        )
    )
    styles.add(
        ParagraphStyle(
            name="SmallCell",
            parent=styles["BodyText"],
            fontSize=7.5,
            leading=9,
        )
    )

    story = [
        Paragraph(
            "Authorized Attack-Surface Inventory and Change Monitor",
            styles["CoverTitle"],
        ),
        Paragraph(f"Generated: {_text(generated_at)}", styles["BodyText"]),
        Spacer(1, 5 * mm),
        Paragraph("Executive summary", styles["SectionHeading"]),
        Paragraph(
            _text(
                f"{len(assets)} configured assets; {len(successful_scans)} successful "
                f"scans in the latest 50 records; "
                f"{sum(f['is_active'] and f['review_status'] != 'FALSE_POSITIVE' for f in findings)} "
                "current unresolved findings. Changes and potential issues are evidence "
                "for review, not automatic vulnerability claims."
            ),
            styles["BodyText"],
        ),
        Paragraph("Scope and authorized assets", styles["SectionHeading"]),
    ]
    story.append(
        _table(
            [["Type", "Configured asset", "Authorized"]]
            + [
                [
                    asset["asset_type"],
                    asset["asset_value"],
                    "Yes" if asset["is_authorized"] else "No",
                ]
                for asset in assets
            ],
            styles,
        )
    )
    story.extend(
        [
            Paragraph("Scan methodology and limitations", styles["SectionHeading"]),
            Paragraph(
                "The application queries DNS for configured names, validates TLS "
                "certificates using the platform trust store, and connects only to "
                "individual TCP ports explicitly listed in the configuration. It "
                "does not discover arbitrary addresses, probe unconfigured ports, "
                "exploit services, or verify ownership of third-party resources. "
                "Timeouts and scanner errors are inconclusive and are not treated as "
                "proof that a record or service was removed.",
                styles["BodyText"],
            ),
            Paragraph("Latest successful scan", styles["SectionHeading"]),
            Paragraph(
                _text(
                    latest
                    and f"Scan {latest['id']} — {latest['scan_timestamp']} "
                    f"({latest['scan_status']})"
                    or "No successful scan is available."
                ),
                styles["BodyText"],
            ),
            Paragraph("Active baseline", styles["SectionHeading"]),
            Paragraph(
                _text(
                    baseline
                    and f"Baseline {baseline['id']} — scan {baseline['scan_id']} "
                    f"({baseline['created_at']})"
                    or "No active baseline has been established."
                ),
                styles["BodyText"],
            ),
        ]
    )

    for scanner_type, title in (
        ("DNS", "DNS inventory"),
        ("TLS", "TLS certificate results"),
        ("PORT", "Port monitoring results"),
    ):
        rows = [row for row in observations if row["scanner_type"] == scanner_type]
        story.append(Paragraph(title, styles["SectionHeading"]))
        if rows:
            data = [["Asset", "Check", "Observed value", "Details"]]
            data.extend(
                [
                    row["asset_value"],
                    row["observation_type"],
                    row["observation_value"],
                    row["details"],
                ]
                for row in rows
            )
            story.append(_table(data, styles, widths=[34 * mm, 27 * mm, 55 * mm, 55 * mm]))
        else:
            story.append(Paragraph("No observations recorded.", styles["BodyText"]))

    story.append(Paragraph("Findings and review status", styles["SectionHeading"]))
    if findings:
        data = [[
            "Asset", "Category", "Severity", "Status", "Evidence / recommendation"
        ]]
        data.extend(
            [
                finding["asset_value"],
                finding["category"],
                finding["severity"],
                finding["review_status"],
                f"{finding['evidence']} Recommendation: {finding['recommended_action']}",
            ]
            for finding in findings
        )
        story.append(
            _table(
                data,
                styles,
                widths=[27 * mm, 30 * mm, 18 * mm, 24 * mm, 72 * mm],
            )
        )
    else:
        story.append(Paragraph("No findings are recorded.", styles["BodyText"]))

    story.append(Paragraph("Scan history", styles["SectionHeading"]))
    if scans:
        story.append(
            _table(
                [["ID", "Source", "Timestamp", "Status", "Assets", "Findings", "Error"]]
                + [
                    [
                        scan["id"],
                        scan.get("scan_source", "manual"),
                        scan["scan_timestamp"],
                        scan["scan_status"],
                        scan["assets_scanned"],
                        scan["findings_count"],
                        scan["error_message"] or "",
                    ]
                    for scan in scans
                ],
                styles,
            )
        )
    else:
        story.append(Paragraph("No scans are recorded.", styles["BodyText"]))
    story.extend(
        [
            Paragraph("Conclusion", styles["SectionHeading"]),
            Paragraph(
                "This report reflects only the configured authorized scope and the "
                "results persisted at generation time. Confirm changes with asset "
                "owners before taking action.",
                styles["BodyText"],
            ),
        ]
    )
    document.build(story)
    report_bytes = buffer.getvalue()
    if output_path is not None:
        destination = Path(output_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(report_bytes)
    return report_bytes


def _table(
    rows: list[list[Any]],
    styles: Any,
    widths: list[float] | None = None,
) -> Table:
    formatted = [
        [Paragraph(_text(cell), styles["SmallCell"]) for cell in row]
        for row in rows
    ]
    table = Table(formatted, colWidths=widths, repeatRows=1, hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#15324b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#cbd5df")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2f6f9")]),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table
