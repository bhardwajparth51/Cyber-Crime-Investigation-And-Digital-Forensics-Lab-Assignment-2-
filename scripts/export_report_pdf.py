"""Export reports/final-investigation-report.md to a formatted PDF document."""

from __future__ import annotations

import argparse
import html
import re
from pathlib import Path

from PIL import Image as PILImage
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    Image,
    KeepTogether,
    PageBreak,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = ROOT_DIR / "reports" / "final-investigation-report.md"
DEFAULT_OUTPUT = ROOT_DIR / "reports" / "final-investigation-report.pdf"

IMAGE_RE = re.compile(r"^!\[([^\]]*)\]\(([^)]+)\)$")
INLINE_TOKEN_RE = re.compile(
    r"(\*\*[^*]+\*\*|\*[^*]+\*|`[^`]+`|\[[^\]]+\]\([^)]+\)|https?://[^\s<>)]+)"
)
NUMBERED_RE = re.compile(r"^(\d+)\.\s+(.*)$")

FONT_DIR = Path("/usr/share/fonts/truetype/dejavu")


def _register_fonts() -> tuple[str, str]:
    """Register Unicode-capable DejaVu Sans and DejaVu Sans Mono fonts when present."""
    sans_regular = FONT_DIR / "DejaVuSans.ttf"
    sans_bold = FONT_DIR / "DejaVuSans-Bold.ttf"
    sans_italic = FONT_DIR / "DejaVuSans-Oblique.ttf"
    sans_bold_italic = FONT_DIR / "DejaVuSans-BoldOblique.ttf"
    mono_regular = FONT_DIR / "DejaVuSansMono.ttf"

    if sans_regular.is_file() and sans_bold.is_file():
        pdfmetrics.registerFont(TTFont("ReportSans", str(sans_regular)))
        pdfmetrics.registerFont(TTFont("ReportSans-Bold", str(sans_bold)))
        pdfmetrics.registerFont(
            TTFont("ReportSans-Italic", str(sans_italic if sans_italic.is_file() else sans_regular))
        )
        pdfmetrics.registerFont(
            TTFont(
                "ReportSans-BoldItalic",
                str(sans_bold_italic if sans_bold_italic.is_file() else sans_bold),
            )
        )
        pdfmetrics.registerFontFamily(
            "ReportSans",
            normal="ReportSans",
            bold="ReportSans-Bold",
            italic="ReportSans-Italic",
            boldItalic="ReportSans-BoldItalic",
        )
        body_font = "ReportSans"
    else:
        body_font = "Helvetica"

    if mono_regular.is_file():
        pdfmetrics.registerFont(TTFont("ReportMono", str(mono_regular)))
        mono_font = "ReportMono"
    else:
        mono_font = "Courier"

    return body_font, mono_font


def _md_inline_to_xml(
    text: str,
    mono_font: str,
    *,
    link_color: str = "#1D4ED8",
    code_color: str = "#1E3A8A",
) -> str:
    """Convert Markdown inline formatting into ReportLab Paragraph XML markup."""
    parts: list[str] = []
    pos = 0
    for match in INLINE_TOKEN_RE.finditer(text):
        if match.start() > pos:
            parts.append(html.escape(text[pos : match.start()]))
        token = match.group(0)
        if token.startswith("**") and token.endswith("**"):
            inner = _md_inline_to_xml(
                token[2:-2], mono_font, link_color=link_color, code_color=code_color
            )
            parts.append(f"<b>{inner}</b>")
        elif token.startswith("*") and token.endswith("*"):
            inner = _md_inline_to_xml(
                token[1:-1], mono_font, link_color=link_color, code_color=code_color
            )
            parts.append(f"<i>{inner}</i>")
        elif token.startswith("`") and token.endswith("`"):
            code_txt = html.escape(token[1:-1])
            parts.append(f'<font name="{mono_font}" color="{code_color}">{code_txt}</font>')
        elif token.startswith("["):
            label, _, target = token[1:-1].partition("](")
            safe_label = html.escape(label)
            if target.startswith("http"):
                safe_url = html.escape(target, quote=True)
                parts.append(f'<a href="{safe_url}" color="{link_color}"><u>{safe_label}</u></a>')
                if label != target and not label.startswith("http"):
                    parts.append(f' <font color="#64748B">({html.escape(target)})</font>')
            else:
                parts.append(f'<font color="{link_color}">{safe_label}</font>')
        elif token.startswith("http"):
            safe_url = html.escape(token, quote=True)
            parts.append(f'<a href="{safe_url}" color="{link_color}"><u>{html.escape(token)}</u></a>')
        pos = match.end()

    if pos < len(text):
        parts.append(html.escape(text[pos:]))
    return "".join(parts)


class _NumberedCanvas:
    """Draw page header/footer with Page X of Y numbering."""

    def __init__(self, body_font: str) -> None:
        self.body_font = body_font

    def make_canvas_class(self):
        from reportlab.pdfgen import canvas as rl_canvas

        body_font = self.body_font

        class FooterCanvas(rl_canvas.Canvas):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self._saved_page_states: list[dict] = []

            def showPage(self):
                self._saved_page_states.append(dict(self.__dict__))
                self._startPage()

            def save(self):
                total_pages = len(self._saved_page_states)
                for state in self._saved_page_states:
                    self.__dict__.update(state)
                    self._draw_footer(total_pages)
                    super().showPage()
                super().save()

            def _draw_footer(self, total_pages: int) -> None:
                self.saveState()
                self.setFont(body_font, 8)
                self.setFillColor(colors.HexColor("#64748B"))
                page_width = self._pagesize[0]
                self.drawRightString(
                    page_width - 0.75 * inch,
                    0.45 * inch,
                    f"Operation Hydra (INC-2026-HYDRA-01) — Synthetic Academic Investigation  |  Page {self._pageNumber} of {total_pages}",
                )
                self.restoreState()

        return FooterCanvas


def _render_table(
    table_lines: list[str],
    avail_width: float,
    header_style: ParagraphStyle,
    cell_style: ParagraphStyle,
    mono_font: str,
) -> Table | None:
    rows: list[list[str]] = []
    for idx, line in enumerate(table_lines):
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if idx == 1 and all(set(c) <= {"-", ":"} for c in cells if c):
            continue
        rows.append(cells)

    if not rows:
        return None

    num_cols = len(rows[0])
    col_widths = [avail_width / num_cols] * num_cols
    if num_cols == 6:
        col_widths = [
            avail_width * 0.105,
            avail_width * 0.205,
            avail_width * 0.21,
            avail_width * 0.175,
            avail_width * 0.115,
            avail_width * 0.19,
        ]
    elif num_cols == 4 and "Amount" in rows[0][1]:
        col_widths = [
            avail_width * 0.26,
            avail_width * 0.14,
            avail_width * 0.16,
            avail_width * 0.44,
        ]
    elif num_cols == 4:
        col_widths = [
            avail_width * 0.18,
            avail_width * 0.22,
            avail_width * 0.24,
            avail_width * 0.36,
        ]

    flow_rows: list[list[Paragraph]] = []
    for r_idx, row_vals in enumerate(rows):
        row_cells: list[Paragraph] = []
        for c_idx in range(num_cols):
            val = row_vals[c_idx] if c_idx < len(row_vals) else ""
            if r_idx == 0:
                xml_txt = _md_inline_to_xml(
                    val, mono_font, link_color="#FFFFFF", code_color="#FFFFFF"
                )
                row_cells.append(Paragraph(f"<b>{xml_txt}</b>", header_style))
            else:
                xml_txt = _md_inline_to_xml(val, mono_font)
                row_cells.append(Paragraph(xml_txt, cell_style))
        flow_rows.append(row_cells)

    tbl = Table(flow_rows, colWidths=col_widths, repeatRows=1)
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E3A8A")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4.5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4.5),
        ("TOPPADDING", (0, 0), (-1, -1), 4.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4.5),
        ("LINEABOVE", (0, 0), (-1, 0), 0.75, colors.HexColor("#CBD5E1")),
        ("LINEBELOW", (0, -1), (-1, -1), 0.75, colors.HexColor("#CBD5E1")),
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, colors.HexColor("#E2E8F0")),
    ]
    for r_idx in range(1, len(flow_rows)):
        if r_idx % 2 == 0:
            style_cmds.append(("BACKGROUND", (0, r_idx), (-1, r_idx), colors.HexColor("#F8FAFC")))
    tbl.setStyle(TableStyle(style_cmds))
    return tbl


def export_markdown_to_pdf(md_path: Path, pdf_path: Path) -> Path:
    """Convert the Markdown final investigation report into a styled PDF file."""
    body_font, mono_font = _register_fonts()
    pdf_path.parent.mkdir(parents=True, exist_ok=True)

    margin_x = 0.75 * inch
    margin_y = 0.72 * inch
    page_w, _ = letter
    avail_w = page_w - 2 * margin_x

    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=letter,
        leftMargin=margin_x,
        rightMargin=margin_x,
        topMargin=margin_y,
        bottomMargin=0.78 * inch,
        title="Operation Hydra — Final Digital Forensics & Legal-Technical Investigation Report",
        author="Parth Bhardwaj",
    )

    base = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "HydraTitle",
        parent=base["Title"],
        fontName=f"{body_font}-Bold" if body_font == "ReportSans" else "Helvetica-Bold",
        fontSize=17,
        leading=21,
        textColor=colors.HexColor("#0F172A"),
        spaceAfter=10,
    )
    h1_style = ParagraphStyle(
        "HydraH1",
        parent=base["Heading1"],
        fontName=f"{body_font}-Bold" if body_font == "ReportSans" else "Helvetica-Bold",
        fontSize=12.5,
        leading=16,
        textColor=colors.HexColor("#1E3A8A"),
        spaceBefore=10,
        spaceAfter=4,
        keepWithNext=True,
    )
    h2_style = ParagraphStyle(
        "HydraH2",
        parent=base["Heading2"],
        fontName=f"{body_font}-Bold" if body_font == "ReportSans" else "Helvetica-Bold",
        fontSize=10.8,
        leading=14,
        textColor=colors.HexColor("#334155"),
        spaceBefore=8,
        spaceAfter=3.5,
        keepWithNext=True,
    )
    body_style = ParagraphStyle(
        "HydraBody",
        parent=base["Normal"],
        fontName=body_font,
        fontSize=9.4,
        leading=13,
        textColor=colors.HexColor("#1E293B"),
        spaceAfter=4.5,
    )
    list_style = ParagraphStyle(
        "HydraList",
        parent=body_style,
        leftIndent=16,
        firstLineIndent=-10,
        spaceAfter=2.5,
    )
    caption_style = ParagraphStyle(
        "HydraCaption",
        parent=body_style,
        fontName=f"{body_font}-Italic" if body_font == "ReportSans" else "Helvetica-Oblique",
        fontSize=8.5,
        leading=11.5,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#475569"),
        spaceBefore=3,
        spaceAfter=7,
    )
    tbl_header_style = ParagraphStyle(
        "HydraTableHeader",
        parent=body_style,
        fontName=f"{body_font}-Bold" if body_font == "ReportSans" else "Helvetica-Bold",
        fontSize=8.0,
        leading=10.2,
        textColor=colors.white,
        spaceAfter=0,
    )
    tbl_cell_style = ParagraphStyle(
        "HydraTableCell",
        parent=body_style,
        fontSize=7.4,
        leading=9.8,
        spaceAfter=0,
    )
    code_style = ParagraphStyle(
        "HydraCode",
        parent=base["Code"],
        fontName=mono_font,
        fontSize=8.2,
        leading=11,
        leftIndent=14,
        textColor=colors.HexColor("#1E293B"),
        spaceAfter=6,
    )

    story: list = []
    lines = md_path.read_text(encoding="utf-8").splitlines()
    i = 0
    in_code_block = False
    code_lang = ""
    code_lines: list[str] = []

    while i < len(lines):
        raw = lines[i]
        stripped = raw.strip()

        if stripped.startswith("```"):
            if not in_code_block:
                in_code_block = True
                code_lang = stripped[3:].strip().lower()
                code_lines = []
            else:
                if code_lang != "mermaid" and code_lines:
                    story.append(Preformatted("\n".join(code_lines), code_style))
                in_code_block = False
                code_lang = ""
                code_lines = []
            i += 1
            continue

        if in_code_block:
            code_lines.append(raw)
            i += 1
            continue

        if not stripped or stripped == "---":
            i += 1
            continue

        if stripped.startswith("|") and "|" in stripped[1:]:
            table_block: list[str] = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                table_block.append(lines[i])
                i += 1
            tbl = _render_table(table_block, avail_w, tbl_header_style, tbl_cell_style, mono_font)
            if tbl is not None:
                story.append(tbl)
                story.append(Spacer(1, 6))
            continue

        img_match = IMAGE_RE.match(stripped)
        if img_match:
            caption, rel_img = img_match.group(1), img_match.group(2)
            img_path = (md_path.parent / rel_img).resolve()
            if img_path.is_file():
                with PILImage.open(img_path) as im:
                    px_w, px_h = im.size
                img_w = min(avail_w, 6.6 * inch)
                img_h = img_w * (px_h / px_w)
                max_h = 4.2 * inch
                if img_h > max_h:
                    img_h = max_h
                    img_w = img_h * (px_w / px_h)
                fig = Image(str(img_path), width=img_w, height=img_h)
                fig.hAlign = "CENTER"
                cap = Paragraph(f"Figure: {html.escape(caption)}", caption_style)
                story.append(Spacer(1, 4))
                story.append(KeepTogether([fig, cap]))
            i += 1
            continue

        if stripped.startswith("# "):
            story.append(Paragraph(html.escape(stripped[2:].strip()), title_style))
            i += 1
            continue
        if stripped.startswith("## "):
            heading_text = stripped[3:].strip()
            if heading_text == "Repository & Submission Details":
                story.append(PageBreak())
            story.append(Paragraph(html.escape(heading_text), h1_style))
            i += 1
            continue
        if stripped.startswith("### "):
            story.append(Paragraph(html.escape(stripped[4:].strip()), h2_style))
            i += 1
            continue

        if stripped.startswith("- "):
            xml_txt = _md_inline_to_xml(stripped[2:].strip(), mono_font)
            story.append(Paragraph(f"&bull;&nbsp;&nbsp;{xml_txt}", list_style))
            i += 1
            continue

        num_match = NUMBERED_RE.match(stripped)
        if num_match:
            num_lbl = num_match.group(1)
            xml_txt = _md_inline_to_xml(num_match.group(2).strip(), mono_font)
            story.append(Paragraph(f"{num_lbl}.&nbsp;&nbsp;{xml_txt}", list_style))
            i += 1
            continue

        para_lines = [(stripped, raw.rstrip("\r\n").endswith("  "))]
        while (
            i + 1 < len(lines)
            and lines[i + 1].strip()
            and not lines[i + 1].strip().startswith(("#", "-", "|", "```", "!["))
            and not NUMBERED_RE.match(lines[i + 1].strip())
            and lines[i + 1].strip() != "---"
        ):
            i += 1
            next_raw = lines[i]
            para_lines.append((next_raw.strip(), next_raw.rstrip("\r\n").endswith("  ")))

        xml_chunks: list[str] = []
        for idx, (segment, has_hard_break) in enumerate(para_lines):
            xml_chunks.append(_md_inline_to_xml(segment, mono_font))
            if idx < len(para_lines) - 1:
                xml_chunks.append("<br/>" if has_hard_break else " ")
        story.append(Paragraph("".join(xml_chunks), body_style))
        i += 1

    canvas_cls = _NumberedCanvas(body_font).make_canvas_class()
    doc.build(story, canvasmaker=canvas_cls)
    return pdf_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Export final-investigation-report.md to PDF.")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    out = export_markdown_to_pdf(args.input, args.output)
    print(f"[OK] Exported formatted PDF report to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
