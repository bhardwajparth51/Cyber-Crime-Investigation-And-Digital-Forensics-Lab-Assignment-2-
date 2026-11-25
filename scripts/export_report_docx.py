"""Export reports/final-investigation-report.md to a formatted Word (.docx) document."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.opc.constants import RELATIONSHIP_TYPE as RT
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn
from docx.shared import Inches, Pt, RGBColor

ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = ROOT_DIR / "reports" / "final-investigation-report.md"
DEFAULT_OUTPUT = ROOT_DIR / "reports" / "final-investigation-report.docx"

IMAGE_RE = re.compile(r"^!\[([^\]]*)\]\(([^)]+)\)$")
INLINE_TOKEN_RE = re.compile(
    r"(\*\*[^*]+\*\*|\*[^*]+\*|`[^`]+`|\[[^\]]+\]\([^)]+\)|https?://[^\s<>)]+)"
)
NUMBERED_RE = re.compile(r"^(\d+)\.\s+(.*)$")


def _set_cell_shading(cell, fill_hex: str) -> None:
    shading = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{fill_hex}"/>')
    cell._tc.get_or_add_tcPr().append(shading)


def _set_table_borders(table) -> None:
    tbl_pr = table._tbl.tblPr
    borders = parse_xml(
        f'<w:tblBorders {nsdecls("w")}>'
        '<w:top w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>'
        '<w:bottom w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>'
        '<w:insideH w:val="single" w:sz="4" w:space="0" w:color="E2E8F0"/>'
        '<w:left w:val="none"/><w:right w:val="none"/><w:insideV w:val="none"/>'
        "</w:tblBorders>"
    )
    tbl_pr.append(borders)


def _add_page_number_footer(section) -> None:
    footer = section.footer
    para = footer.paragraphs[0]
    para.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    run_left = para.add_run("Operation Hydra (INC-2026-HYDRA-01) — Synthetic Academic Investigation  |  Page ")
    run_left.font.size = Pt(8.5)
    run_left.font.color.rgb = RGBColor(100, 116, 139)

    fld_begin = OxmlElement("w:fldChar")
    fld_begin.set(qn("w:fldCharType"), "begin")
    instr = OxmlElement("w:instrText")
    instr.set(qn("xml:space"), "preserve")
    instr.text = "PAGE"
    fld_end = OxmlElement("w:fldChar")
    fld_end.set(qn("w:fldCharType"), "end")

    r_page = para.add_run()
    r_page.font.size = Pt(8.5)
    r_page.font.color.rgb = RGBColor(100, 116, 139)
    r_page._r.append(fld_begin)
    r_page._r.append(instr)
    r_page._r.append(fld_end)


def _set_row_pagination(row, *, is_header: bool = False) -> None:
    """Keep table rows intact across pages and repeat the header row."""
    tr_pr = row._tr.get_or_add_trPr()
    tr_pr.append(OxmlElement("w:cantSplit"))
    if is_header:
        tr_pr.append(OxmlElement("w:tblHeader"))


def _add_hyperlink(
    paragraph,
    url: str,
    text: str,
    base_size: float = 10.5,
    *,
    bold: bool = False,
    italic: bool = False,
    color: RGBColor | None = None,
) -> None:
    """Insert a clickable Word hyperlink element into a paragraph."""
    part = paragraph.part
    r_id = part.relate_to(url, RT.HYPERLINK, is_external=True)

    hyperlink = OxmlElement("w:hyperlink")
    hyperlink.set(qn("r:id"), r_id)

    new_run = OxmlElement("w:r")
    r_pr = OxmlElement("w:rPr")

    r_fonts = OxmlElement("w:rFonts")
    r_fonts.set(qn("w:ascii"), "Calibri")
    r_fonts.set(qn("w:hAnsi"), "Calibri")
    r_pr.append(r_fonts)

    sz = OxmlElement("w:sz")
    sz.set(qn("w:val"), str(int(base_size * 2)))
    r_pr.append(sz)

    if bold:
        r_pr.append(OxmlElement("w:b"))
    if italic:
        r_pr.append(OxmlElement("w:i"))

    link_hex = "FFFFFF" if color == RGBColor(255, 255, 255) else "1D4ED8"
    c_el = OxmlElement("w:color")
    c_el.set(qn("w:val"), link_hex)
    r_pr.append(c_el)

    u_el = OxmlElement("w:u")
    u_el.set(qn("w:val"), "single")
    r_pr.append(u_el)

    new_run.append(r_pr)
    t_el = OxmlElement("w:t")
    t_el.text = text
    new_run.append(t_el)
    hyperlink.append(new_run)
    paragraph._p.append(hyperlink)


def _add_inline_runs(
    paragraph,
    text: str,
    base_size: float = 10.5,
    *,
    bold: bool = False,
    italic: bool = False,
    color: RGBColor | None = None,
) -> None:
    """Render bold, italic, inline code, and markdown links cleanly into a Word paragraph."""
    pos = 0
    for match in INLINE_TOKEN_RE.finditer(text):
        if match.start() > pos:
            r = paragraph.add_run(text[pos : match.start()])
            r.bold = bold
            r.italic = italic
            r.font.size = Pt(base_size)
            if color is not None:
                r.font.color.rgb = color
        token = match.group(0)
        if token.startswith("**") and token.endswith("**"):
            _add_inline_runs(
                paragraph,
                token[2:-2],
                base_size=base_size,
                bold=True,
                italic=italic,
                color=color,
            )
        elif token.startswith("*") and token.endswith("*"):
            _add_inline_runs(
                paragraph,
                token[1:-1],
                base_size=base_size,
                bold=bold,
                italic=True,
                color=color,
            )
        elif token.startswith("`") and token.endswith("`"):
            r = paragraph.add_run(token[1:-1])
            r.bold = bold
            r.italic = italic
            r.font.name = "DejaVu Sans Mono"
            r.font.size = Pt(max(base_size - 1.0, 8.5))
            r.font.color.rgb = color if color is not None else RGBColor(30, 58, 138)
        elif token.startswith("["):
            label, _, target = token[1:-1].partition("](")
            if target.startswith("http"):
                _add_hyperlink(
                    paragraph,
                    target,
                    label,
                    base_size=base_size,
                    bold=bold,
                    italic=italic,
                    color=color,
                )
                if label != target and not label.startswith("http"):
                    r_url = paragraph.add_run(f" ({target})")
                    r_url.bold = bold
                    r_url.italic = italic
                    r_url.font.size = Pt(max(base_size - 1.0, 8.5))
                    r_url.font.color.rgb = color if color is not None else RGBColor(100, 116, 139)
            else:
                r = paragraph.add_run(label)
                r.bold = bold
                r.italic = italic
                r.font.size = Pt(base_size)
                r.font.color.rgb = color if color is not None else RGBColor(29, 78, 216)
        elif token.startswith("http"):
            _add_hyperlink(
                paragraph,
                token,
                token,
                base_size=base_size,
                bold=bold,
                italic=italic,
                color=color,
            )
        pos = match.end()

    if pos < len(text):
        r = paragraph.add_run(text[pos:])
        r.bold = bold
        r.italic = italic
        r.font.size = Pt(base_size)
        if color is not None:
            r.font.color.rgb = color


def _render_table(doc: Document, table_lines: list[str]) -> None:
    rows = []
    for idx, line in enumerate(table_lines):
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if idx == 1 and all(set(c) <= {"-", ":"} for c in cells if c):
            continue
        rows.append(cells)

    if not rows:
        return

    num_cols = len(rows[0])
    table = doc.add_table(rows=len(rows), cols=num_cols)
    _set_table_borders(table)

    for r_idx, row_vals in enumerate(rows):
        _set_row_pagination(table.rows[r_idx], is_header=(r_idx == 0))
        for c_idx in range(num_cols):
            cell = table.cell(r_idx, c_idx)
            val = row_vals[c_idx] if c_idx < len(row_vals) else ""
            p = cell.paragraphs[0]
            p.paragraph_format.space_before = Pt(3)
            p.paragraph_format.space_after = Pt(3)
            if r_idx == 0:
                _set_cell_shading(cell, "1E3A8A")
                _add_inline_runs(
                    p,
                    val,
                    base_size=9.5,
                    bold=True,
                    color=RGBColor(255, 255, 255),
                )
            else:
                if r_idx % 2 == 0:
                    _set_cell_shading(cell, "F8FAFC")
                _add_inline_runs(p, val, base_size=9.2)

    spacer = doc.add_paragraph()
    spacer.paragraph_format.space_after = Pt(4)


def export_markdown_to_docx(md_path: Path, docx_path: Path) -> Path:
    """Convert the Markdown final investigation report into a styled .docx file."""
    doc = Document()

    section = doc.sections[0]
    section.top_margin = Inches(0.8)
    section.bottom_margin = Inches(0.8)
    section.left_margin = Inches(0.85)
    section.right_margin = Inches(0.85)
    _add_page_number_footer(section)

    normal_style = doc.styles["Normal"]
    normal_style.font.name = "Calibri"
    normal_style.font.size = Pt(10.5)
    normal_style.font.color.rgb = RGBColor(30, 41, 59)

    lines = md_path.read_text(encoding="utf-8").splitlines()
    i = 0
    in_code_block = False
    code_lang = ""
    code_lines: list[str] = []

    while i < len(lines):
        raw = lines[i]
        stripped = raw.strip()

        # Handle fenced code blocks (omit raw mermaid text because PNG figure is already embedded)
        if stripped.startswith("```"):
            if not in_code_block:
                in_code_block = True
                code_lang = stripped[3:].strip().lower()
                code_lines = []
            else:
                if code_lang != "mermaid" and code_lines:
                    p = doc.add_paragraph()
                    p.paragraph_format.left_indent = Inches(0.25)
                    r = p.add_run("\n".join(code_lines))
                    r.font.name = "DejaVu Sans Mono"
                    r.font.size = Pt(9.0)
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

        # Markdown table block
        if stripped.startswith("|") and "|" in stripped[1:]:
            table_block: list[str] = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                table_block.append(lines[i])
                i += 1
            _render_table(doc, table_block)
            continue

        # Image embed
        img_match = IMAGE_RE.match(stripped)
        if img_match:
            caption, rel_img = img_match.group(1), img_match.group(2)
            img_path = (md_path.parent / rel_img).resolve()
            if img_path.is_file():
                p_img = doc.add_paragraph()
                p_img.alignment = WD_ALIGN_PARAGRAPH.CENTER
                p_img.paragraph_format.space_before = Pt(6)
                p_img.paragraph_format.space_after = Pt(2)
                p_img.paragraph_format.keep_with_next = True
                p_img.add_run().add_picture(str(img_path), width=Inches(6.4))

                p_cap = doc.add_paragraph()
                p_cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
                p_cap.paragraph_format.space_after = Pt(8)
                rc = p_cap.add_run(f"Figure: {caption}")
                rc.italic = True
                rc.font.size = Pt(9.0)
                rc.font.color.rgb = RGBColor(71, 85, 105)
            i += 1
            continue

        # Headings
        if stripped.startswith("# "):
            h = doc.add_heading(stripped[2:].strip(), level=0)
            h.paragraph_format.keep_with_next = True
            for r in h.runs:
                r.font.color.rgb = RGBColor(15, 23, 42)
            i += 1
            continue
        if stripped.startswith("## "):
            heading_text = stripped[3:].strip()
            if heading_text == "Repository & Submission Details":
                doc.add_page_break()
            h = doc.add_heading(heading_text, level=1)
            h.paragraph_format.keep_with_next = True
            for r in h.runs:
                r.font.color.rgb = RGBColor(30, 58, 138)
            i += 1
            continue
        if stripped.startswith("### "):
            h = doc.add_heading(stripped[4:].strip(), level=2)
            h.paragraph_format.keep_with_next = True
            for r in h.runs:
                r.font.color.rgb = RGBColor(51, 65, 85)
            i += 1
            continue

        # Bullet lists
        if stripped.startswith("- "):
            p = doc.add_paragraph(style="List Bullet")
            p.paragraph_format.space_after = Pt(3)
            _add_inline_runs(p, stripped[2:].strip())
            i += 1
            continue

        # Numbered lists
        num_match = NUMBERED_RE.match(stripped)
        if num_match:
            p = doc.add_paragraph(style="List Number")
            p.paragraph_format.space_after = Pt(3)
            _add_inline_runs(p, num_match.group(2).strip())
            i += 1
            continue

        # Standard paragraph (preserve Markdown hard line breaks ending in >=2 spaces)
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

        p = doc.add_paragraph()
        p.paragraph_format.space_after = Pt(5)
        p.paragraph_format.line_spacing = 1.15
        for line_idx, (segment, has_hard_break) in enumerate(para_lines):
            _add_inline_runs(p, segment)
            if line_idx < len(para_lines) - 1:
                if has_hard_break:
                    p.add_run().add_break()
                else:
                    p.add_run(" ")
        i += 1

    docx_path.parent.mkdir(parents=True, exist_ok=True)
    doc.save(str(docx_path))
    return docx_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Export final-investigation-report.md to DOCX.")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    out = export_markdown_to_docx(args.input, args.output)
    print(f"[OK] Exported formatted DOCX report to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
