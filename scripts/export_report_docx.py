"""Export reports/final-investigation-report.md to a formatted Word (.docx) document."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn
from docx.shared import Inches, Pt, RGBColor

ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = ROOT_DIR / "reports" / "final-investigation-report.md"
DEFAULT_OUTPUT = ROOT_DIR / "reports" / "final-investigation-report.docx"

IMAGE_RE = re.compile(r"^!\[([^\]]*)\]\(([^)]+)\)$")
INLINE_TOKEN_RE = re.compile(r"(\*\*[^*]+\*\*|\*[^*]+\*|`[^`]+`|\[[^\]]+\]\([^)]+\))")
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


def _add_inline_runs(paragraph, text: str, base_size: float = 10.5) -> None:
    """Render bold, italic, inline code, and markdown links cleanly into a Word paragraph."""
    pos = 0
    for match in INLINE_TOKEN_RE.finditer(text):
        if match.start() > pos:
            r = paragraph.add_run(text[pos : match.start()])
            r.font.size = Pt(base_size)
        token = match.group(0)
        if token.startswith("**") and token.endswith("**"):
            r = paragraph.add_run(token[2:-2])
            r.bold = True
            r.font.size = Pt(base_size)
        elif token.startswith("*") and token.endswith("*"):
            r = paragraph.add_run(token[1:-1])
            r.italic = True
            r.font.size = Pt(base_size)
        elif token.startswith("`") and token.endswith("`"):
            r = paragraph.add_run(token[1:-1])
            r.font.name = "DejaVu Sans Mono"
            r.font.size = Pt(max(base_size - 1.0, 8.5))
            r.font.color.rgb = RGBColor(30, 58, 138)
        elif token.startswith("["):
            label, _, target = token[1:-1].partition("](")
            r = paragraph.add_run(label)
            r.font.size = Pt(base_size)
            r.font.color.rgb = RGBColor(29, 78, 216)
            if target.startswith("http") and label != target:
                r_url = paragraph.add_run(f" ({target})")
                r_url.font.size = Pt(max(base_size - 1.0, 8.5))
                r_url.font.color.rgb = RGBColor(100, 116, 139)
        pos = match.end()

    if pos < len(text):
        r = paragraph.add_run(text[pos:])
        r.font.size = Pt(base_size)


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
        for c_idx in range(num_cols):
            cell = table.cell(r_idx, c_idx)
            val = row_vals[c_idx] if c_idx < len(row_vals) else ""
            p = cell.paragraphs[0]
            p.paragraph_format.space_before = Pt(3)
            p.paragraph_format.space_after = Pt(3)
            if r_idx == 0:
                _set_cell_shading(cell, "1E3A8A")
                run = p.add_run(val.replace("**", ""))
                run.bold = True
                run.font.size = Pt(9.5)
                run.font.color.rgb = RGBColor(255, 255, 255)
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
            for r in h.runs:
                r.font.color.rgb = RGBColor(15, 23, 42)
            i += 1
            continue
        if stripped.startswith("## "):
            h = doc.add_heading(stripped[3:].strip(), level=1)
            for r in h.runs:
                r.font.color.rgb = RGBColor(30, 58, 138)
            i += 1
            continue
        if stripped.startswith("### "):
            h = doc.add_heading(stripped[4:].strip(), level=2)
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

        # Standard paragraph (coalesce consecutive plain lines separated by single newline)
        para_lines = [stripped]
        while (
            i + 1 < len(lines)
            and lines[i + 1].strip()
            and not lines[i + 1].strip().startswith(("#", "-", "|", "```", "!["))
            and not NUMBERED_RE.match(lines[i + 1].strip())
            and lines[i + 1].strip() != "---"
        ):
            i += 1
            para_lines.append(lines[i].strip())

        p = doc.add_paragraph()
        p.paragraph_format.space_after = Pt(5)
        p.paragraph_format.line_spacing = 1.15
        _add_inline_runs(p, " ".join(para_lines))
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
