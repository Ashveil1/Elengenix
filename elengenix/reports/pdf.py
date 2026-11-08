"""Markdown → PDF rendering (reportlab), CJK-safe and emoji-safe.

The renderer parses a pragmatic subset of markdown (headings, paragraphs,
fenced code blocks, nested lists, tables, horizontal rules) and lays it out
with reportlab platypus. CJK runs are rendered with the built-in
``STSong-Light`` CID font; the 16 known status emojis are substituted with
``[TAG]`` text placeholders before rendering.
"""

from __future__ import annotations

import io
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    XPreformatted,
)

__all__ = [
    "HEADING_FONT_SIZES",
    "EMOJI_SUBSTITUTIONS",
    "substitute_emojis",
    "split_by_cjk",
    "CSegment",
    "render_to_pdf_bytes",
]

HEADING_FONT_SIZES = {1: 16, 2: 14, 3: 13, 4: 12, 5: 11, 6: 10}

# The 16 known emojis → [TAG] text placeholders (fonts cannot render emoji).
EMOJI_SUBSTITUTIONS = {
    "\U0001F4DD": "[NOTE]",    # 📝
    "\u26A1": "[FAST]",        # ⚡
    "\u2705": "[DONE]",        # ✅
    "\u274C": "[FAIL]",        # ❌
    "\u23F3": "[WAIT]",        # ⏳
    "\U0001F50D": "[SEARCH]",  # 🔍
    "\U0001F680": "[ROCKET]",  # 🚀
    "\U0001F4A1": "[IDEA]",    # 💡
    "\u26A0\uFE0F": "[WARN]",  # ⚠️
    "\U0001F512": "[LOCK]",    # 🔒
    "\U0001F41B": "[BUG]",     # 🐛
    "\U0001F4CA": "[CHART]",   # 📊
    "\U0001F3AF": "[TARGET]",  # 🎯
    "\U0001F525": "[HOT]",     # 🔥
    "\U0001F4A5": "[BOOM]",    # 💥
    "\U0001F6E1\uFE0F": "[SHIELD]",  # 🛡️
}


def substitute_emojis(text: str) -> str:
    """Replace every known emoji with its ``[TAG]`` placeholder."""
    for emoji, tag in EMOJI_SUBSTITUTIONS.items():
        text = text.replace(emoji, tag)
    return text


@dataclass
class CSegment:
    """A text run that is either CJK or non-CJK."""

    text: str
    is_cjk: bool


_CJK_RANGES = (
    (0x1100, 0x11FF),   # Hangul Jamo
    (0x2E80, 0x303F),   # CJK radicals / Kangxi / CJK symbols
    (0x3040, 0x30FF),   # Hiragana / Katakana
    (0x3130, 0x318F),   # Hangul compatibility jamo
    (0x3400, 0x4DBF),   # CJK extension A
    (0x4E00, 0x9FFF),   # CJK unified ideographs
    (0xAC00, 0xD7AF),   # Hangul syllables
    (0xF900, 0xFAFF),   # CJK compatibility ideographs
    (0xFF00, 0xFFEF),   # fullwidth forms
)


def _is_cjk_char(ch: str) -> bool:
    cp = ord(ch)
    return any(lo <= cp <= hi for lo, hi in _CJK_RANGES)


def split_by_cjk(text: str) -> List[CSegment]:
    """Split text into alternating non-CJK / CJK runs.

    Empty input yields a single empty non-CJK segment; pure CJK input a
    single CJK segment.
    """
    if not text:
        return [CSegment("", False)]
    segments: List[CSegment] = []
    current = ""
    current_cjk: Optional[bool] = None
    for ch in text:
        cjk = _is_cjk_char(ch)
        if current_cjk is None or cjk == current_cjk:
            current += ch
            current_cjk = cjk
        else:
            segments.append(CSegment(current, current_cjk))
            current, current_cjk = ch, cjk
    segments.append(CSegment(current, bool(current_cjk)))
    return segments


_CJK_FONT = "WQYMicroHei"
_CJK_FALLBACK_FONT = "STSong-Light"
_BUNDLED_CJK_TTC = Path(__file__).parent / "fonts" / "wqy-microhei.ttc"
_font_registered = False


def _ensure_fonts() -> None:
    """Register the embedded CJK font (bundled WenQuanYi Micro Hei, GPL-2.0
    with font-embedding exception); fall back to the non-embedded
    STSong-Light CID font when the bundle is unavailable."""
    global _font_registered
    if not _font_registered:
        if _BUNDLED_CJK_TTC.exists():
            pdfmetrics.registerFont(TTFont(_CJK_FONT, str(_BUNDLED_CJK_TTC), subfontIndex=0))
        else:
            pdfmetrics.registerFont(UnicodeCIDFont(_CJK_FALLBACK_FONT))
        _font_registered = True


def _escape_xml(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _inline_markup(text: str) -> str:
    """Escape + convert inline markdown (bold/italic/code/links) + CJK fonts."""
    text = _escape_xml(text)

    def _link(match: "re.Match[str]") -> str:
        label, url = match.group(1), match.group(2)
        if url.startswith("#"):
            # Internal anchors have no PDF destination — render as plain text.
            return label
        return f'<link href="{url}" color="blue">{label}</link>'

    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", _link, text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", text)
    text = re.sub(r"(?<!\*)\*([^*]+)\*(?!\*)", r"<i>\1</i>", text)
    text = re.sub(r"`([^`]+)`", r'<font face="Courier">\1</font>', text)

    parts: List[str] = []
    for seg in split_by_cjk(text):
        if seg.is_cjk:
            parts.append(f'<font name="{_CJK_FONT}">{seg.text}</font>')
        else:
            parts.append(seg.text)
    return "".join(parts)


def _sanitize_latin1(text: str) -> str:
    """Keep code blocks renderable in the Courier base font."""
    return text.encode("latin-1", "replace").decode("latin-1")


def _parse_blocks(md_text: str) -> List[Tuple[str, object]]:
    """Parse markdown into (kind, payload) blocks."""
    lines = md_text.split("\n")
    blocks: List[Tuple[str, object]] = []
    i = 0
    while i < len(lines):
        raw = lines[i]
        stripped = raw.strip()

        if stripped.startswith("```"):
            i += 1
            code: List[str] = []
            while i < len(lines) and not lines[i].strip().startswith("```"):
                code.append(lines[i])
                i += 1
            i += 1  # skip the closing fence
            blocks.append(("code", "\n".join(code)))
            continue

        heading = re.match(r"^(#{1,6})\s+(.*)$", stripped)
        if heading:
            blocks.append(("heading", (len(heading.group(1)), heading.group(2))))
            i += 1
            continue

        if stripped.startswith("|") and i + 1 < len(lines) and re.match(
            r"^\|[\s:\-|]+\|$", lines[i + 1].strip()
        ):
            header = [c.strip() for c in stripped.strip("|").split("|")]
            i += 2
            rows: List[List[str]] = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                rows.append([c.strip() for c in lines[i].strip().strip("|").split("|")])
                i += 1
            blocks.append(("table", (header, rows)))
            continue

        list_match = re.match(r"^(\s*)[-*]\s+(.*)$", raw)
        if list_match:
            items: List[Tuple[int, str]] = []
            while i < len(lines):
                item = re.match(r"^(\s*)[-*]\s+(.*)$", lines[i])
                if not item:
                    break
                items.append((len(item.group(1)) // 2, item.group(2)))
                i += 1
            blocks.append(("list", items))
            continue

        if stripped:
            paragraph: List[str] = [stripped]
            i += 1
            while i < len(lines):
                nxt = lines[i].strip()
                if (
                    not nxt
                    or re.match(r"^#{1,6}\s", nxt)
                    or nxt.startswith("|")
                    or nxt.startswith("```")
                    or re.match(r"^[-*]\s", nxt)
                ):
                    break
                paragraph.append(nxt)
                i += 1
            blocks.append(("para", " ".join(paragraph)))
            continue

        i += 1
    return blocks


def _build_styles() -> Tuple[ParagraphStyle, dict]:
    body = ParagraphStyle(
        "Body", fontName="Helvetica", fontSize=10, leading=14,
        alignment=TA_LEFT, spaceAfter=6,
    )
    heading_styles = {}
    for level, size in HEADING_FONT_SIZES.items():
        heading_styles[level] = ParagraphStyle(
            f"Heading{level}", fontName="Helvetica-Bold", fontSize=size,
            leading=size + 4, spaceBefore=10 if level > 1 else 0, spaceAfter=6,
        )
    code_style = ParagraphStyle(
        "Code", fontName="Courier", fontSize=8.5, leading=11,
        backColor=colors.HexColor("#f4f4f4"), borderPadding=4,
        spaceAfter=6,
    )
    return body, {"headings": heading_styles, "code": code_style}


def render_to_pdf_bytes(md_text: str) -> bytes:
    """Render a markdown string to PDF bytes (synchronous)."""
    _ensure_fonts()
    text = substitute_emojis(md_text)
    blocks = _parse_blocks(text)

    body, styles = _build_styles()
    story: List[object] = []
    for kind, payload in blocks:
        if kind == "heading":
            level, content = payload  # type: ignore[misc]
            story.append(Paragraph(_inline_markup(content), styles["headings"][level]))
        elif kind == "para":
            story.append(Paragraph(_inline_markup(str(payload)), body))
        elif kind == "code":
            story.append(XPreformatted(_sanitize_latin1(str(payload)), styles["code"]))
        elif kind == "list":
            for depth, item in payload:  # type: ignore[union-attr]
                indent_style = ParagraphStyle(
                    f"List{depth}", parent=body, leftIndent=12 * (depth + 1),
                    bulletIndent=12 * depth, spaceAfter=2,
                )
                story.append(Paragraph(_inline_markup(item), indent_style, bulletText="\u2022"))
            story.append(Spacer(1, 4))
        elif kind == "table":
            header, rows = payload  # type: ignore[misc]
            data = [[Paragraph(_inline_markup(c), body) for c in header]]
            for row in rows:
                data.append([Paragraph(_inline_markup(c), body) for c in row])
            table = Table(data, hAlign="LEFT")
            table.setStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#999999")),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eeeeee")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
            story.append(table)
            story.append(Spacer(1, 6))
        elif kind == "hr":
            story.append(HRFlowable(width="100%", thickness=0.5))

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        title="Elengenix Report",
    )

    def _canvasmaker(*args, **kwargs):
        kwargs["pageCompression"] = 0
        return Canvas(*args, **kwargs)

    doc.build(story, canvasmaker=_canvasmaker)
    return buf.getvalue()
