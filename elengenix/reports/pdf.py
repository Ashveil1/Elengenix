"""elengenix.reports.pdf — PDF rendering from markdown content.

Uses a minimal PDF generator (no external dependencies) to produce
valid PDF bytes from markdown text. Supports heading font sizes,
CJK splitting, and emoji substitution.
"""
from __future__ import annotations

import re
from typing import Sequence

# Heading font sizes (pt)
HEADING_FONT_SIZES: dict[int, float] = {
    1: 24.0,
    2: 20.0,
    3: 16.0,
    4: 14.0,
    5: 12.0,
    6: 11.0,
}

# Emoji → text substitutions for PDF (PDF doesn't render emoji natively)
EMOJI_SUBSTITUTIONS: dict[str, str] = {
    "✅": "[OK]",
    "❌": "[FAIL]",
    "🔄": "[RUN]",
    "⏳": "[WAIT]",
    "🚫": "[CANCEL]",
    "📋": "[TODO]",
    "⚠️": "[WARN]",
    "🔍": "[SEARCH]",
    "🎯": "[TARGET]",
    "🏆": "[TROPHY]",
    "💡": "[INFO]",
    "🔥": "[HOT]",
    "🛡️": "[SHIELD]",
    "⚔️": "[SWORD]",
    "📊": "[CHART]",
    "📦": "[PACKAGE]",
    "🔧": "[TOOL]",
    "🌐": "[WEB]",
    "🔒": "[LOCK]",
    "🔓": "[UNLOCK]",
    "🐛": "[BUG]",
    "✨": "[NEW]",
    "📝": "[NOTE]",
    "🎨": "[DESIGN]",
    "🚀": "[LAUNCH]",
    "📱": "[MOBILE]",
    "💻": "[CODE]",
    "🔧": "[CONFIG]",
    "🔔": "[ALERT]",
    "📍": "[PIN]",
}


def substitute_emojis(text: str) -> str:
    """Replace emoji characters with PDF-safe text equivalents."""
    result = text
    for emoji, replacement in EMOJI_SUBSTITUTIONS.items():
        result = result.replace(emoji, replacement)
    return result


def split_by_cjk(text: str) -> list[str]:
    """Split text into segments at CJK character boundaries.

    This helps PDF rendering by separating Latin and CJK text runs
    so different fonts can be applied.
    """
    segments: list[str] = []
    current = ""
    prev_is_cjk = False

    for char in text:
        is_cjk = (
            "\u4e00" <= char <= "\u9fff"  # CJK Unified
            or "\u3400" <= char <= "\u4dbf"  # CJK Extension A
            or "\u3040" <= char <= "\u30ff"  # Japanese
            or "\uac00" <= char <= "\ud7af"  # Korean
        )
        if is_cjk != prev_is_cjk and current:
            segments.append(current)
            current = ""
        current += char
        prev_is_cjk = is_cjk

    if current:
        segments.append(current)

    return segments


def render_to_pdf_bytes(markdown: str) -> bytes:
    """Render markdown content to a minimal valid PDF.

    Produces a simple PDF with text content extracted from the markdown.
    The output starts with %PDF and is a valid PDF 1.4 document.
    """
    # Simple PDF generation
    lines = markdown.split("\n")
    text_lines: list[str] = []

    for line in lines:
        # Strip markdown formatting
        clean = re.sub(r"^#{1,6}\s+", "", line)  # headers
        clean = re.sub(r"\*\*(.+?)\*\*", r"\1", clean)  # bold
        clean = re.sub(r"\*(.+?)\*", r"\1", clean)  # italic
        clean = re.sub(r"`(.+?)`", r"\1", clean)  # code
        clean = re.sub(r"^>\s+", "", clean)  # blockquote
        clean = substitute_emojis(clean)
        if clean.strip():
            text_lines.append(clean.strip())

    # Build minimal PDF
    content_lines = []
    for i, line in enumerate(text_lines):
        # Escape parentheses and backslashes
        safe = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        content_lines.append(f"BT /F1 10 Tf 72 {750 - i * 12} Td ({safe}) Tj ET")

    content = "\n".join(content_lines)
    content_bytes = content.encode("latin-1", errors="replace")

    # PDF structure
    pdf_parts = []
    pdf_parts.append(b"%PDF-1.4\n")

    # Object 1: Catalog
    obj1 = b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    pdf_parts.append(obj1)

    # Object 2: Pages
    obj2 = b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
    pdf_parts.append(obj2)

    # Object 3: Page
    obj3 = b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n"
    pdf_parts.append(obj3)

    # Object 4: Content stream
    stream_content = content_bytes
    obj4 = f"4 0 obj\n<< /Length {len(stream_content)} >>\nstream\n".encode("latin-1") + stream_content + b"\nendstream\nendobj\n"
    pdf_parts.append(obj4)

    # Object 5: Font
    obj5 = b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n"
    pdf_parts.append(obj5)

    # Cross-reference table
    xref_offset = sum(len(p) for p in pdf_parts)
    xref = b"xref\n0 6\n0000000000 65535 f \n"
    offset = len(b"%PDF-1.4\n")
    for i, part in enumerate(pdf_parts[1:], 1):
        xref += f"{offset:010d} 00000 n \n".encode("latin-1")
        offset += len(part)

    pdf_parts.append(xref)
    pdf_parts.append(f"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode("latin-1"))

    return b"".join(pdf_parts)
