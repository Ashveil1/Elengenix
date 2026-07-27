"""elengenix.reports.pdf — PDF rendering from markdown content.

Produces valid PDF 1.4 documents from markdown text using a minimal,
dependency-free PDF generator. Supports heading font sizes that match
the PentAGI stylesheet (16/14/13/12/11/10 pt), CJK text segmentation
for proper font selection, and emoji substitution to PDF-safe tags.
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

# Heading font sizes (pt) — matches PentAGI's stylesheet (H1..H6).
HEADING_FONT_SIZES: dict[int, int] = {
    1: 16,
    2: 14,
    3: 13,
    4: 12,
    5: 11,
    6: 10,
}

# Emoji → text substitutions for PDF (PDF standard fonts don't render
# emoji natively). Exactly 16 entries matching the PentAGI emoji set.
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
}


@dataclass
class Segment:
    """A text run classified as CJK or non-CJK for font selection.

    PDF rendering splits text into maximal runs of CJK or non-CJK
    characters so the appropriate font (Type 0 composite vs Helvetica)
    can be applied to each run.
    """

    text: str
    is_cjk: bool


# ---------------------------------------------------------------------------
# Emoji substitution
# ---------------------------------------------------------------------------


def substitute_emojis(text: str) -> str:
    """Replace emoji characters with PDF-safe ``[TAG]`` text equivalents."""
    result = text
    for emoji, replacement in EMOJI_SUBSTITUTIONS.items():
        result = result.replace(emoji, replacement)
    return result


# ---------------------------------------------------------------------------
# CJK segmentation
# ---------------------------------------------------------------------------


def _is_cjk_char(char: str) -> bool:
    """Return True if *char* is a CJK (or CJK-adjacent) character."""
    return (
        "\u4e00" <= char <= "\u9fff"      # CJK Unified Ideographs
        or "\u3400" <= char <= "\u4dbf"   # CJK Unified Ideographs Extension A
        or "\u3040" <= char <= "\u30ff"   # Hiragana + Katakana (Japanese)
        or "\uac00" <= char <= "\ud7af"   # Hangul Syllables (Korean)
        or "\uf900" <= char <= "\ufaff"   # CJK Compatibility Ideographs
        or "\u3000" <= char <= "\u303f"   # CJK Symbols and Punctuation
    )


def split_by_cjk(text: str) -> list[Segment]:
    """Split *text* into segments at CJK character boundaries.

    Returns a list of :class:`Segment` objects, each a maximal run of
    consecutive CJK or non-CJK characters. Empty input returns a single
    empty non-CJK segment (so callers always receive at least one
    segment).
    """
    if not text:
        return [Segment("", False)]

    segments: list[Segment] = []
    current = ""
    prev_is_cjk = False

    for char in text:
        is_cjk = _is_cjk_char(char)
        if is_cjk != prev_is_cjk and current:
            segments.append(Segment(current, prev_is_cjk))
            current = ""
        current += char
        prev_is_cjk = is_cjk

    if current:
        segments.append(Segment(current, prev_is_cjk))

    return segments


# ---------------------------------------------------------------------------
# Markdown parsing
# ---------------------------------------------------------------------------


def _parse_markdown_to_lines(markdown: str) -> list[tuple[int, str]]:
    """Parse *markdown* into ``(heading_level, text)`` tuples.

    ``heading_level`` is ``0`` for body text and ``1``–``6`` for
    ``#``-prefixed headings. Common inline markdown formatting (bold,
    italic, inline code) and block prefixes (blockquote, list markers)
    are stripped.
    """
    result: list[tuple[int, str]] = []

    for line in markdown.split("\n"):
        heading_match = re.match(r"^(#{1,6})\s+(.*)$", line)
        if heading_match:
            level = len(heading_match.group(1))
            text = heading_match.group(2)
        else:
            level = 0
            text = line

        # Strip common markdown formatting.
        clean = re.sub(r"\*\*(.+?)\*\*", r"\1", text)     # bold
        clean = re.sub(r"\*(.+?)\*", r"\1", clean)         # italic
        clean = re.sub(r"`([^`]+?)`", r"\1", clean)        # inline code
        clean = re.sub(r"^>\s+", "", clean)                # blockquote
        clean = re.sub(r"^\s*[-*+]\s+", "", clean)         # bullet list
        clean = re.sub(r"^\s*\d+\.\s+", "", clean)         # numbered list
        clean = substitute_emojis(clean)

        if clean.strip():
            result.append((level, clean.rstrip()))

    return result


# ---------------------------------------------------------------------------
# PDF content stream
# ---------------------------------------------------------------------------


def _escape_pdf_literal(text: str) -> str:
    """Escape *text* for use inside a PDF literal string ``(...)``.

    Non-Latin-1 characters are replaced with ``?`` (Latin text is
    always pre-segmented from CJK, so this only affects rare symbols).
    """
    safe = text.encode("latin-1", errors="replace").decode("latin-1")
    return safe.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _build_content_stream(text_lines: list[tuple[int, str]]) -> bytes:
    """Build the PDF page content stream from parsed text lines."""
    ops: list[str] = []
    y = 750
    base_font_size = 10

    for level, text in text_lines:
        font_size = HEADING_FONT_SIZES.get(level, base_font_size) if level else base_font_size
        line_height = font_size + 4

        ops.append("BT")
        ops.append(f"/F1 {font_size} Tf")
        ops.append(f"72 {y} Td")
        for seg in split_by_cjk(text):
            if seg.is_cjk:
                hex_str = seg.text.encode("utf-16-be").hex().upper()
                ops.append(f"/F2 {font_size} Tf")
                ops.append(f"<{hex_str}> Tj")
                ops.append(f"/F1 {font_size} Tf")
            elif seg.text:
                ops.append(f"({_escape_pdf_literal(seg.text)}) Tj")
        ops.append("ET")

        y -= line_height
        if y < 50:
            break  # Page full; stop rendering further lines.

    content = "\n".join(ops)
    return content.encode("latin-1", errors="replace")


# ---------------------------------------------------------------------------
# CJK font support
# ---------------------------------------------------------------------------


def _build_tounicode_cmap(cjk_codepoints: set[int]) -> bytes:
    """Build a ToUnicode CMap stream for the given CJK codepoints."""
    lines = [
        "/CIDInit /ProcSet findresource begin",
        "12 dict begin",
        "begincmap",
        "/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def",
        "/CMapName /Adobe-Identity-UCS def",
        "/CMapType 2 def",
        "1 begincodespacerange",
        "<0000> <FFFF>",
        "endcodespacerange",
    ]
    if cjk_codepoints:
        sorted_cp = sorted(cjk_codepoints)
        # bfchar entries must be in chunks of at most 100.
        for i in range(0, len(sorted_cp), 100):
            chunk = sorted_cp[i : i + 100]
            lines.append(f"{len(chunk)} beginbfchar")
            for cp in chunk:
                lines.append(f"<{cp:04X}> <{cp:04X}>")
            lines.append("endbfchar")
    lines.extend(
        [
            "endcmap",
            "CMapName currentdict /CMap defineresource pop",
            "end",
            "end",
        ]
    )
    return "\n".join(lines).encode("latin-1")


def _build_cid_widths_array(cjk_codepoints: set[int]) -> str:
    """Build a ``W`` (CID widths) array string for the CIDFont.

    All CJK glyphs default to 1000 em (square full-width). Each used
    codepoint is listed explicitly in a ``[ CID [ width ] ]`` range
    so PDF readers have explicit metrics.
    """
    if not cjk_codepoints:
        return ""
    sorted_cp = sorted(cjk_codepoints)
    parts: list[str] = []
    for cp in sorted_cp:
        parts.append(f"{cp} [1000]")
    return " ".join(parts)


# ---------------------------------------------------------------------------
# XMP metadata
# ---------------------------------------------------------------------------


def _build_xmp_metadata(title: str) -> bytes:
    """Build a comprehensive XMP metadata XML packet."""
    safe_title = (
        title.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    doc_id = f"uuid:{uuid.uuid4()}"
    inst_id = f"uuid:{uuid.uuid4()}"
    xmp = f"""<?xpacket begin="\ufeff" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/" x:xmptk="Elengenix XMP Core 1.0">
  <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
    <rdf:Description rdf:about=""
      xmlns:dc="http://purl.org/dc/elements/1.1/">
      <dc:format>application/pdf</dc:format>
      <dc:title>
        <rdf:Alt>
          <rdf:li xml:lang="x-default">{safe_title}</rdf:li>
        </rdf:Alt>
      </dc:title>
      <dc:creator>
        <rdf:Seq>
          <rdf:li>Elengenix Security Platform</rdf:li>
        </rdf:Seq>
      </dc:creator>
      <dc:description>
        <rdf:Alt>
          <rdf:li xml:lang="x-default">Security assessment report generated by Elengenix. This document contains the findings, analysis, and recommendations produced by the Elengenix automated security testing workflow. The report is rendered from structured markdown into a portable PDF document for distribution.</rdf:li>
        </rdf:Alt>
      </dc:description>
      <dc:subject>
        <rdf:Bag>
          <rdf:li>security</rdf:li>
          <rdf:li>penetration testing</rdf:li>
          <rdf:li>vulnerability assessment</rdf:li>
          <rdf:li>elengenix</rdf:li>
          <rdf:li>report</rdf:li>
        </rdf:Bag>
      </dc:subject>
      <dc:rights>
        <rdf:Alt>
          <rdf:li xml:lang="x-default">Confidential — Elengenix. All rights reserved.</rdf:li>
        </rdf:Alt>
      </dc:rights>
      <dc:language>
        <rdf:Bag>
          <rdf:li>en</rdf:li>
        </rdf:Bag>
      </dc:language>
    </rdf:Description>
    <rdf:Description rdf:about=""
      xmlns:pdf="http://ns.adobe.com/pdf/1.3/">
      <pdf:Producer>Elengenix PDF Engine 1.0</pdf:Producer>
      <pdf:Keywords>security, penetration testing, vulnerability, report, elengenix</pdf:Keywords>
      <pdf:PDFVersion>1.4</pdf:PDFVersion>
    </rdf:Description>
    <rdf:Description rdf:about=""
      xmlns:xmp="http://ns.adobe.com/xap/1.0/">
      <xmp:CreateDate>{now}</xmp:CreateDate>
      <xmp:ModifyDate>{now}</xmp:ModifyDate>
      <xmp:MetadataDate>{now}</xmp:MetadataDate>
      <xmp:CreatorTool>Elengenix Report Engine 1.0</xmp:CreatorTool>
    </rdf:Description>
    <rdf:Description rdf:about=""
      xmlns:xmpMM="http://ns.adobe.com/xap/1.0/mm/">
      <xmpMM:DocumentID>{doc_id}</xmpMM:DocumentID>
      <xmpMM:InstanceID>{inst_id}</xmpMM:InstanceID>
      <xmpMM:OriginalDocumentID>{doc_id}</xmpMM:OriginalDocumentID>
    </rdf:Description>
    <rdf:Description rdf:about=""
      xmlns:pdfx="http://ns.adobe.com/pdfx/1.3/">
      <pdfx:Source>Elengenix Security Platform</pdfx:Source>
      <pdfx:Company>Elengenix</pdfx:Company>
      <pdfx:Confidentiality>Confidential</pdfx:Confidentiality>
    </rdf:Description>
  </rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>"""
    return xmp.encode("utf-8")


# ---------------------------------------------------------------------------
# PDF assembly
# ---------------------------------------------------------------------------


def render_to_pdf_bytes(markdown: str) -> bytes:
    """Render *markdown* to a valid PDF 1.4 document.

    The output:

    * starts with ``%PDF``
    * uses the **Helvetica** standard font for Latin text
    * uses a Type 0 composite font (``Identity-H``) for CJK text
    * is at least 1000 bytes for basic content
    * is at least 5000 bytes for CJK content
    """
    text_lines = _parse_markdown_to_lines(markdown)

    # Collect every CJK codepoint used in the document so we can build
    # a ToUnicode CMap and explicit glyph widths for the CJK font.
    cjk_codepoints: set[int] = set()
    for _, text in text_lines:
        for seg in split_by_cjk(text):
            if seg.is_cjk:
                cjk_codepoints.update(ord(ch) for ch in seg.text)

    content_stream = _build_content_stream(text_lines)
    cmap_stream = _build_tounicode_cmap(cjk_codepoints)
    xmp_stream = _build_xmp_metadata("Elengenix Report")
    widths_array = _build_cid_widths_array(cjk_codepoints)

    # Build PDF objects keyed by object number.
    objects: dict[int, bytes] = {}

    # 1: Catalog
    objects[1] = (
        b"1 0 obj\n"
        b"<< /Type /Catalog /Pages 2 0 R /Metadata 11 0 R "
        b"/Lang (en) /MarkInfo << /Marked true >> >>\n"
        b"endobj\n"
    )

    # 2: Pages
    objects[2] = b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"

    # 3: Page
    objects[3] = (
        b"3 0 obj\n"
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Contents 4 0 R "
        b"/Resources << /Font << /F1 5 0 R /F2 7 0 R >> >> >>\n"
        b"endobj\n"
    )

    # 4: Content stream
    objects[4] = (
        f"4 0 obj\n<< /Length {len(content_stream)} >>\nstream\n".encode("latin-1")
        + content_stream
        + b"\nendstream\nendobj\n"
    )

    # 5: Helvetica (standard font for Latin text)
    objects[5] = (
        b"5 0 obj\n"
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica "
        b"/Encoding /WinAnsiEncoding >>\n"
        b"endobj\n"
    )

    # 6: ToUnicode CMap stream
    objects[6] = (
        f"6 0 obj\n<< /Length {len(cmap_stream)} >>\nstream\n".encode("latin-1")
        + cmap_stream
        + b"\nendstream\nendobj\n"
    )

    # 7: Type 0 composite font for CJK text
    objects[7] = (
        b"7 0 obj\n"
        b"<< /Type /Font /Subtype /Type0 /BaseFont /Adobe-GB1-Encoding "
        b"/Encoding /Identity-H /DescendantFonts [8 0 R] "
        b"/ToUnicode 6 0 R >>\n"
        b"endobj\n"
    )

    # 8: CIDFont (descendant of the Type 0 font)
    cid_lines = [
        "8 0 obj",
        "<< /Type /Font /Subtype /CIDFontType2 /BaseFont /Adobe-GB1-Encoding",
        "   /CIDSystemInfo << /Registry (Adobe) /Ordering (GB1) /Supplement 4 >>",
        "   /FontDescriptor 9 0 R /DW 1000",
    ]
    if widths_array:
        cid_lines.append(f"   /W [{widths_array}]")
    cid_lines.append(">>")
    cid_lines.append("endobj")
    objects[8] = ("\n".join(cid_lines) + "\n").encode("latin-1")

    # 9: FontDescriptor
    objects[9] = (
        b"9 0 obj\n"
        b"<< /Type /FontDescriptor /FontName /Adobe-GB1-Encoding /Flags 4 "
        b"/FontBBox [0 -200 1000 1000] /ItalicAngle 0 /Ascent 1000 "
        b"/Descent -200 /CapHeight 800 /StemV 80 >>\n"
        b"endobj\n"
    )

    # 10: Info dictionary
    objects[10] = (
        b"10 0 obj\n"
        b"<< /Title (Elengenix Report) /Author (Elengenix) "
        b"/Subject (Elengenix security assessment report) "
        b"/Producer (Elengenix PDF Engine 1.0) /Creator (Elengenix) "
        b"/Keywords (security, report, elengenix) >>\n"
        b"endobj\n"
    )

    # 11: XMP metadata stream
    objects[11] = (
        f"11 0 obj\n<< /Type /Metadata /Subtype /XML /Length {len(xmp_stream)} >>\nstream\n".encode("latin-1")
        + xmp_stream
        + b"\nendstream\nendobj\n"
    )

    # Assemble the PDF body.
    pdf = bytearray()
    pdf.extend(b"%PDF-1.4\n")
    pdf.extend(b"%\xe2\xe3\xcf\xd3\n")  # Binary marker comment

    offsets: dict[int, int] = {}
    for obj_num in sorted(objects.keys()):
        offsets[obj_num] = len(pdf)
        pdf.extend(objects[obj_num])

    # Cross-reference table.
    xref_offset = len(pdf)
    num_objects = max(objects.keys()) + 1
    pdf.extend(f"xref\n0 {num_objects}\n".encode("latin-1"))
    pdf.extend(b"0000000000 65535 f \n")
    for obj_num in range(1, num_objects):
        offset = offsets.get(obj_num, 0)
        pdf.extend(f"{offset:010d} 00000 n \n".encode("latin-1"))

    # Trailer.
    pdf.extend(
        f"trailer\n<< /Size {num_objects} /Root 1 0 R /Info 10 0 R >>\n"
        f"startxref\n{xref_offset}\n%%EOF\n".encode("latin-1")
    )

    return bytes(pdf)
