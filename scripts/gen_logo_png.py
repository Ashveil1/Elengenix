#!/usr/bin/env python3
"""Generate a PNG logo that looks exactly like the TUI startup screen."""

from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

OUT = Path(__file__).resolve().parents[1] / "assets"
OUT.mkdir(exist_ok=True)

# The exact ASCII art from ui_components.py
ascii_art = [
    "███████╗██╗     ███████╗███╗   ██╗ ██████╗ ███████╗███╗   ██╗██╗██╗  ██╗",
    "██╔════╝██║     ██╔════╝████╗  ██║██╔════╝ ██╔════╝████╗  ██║██║╚██╗██╔╝",
    "█████╗  ██║     █████╗  ██╔██╗ ██║██║  ███╗█████╗  ██╔██╗ ██║██║ ╚███╔╝ ",
    "██╔══╝  ██║     ██╔══╝  ██║╚██╗██║██║   ██║██╔══╝  ██║╚██╗██║██║ ██╔██╗ ",
    "███████╗███████╗███████╗██║ ╚████║╚██████╔╝███████╗██║ ╚████║██║██╔╝ ██╗",
    "╚══════╝╚══════╝╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝",
]

# Fonts
FONT_BOLD = "/usr/share/fonts/TTF/JetBrainsMonoNerdFontMono-Bold.ttf"
FONT_REG = "/usr/share/fonts/TTF/JetBrainsMonoNLNerdFont-Regular.ttf"

# Try to find a good monospace font
for p in [
    FONT_BOLD,
    "/usr/share/fonts/TTF/JetBrainsMonoNLNerdFontMono-Bold.ttf",
    "/usr/share/fonts/liberation/LiberationMono-Bold.ttf",
    "/usr/share/fonts/noto/NotoSansMono-Bold.ttf",
]:
    if Path(p).exists():
        FONT_BOLD = p
        break

for p in [
    FONT_REG,
    "/usr/share/fonts/TTF/JetBrainsMonoNLNerdFontMono-Regular.ttf",
    "/usr/share/fonts/liberation/LiberationMono-Regular.ttf",
    "/usr/share/fonts/noto/NotoSansMono-Regular.ttf",
]:
    if Path(p).exists():
        FONT_REG = p
        break

# Sizes
ASCII_SIZE = 16
SUB_SIZE = 12
CTRL_R = 7
CTRL_GAP = 12
MARGIN_LEFT = 30
MARGIN_TOP = 50
LINE_H = int(ASCII_SIZE * 1.35)

# Colors
BG = (13, 13, 13)  # #0d0d0d
WHITE = (255, 255, 255)  # #ffffff
DIM = (136, 136, 136)  # #888888
RED = (255, 95, 87)  # macOS close
YEL = (255, 189, 46)  # macOS minimize
GRN = (39, 201, 63)  # macOS maximize
BORDER = (40, 40, 40)  # subtle border

font_ascii = ImageFont.truetype(FONT_BOLD, ASCII_SIZE)
font_sub = ImageFont.truetype(FONT_REG, SUB_SIZE)

# Measure text widths
dummy = Image.new("RGB", (1, 1))
draw = ImageDraw.Draw(dummy)

ascii_w = max(draw.textlength(line, font=font_ascii) for line in ascii_art)
sub1 = "           Universal AI & Bug Bounty Agent"
sub2 = "           Type /help for commands"
sub1_w = draw.textlength(sub1, font=font_sub)
sub2_w = draw.textlength(sub2, font=font_sub)

total_w = int(max(ascii_w, sub1_w, sub2_w) + MARGIN_LEFT * 2 + 20)
ctrl_y = 18

# Calculate height
ascii_h = len(ascii_art) * LINE_H
total_h = MARGIN_TOP + ascii_h + 20 + SUB_SIZE * 2 + 40

# Create image
img = Image.new("RGB", (total_w, total_h), BG)
draw = ImageDraw.Draw(img)

# Draw border
draw.rectangle([0, 0, total_w - 1, total_h - 1], outline=BORDER, width=1)

# Draw macOS window controls
ctrl_x = MARGIN_LEFT
draw.ellipse([ctrl_x, ctrl_y, ctrl_x + CTRL_R * 2, ctrl_y + CTRL_R * 2], fill=RED)
draw.ellipse(
    [ctrl_x + CTRL_GAP + CTRL_R * 2, ctrl_y, ctrl_x + CTRL_GAP + CTRL_R * 4, ctrl_y + CTRL_R * 2],
    fill=YEL,
)
draw.ellipse(
    [
        ctrl_x + CTRL_GAP * 2 + CTRL_R * 4,
        ctrl_y,
        ctrl_x + CTRL_GAP * 2 + CTRL_R * 6,
        ctrl_y + CTRL_R * 2,
    ],
    fill=GRN,
)

# Draw ASCII art
y = MARGIN_TOP
for line in ascii_art:
    draw.text((MARGIN_LEFT, y), line, font=font_ascii, fill=WHITE)
    y += LINE_H

# Draw subtitles
y += 15
draw.text((MARGIN_LEFT, y), sub1, font=font_sub, fill=DIM)
y += SUB_SIZE + 8
draw.text((MARGIN_LEFT, y), sub2, font=font_sub, fill=DIM)

# Save
out_path = OUT / "elengenix_banner.png"
img.save(str(out_path), "PNG")
print(f"PNG saved to {out_path}")
print(f"Size: {total_w}x{total_h}")
