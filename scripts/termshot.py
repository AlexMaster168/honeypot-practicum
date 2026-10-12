"""Render captured terminal output into terminal-style PNGs for docs/screenshots.

    python scripts/termshot.py <capture.txt> <out_dir> [--prefix stage2]

The capture is split on "### <name>" lines (see attacker/*-smoke.sh); each section becomes
<out_dir>/<prefix>-<name>.png. Pass --single NAME to render the whole file as one image.
"""
import argparse
import re
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
BG, FG, PROMPT, TITLE_BG = "#1e1f29", "#e6e6e6", "#50fa7b", "#2b2d3a"
FONT_CANDIDATES = [
    r"C:\Windows\Fonts\consola.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
]


def load_font(size):
    for f in FONT_CANDIDATES:
        if Path(f).exists():
            return ImageFont.truetype(f, size)
    return ImageFont.load_default()


def render(lines, title, out, font_size=16, max_cols=150):
    font = load_font(font_size)
    lines = [ANSI.sub("", l.rstrip()).expandtabs(4)[:max_cols] for l in lines]
    while lines and not lines[-1]:
        lines.pop()
    cw = font.getbbox("M")[2]
    lh = int(font_size * 1.35)
    pad, bar = 18, 34
    w = max(560, pad * 2 + cw * max([len(l) for l in lines] + [len(title) + 10]))
    h = bar + pad * 2 + lh * len(lines)
    img = Image.new("RGB", (w, h), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, w, bar], fill=TITLE_BG)
    for i, c in enumerate(["#ff5555", "#f1fa8c", "#50fa7b"]):
        d.ellipse([14 + i * 22, 11, 26 + i * 22, 23], fill=c)
    d.text((90, 8), title, font=font, fill="#9aa0b4")
    y = bar + pad
    for l in lines:
        d.text((pad, y), l, font=font, fill=PROMPT if l.startswith("$ ") else FG)
        y += lh
    img.save(out)
    print(f"{out}  ({w}x{h})")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("capture")
    ap.add_argument("out_dir")
    ap.add_argument("--prefix", default="shot")
    ap.add_argument("--title", default="kali@kali: ~")
    ap.add_argument("--single")
    a = ap.parse_args()
    text = Path(a.capture).read_text(encoding="utf-8-sig", errors="replace").splitlines()
    out = Path(a.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    if a.single:
        render(text, a.title, out / f"{a.prefix}-{a.single}.png")
        return
    sections, name = {}, None
    for l in text:
        m = re.match(r"^### (\S+)", l)
        if m:
            name = m.group(1)
            sections[name] = []
        elif name:
            sections[name].append(l)
    for name, lines in sections.items():
        render(lines, a.title, out / f"{a.prefix}-{name}.png")


if __name__ == "__main__":
    main()
