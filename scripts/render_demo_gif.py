"""Render docs/assets/demo.gif from a live run of the injection demo.

Runs examples/injection-demo/agent.py twice (without and with the
gateway), captures its real colored output, and animates it as a
terminal recording. Nothing in the GIF is hand-typed.

    pip install pillow
    python scripts/render_demo_gif.py [--out docs/assets/demo.gif] [--font PATH]
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
AGENT = ROOT / "examples" / "injection-demo" / "agent.py"

COLS, ROWS = 100, 21
FONT_SIZE = 15
PAD_X, PAD_Y, TITLE_H = 18, 14, 30

BG = (13, 17, 23)
FG = (201, 209, 217)
DIM = (110, 118, 129)
COLORS = {
    30: (13, 17, 23), 31: (255, 123, 114), 32: (63, 185, 80), 33: (210, 153, 34),
    36: (57, 197, 207), 97: (255, 255, 255),
}
BG_COLORS = {41: (180, 35, 24), 42: (46, 160, 67)}

FONT_CANDIDATES = [
    ("C:/Windows/Fonts/consola.ttf", "C:/Windows/Fonts/consolab.ttf"),
    ("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
     "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"),
    ("/System/Library/Fonts/Menlo.ttc", "/System/Library/Fonts/Menlo.ttc"),
]

SGR = re.compile(r"\033\[([0-9;]*)m")


@dataclass
class Span:
    text: str
    fg: tuple[int, int, int]
    bg: tuple[int, int, int] | None
    bold: bool


def parse_ansi(line: str) -> list[Span]:
    spans: list[Span] = []
    fg, bg, bold, pos = FG, None, False, 0
    for match in SGR.finditer(line):
        if match.start() > pos:
            spans.append(Span(line[pos:match.start()], fg, bg, bold))
        for code in [int(c) for c in (match.group(1) or "0").split(";") if c]:
            if code == 0:
                fg, bg, bold = FG, None, False
            elif code == 1:
                bold = True
            elif code == 2:
                fg = DIM
            elif code in COLORS:
                fg = COLORS[code]
            elif code in BG_COLORS:
                bg = BG_COLORS[code]
        pos = match.end()
    if pos < len(line):
        spans.append(Span(line[pos:], fg, bg, bold))
    return spans


def run_demo(extra: list[str]) -> list[str]:
    env = {**os.environ, "FORCE_COLOR": "1", "PYTHONIOENCODING": "utf-8"}
    out = subprocess.run(  # noqa: S603  # nosec B603
        [sys.executable, str(AGENT), *extra],
        capture_output=True, env=env, check=True, timeout=60, cwd=ROOT,
    ).stdout.decode("utf-8")
    return out.splitlines()


class Terminal:
    def __init__(self, regular: ImageFont.FreeTypeFont, bold: ImageFont.FreeTypeFont) -> None:
        self.regular, self.bold = regular, bold
        self.cell_w = regular.getlength("M")
        ascent, descent = regular.getmetrics()
        self.cell_h = ascent + descent + 4
        self.width = int(PAD_X * 2 + self.cell_w * COLS)
        self.height = int(TITLE_H + PAD_Y * 2 + self.cell_h * ROWS)
        self.lines: list[str] = []

    def render(self) -> Image.Image:
        img = Image.new("RGB", (self.width, self.height), BG)
        draw = ImageDraw.Draw(img)
        draw.rectangle([0, 0, self.width, TITLE_H], fill=(22, 27, 34))
        for i, color in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
            cx = 18 + i * 20
            draw.ellipse([cx - 6, TITLE_H // 2 - 6, cx + 6, TITLE_H // 2 + 6], fill=color)
        title = "secure-agent-gateway: prompt-injection demo"
        tw = self.regular.getlength(title)
        draw.text(((self.width - tw) / 2, 7), title, font=self.regular, fill=DIM)
        for row, line in enumerate(self.lines[-ROWS:]):
            x = PAD_X
            y = TITLE_H + PAD_Y + row * self.cell_h
            for span in parse_ansi(line):
                w = self.cell_w * len(span.text)
                if span.bg:
                    draw.rectangle([x, y - 1, x + w, y + self.cell_h - 3], fill=span.bg)
                font = self.bold if span.bold else self.regular
                draw.text((x, y), span.text, font=font, fill=span.fg)
                x += w
        return img


def load_fonts(path: str | None) -> tuple[ImageFont.FreeTypeFont, ImageFont.FreeTypeFont]:
    pairs = [(path, path)] if path else FONT_CANDIDATES
    for regular, bold in pairs:
        if regular and Path(regular).exists():
            bold_path = bold if bold and Path(bold).exists() else regular
            return (ImageFont.truetype(regular, FONT_SIZE),
                    ImageFont.truetype(bold_path, FONT_SIZE))
    raise SystemExit("no monospace font found; pass --font /path/to/mono.ttf")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=str(ROOT / "docs" / "assets" / "demo.gif"))
    parser.add_argument("--font")
    args = parser.parse_args()

    term = Terminal(*load_fonts(args.font))
    frames: list[Image.Image] = []
    durations: list[int] = []

    def snap(ms: int) -> None:
        frames.append(term.render())
        durations.append(ms)

    prompt = "\033[1;32m$\033[0m "
    scenes = [
        ("python examples/injection-demo/agent.py", []),
        ("python examples/injection-demo/agent.py --protected", ["--protected"]),
    ]
    for index, (command, extra) in enumerate(scenes):
        output = run_demo(extra)
        term.lines = [prompt]
        snap(500)
        for i in range(0, len(command), 3):
            term.lines[-1] = prompt + command[: i + 3]
            snap(45)
        snap(450)
        for line in output:
            term.lines.append(line)
            pause = 900 if "RESULT" in line else 600 if "BLOCKED" in line else 380
            snap(pause)
        snap(3200 if index == len(scenes) - 1 else 2600)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    palette_frames = [f.quantize(colors=64, method=Image.Quantize.MEDIANCUT) for f in frames]
    palette_frames[0].save(
        out, save_all=True, append_images=palette_frames[1:], duration=durations,
        loop=0, optimize=True, disposal=1,
    )
    print(f"wrote {out} ({out.stat().st_size // 1024} KiB, {len(frames)} frames)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
