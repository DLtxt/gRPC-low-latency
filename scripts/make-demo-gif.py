#!/usr/bin/env python3
"""Render the README demo GIF.

Draws a terminal session frame by frame rather than screen-recording one, so the result
is deterministic, diffable in review, and reproducible on any machine with Pillow — no
capture tooling, no window manager, no retakes.

Every line of output here is copied from a real run of this project. The script types
commands at a readable cadence and holds on each result long enough to read it.

    ./scripts/make-demo-gif.py [-o docs/demo.gif]
"""

from __future__ import annotations

import argparse
import pathlib

from PIL import Image, ImageDraw, ImageFont

# --- appearance ---------------------------------------------------------------------
W, H = 920, 560
PAD = 22
LINE = 21
FONT_PATH = "/System/Library/Fonts/Menlo.ttc"
FONT_SIZE = 14

BG = (13, 17, 23)          # GitHub dark, so the GIF sits naturally in the README
CHROME = (22, 27, 34)
FG = (201, 209, 217)
DIM = (110, 118, 129)
GREEN = (63, 185, 80)
CYAN = (57, 197, 207)
YELLOW = (210, 168, 63)
RED = (248, 81, 73)
PURPLE = (188, 140, 255)

PROMPT = "$ "

# Frame counts at ~20 fps.
HOLD_SHORT = 10
HOLD_LONG = 34
TYPE_EVERY = 2   # frames per typed character


def colour_for(line: str) -> tuple[int, int, int]:
    """Colour a line by what it is, so the eye can find the result quickly."""
    s = line.strip()
    if s.startswith("#"):
        return DIM
    if "PermissionDenied" in s or "ERROR" in s or s.startswith("Code:"):
        return RED
    if any(k in s for k in ("signature", "valid", "OK]", "healthy", "up ")):
        return GREEN
    if s.startswith(("Grafana:", "Prometheus:", "gRPC:", "make ")):
        return CYAN
    if "QPS" in s or "p99" in s or "req/s" in s:
        return YELLOW
    return FG


# --- the session --------------------------------------------------------------------
# Real output. Throughput and latency figures come from the two-host reference run
# recorded in results/reference/.
SESSION = [
    ("cmd", "make up"),
    ("out", [
        "  stack is up.",
        "    Grafana:     http://localhost:3000   (dashboard is pre-loaded)",
        "    Prometheus:  http://localhost:9090",
        "    gRPC:        localhost:50051  (mTLS; client certs in ./certs)",
    ]),
    ("hold", HOLD_LONG),

    ("cmd", "# sign with the 'payments' identity"),
    ("cmd", "grpcurl -cert certs/payments.crt -key certs/payments.key \\"),
    ("cmd", "  -d @ localhost:50051 hsm.v1.HsmService/Sign"),
    ("out", [
        "{",
        '  "signature": "O+8WrcspIqTLXWJyeWEVfzs8W7kAmOpN9RI9osvIDu8...",',
        '  "keyLabel": "demo-ec-p256"',
        "}",
    ]),
    ("hold", HOLD_LONG),

    ("cmd", "# 'batch' is not permitted to use the RSA key"),
    ("cmd", "grpcurl -cert certs/batch.crt -key certs/batch.key \\"),
    ("cmd", "  -d @ localhost:50051 hsm.v1.HsmService/Sign"),
    ("out", [
        "ERROR:",
        "  Code: PermissionDenied",
        "  Message: identity 'spiffe://local/ns/default/sa/batch' is not",
        "           permitted to sign key 'demo-rsa-2048'",
    ]),
    ("hold", HOLD_LONG),

    ("cmd", "make bench"),
    ("out", [
        "offered   accepted   shed%    acc p50     acc p99",
        "--------------------------------------------------",
        "4000      24000        0%    0.29ms      0.48ms",
        "8000      48000        0%    0.29ms      0.49ms",
        "12000     72000        0%    0.31ms      0.56ms",
        "16000     96000        0%    0.34ms      0.76ms",
        "20000     119978       0%    0.42ms      1.15ms",
        "",
        "RESULT: 20,000 QPS sustained with p99 < 2.0 ms",
    ]),
    ("hold", HOLD_LONG + 30),
]


def draw_frame(font, header_font, lines: list[tuple[str, tuple[int, int, int]]],
               cursor: bool) -> Image.Image:
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)

    # Window chrome, so it reads as a terminal at a glance.
    d.rectangle([0, 0, W, 30], fill=CHROME)
    for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse([16 + i * 18, 11, 26 + i * 18, 21], fill=c)
    d.text((W // 2 - 78, 8), "gRPC-low-latency", font=header_font, fill=DIM)

    # Only the lines that fit, newest last.
    visible = (H - 30 - PAD) // LINE
    for i, (text, colour) in enumerate(lines[-visible:]):
        d.text((PAD, 38 + i * LINE), text, font=font, fill=colour)

    if cursor and lines:
        y = 38 + (len(lines[-visible:]) - 1) * LINE
        x = PAD + int(d.textlength(lines[-1][0], font=font))
        d.rectangle([x + 1, y + 2, x + 8, y + 16], fill=GREEN)

    return img


def build(out_path: pathlib.Path) -> None:
    font = ImageFont.truetype(FONT_PATH, FONT_SIZE)
    header_font = ImageFont.truetype(FONT_PATH, 12)

    frames: list[Image.Image] = []
    lines: list[tuple[str, tuple[int, int, int]]] = []

    for kind, payload in SESSION:
        if kind == "cmd":
            is_comment = payload.strip().startswith("#")
            # Type it out. A comment appears whole: watching a comment being typed is
            # slow and tells the viewer nothing.
            if is_comment:
                lines.append((PROMPT + payload, DIM))
                frames.extend([draw_frame(font, header_font, lines, True)] * 8)
            else:
                lines.append((PROMPT, FG))
                for i in range(1, len(payload) + 1):
                    lines[-1] = (PROMPT + payload[:i], PURPLE)
                    frames.extend([draw_frame(font, header_font, lines, True)] * TYPE_EVERY)
                frames.extend([draw_frame(font, header_font, lines, True)] * 4)

        elif kind == "out":
            for line in payload:
                lines.append((line, colour_for(line)))
                frames.extend([draw_frame(font, header_font, lines, False)] * 2)
            frames.extend([draw_frame(font, header_font, lines, False)] * HOLD_SHORT)

        elif kind == "hold":
            frames.extend([draw_frame(font, header_font, lines, True)] * payload)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    frames[0].save(
        out_path,
        save_all=True,
        append_images=frames[1:],
        duration=50,          # ~20 fps
        loop=0,
        optimize=True,
    )
    size_mb = out_path.stat().st_size / 1e6
    print(f"wrote {out_path} — {len(frames)} frames, {size_mb:.2f} MB")
    if size_mb > 10:
        print("  warning: large for a README; consider trimming holds")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("-o", "--out", default="docs/demo.gif", type=pathlib.Path)
    args = ap.parse_args()
    build(args.out)
