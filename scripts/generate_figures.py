"""Generate diagrams and genuine captured CLI output screenshots for reports/figures/."""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.dates as mdates
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
from PIL import Image, ImageDraw, ImageFont

ROOT_DIR = Path(__file__).resolve().parent.parent
FIGURES_DIR = ROOT_DIR / "reports" / "figures"
MONO_FONT_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"


def render_attack_chain_diagram(output_path: Path) -> Path:
    """Render a clean 6-stage attack-chain flowchart PNG for PDF/DOCX and Markdown reports."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(12.5, 5.2))
    ax.set_xlim(0, 12.5)
    ax.set_ylim(0, 5.2)
    ax.axis("off")

    stages = [
        ("Stage 1\nRecon & Staging", "2026-11-16 to 11-18\nLookalike domains\nasteri0nfin.example", "#334155", 0.4, 2.8),
        ("Stage 2\nPhishing & Spoofing", "08:42–09:04 UTC\nPHISH-01, 02, 03\nSpoofed portal links", "#1d4ed8", 4.4, 2.8),
        ("Stage 3\nInitial Compromise", "09:14:48–09:15:22 UTC\ninvoice_viewer.exe\n(Harmless Sim)", "#b45309", 8.4, 2.8),
        ("Stage 4\nUnauthorized Access", "09:18:10–09:41:00 UTC\nSES-9941-HYDRA\nIP 203.0.113.95", "#be123c", 8.4, 0.5),
        ("Stage 5\nFinancial Laundering", "09:45:12–10:11:15 UTC\nINR 450K UPI/IMPS\nMules + Sim Crypto", "#7f1d1d", 4.4, 0.5),
        ("Stage 6\nDetection & Containment", "10:15:00–10:30:00 UTC\nINR 200K Frozen\nSHA-256 + CERT-In", "#15803d", 0.4, 0.5),
    ]

    box_w, box_h = 3.5, 1.55
    for title, body, color, x, y in stages:
        patch = FancyBboxPatch(
            (x, y),
            box_w,
            box_h,
            boxstyle="round,pad=0.12,rounding_size=0.15",
            facecolor=color,
            edgecolor="#0f172a",
            linewidth=1.3,
        )
        ax.add_patch(patch)
        ax.text(
            x + box_w / 2,
            y + box_h - 0.38,
            title,
            ha="center",
            va="center",
            color="white",
            fontsize=9.5,
            fontweight="bold",
        )
        ax.text(
            x + box_w / 2,
            y + 0.48,
            body,
            ha="center",
            va="center",
            color="#f8fafc",
            fontsize=8.0,
        )

    # Arrows connecting 1 -> 2 -> 3 -> 4 -> 5 -> 6
    arrows = [
        ((3.95, 3.58), (4.35, 3.58)),
        ((7.95, 3.58), (8.35, 3.58)),
        ((10.15, 2.72), (10.15, 2.15)),
        ((8.35, 1.28), (7.95, 1.28)),
        ((4.35, 1.28), (3.95, 1.28)),
    ]
    for start, end in arrows:
        ax.annotate(
            "",
            xy=end,
            xytext=start,
            arrowprops={"arrowstyle": "-|>", "lw": 2.2, "color": "#1e293b"},
        )

    ax.text(
        6.25,
        4.85,
        "Operation Hydra — Six-Stage Multi-Vector Attack & Response Chain (UTC)",
        ha="center",
        va="center",
        fontsize=12.5,
        fontweight="bold",
        color="#0f172a",
    )
    plt.tight_layout()
    fig.savefig(output_path, dpi=180, bbox_inches="tight")
    plt.close(fig)
    return output_path


def render_timeline_chart(timeline_json_path: Path, output_path: Path) -> Path:
    """Plot the 20 November 2026 active operational timeline directly from timeline.json."""
    data = json.loads(timeline_json_path.read_text(encoding="utf-8"))
    events = [
        ev for ev in data["timeline"] if ev["timestamp_utc"].startswith("2026-11-20")
    ]

    layer_order = [
        ("authentication", "Authentication / SOC"),
        ("financial_crypto_sim", "Simulated Crypto"),
        ("financial_fiat", "Banking (UPI/IMPS/NEFT)"),
        ("endpoint_simulation", "Endpoint Simulator"),
        ("network", "Network Sensor"),
        ("email", "Email Gateway"),
    ]
    layer_y = {key: idx for idx, (key, _) in enumerate(layer_order)}
    layer_colors = {
        "email": "#2563eb",
        "network": "#7c3aed",
        "endpoint_simulation": "#d97706",
        "financial_fiat": "#dc2626",
        "financial_crypto_sim": "#7f1d1d",
        "authentication": "#059669",
    }

    fig, ax = plt.subplots(figsize=(13.5, 5.6))
    times = [datetime.fromisoformat(ev["timestamp_utc"].replace("Z", "+00:00")) for ev in events]
    base_ys = [layer_y[ev["source_layer"]] for ev in events]
    # Add gentle vertical jitter when multiple endpoint events cluster within seconds
    endpoint_offsets = {
        "EVT-EP-001": -0.14,
        "EVT-EP-002": -0.07,
        "EVT-EP-003": 0.0,
        "EVT-EP-004": 0.07,
        "EVT-EP-005": 0.14,
    }
    ys = [y + endpoint_offsets.get(ev["evidence_ref"], 0.0) for ev, y in zip(events, base_ys)]
    colors = [layer_colors[ev["source_layer"]] for ev in events]

    ax.scatter(times, ys, c=colors, s=85, edgecolors="#0f172a", linewidths=0.9, zorder=3)

    # Annotate key forensic milestones
    highlights = {
        "phishing-01.eml": ("PHISH-01", (0, 12)),
        "EVT-EP-001": ("Decoy Opened", (-14, -22)),
        "EVT-EP-005": ("Beacon\n09:15:22Z", (10, 14)),
        "AUTH-005": ("SES-9941-HYDRA", (-10, -18)),
        "AUTH-006": ("PAY-REQ-7721", (0, 14)),
        "TXN-001": ("TXN-001\nINR 450K", (-15, 14)),
        "WLT-SIM-002": ("Exit Wallet", (-12, 13)),
        "AUTH-007": ("Detected\n10:15Z", (-18, 15)),
        "AUTH-008": ("Contained\n10:20Z", (-12, -26)),
    }
    for ev, dt, y in zip(events, times, ys):
        ref = ev["evidence_ref"]
        if ref in highlights:
            label, offset = highlights[ref]
            ax.annotate(
                label,
                xy=(dt, y),
                xytext=offset,
                textcoords="offset points",
                fontsize=7.6,
                fontweight="bold",
                color="#0f172a",
                arrowprops={"arrowstyle": "-", "color": "#64748b", "lw": 0.8},
            )

    ax.set_yticks(range(len(layer_order)))
    ax.set_yticklabels([label for _, label in layer_order], fontsize=9.5, fontweight="bold")
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M UTC"))
    ax.grid(axis="both", linestyle="--", alpha=0.45)
    ax.set_ylim(-0.9, len(layer_order) - 0.2)
    ax.set_title(
        "Operation Hydra — Multi-Source Incident Timeline (20 November 2026, 28 Active-Day Events)",
        fontsize=12,
        fontweight="bold",
        pad=12,
    )
    ax.set_xlabel("Time (UTC)", fontsize=10)
    plt.tight_layout()
    fig.savefig(output_path, dpi=180, bbox_inches="tight")
    plt.close(fig)
    return output_path


def render_terminal_screenshot(
    commands: list[list[str]],
    title: str,
    output_path: Path,
) -> Path:
    """Execute commands and render their genuine captured stdout as a terminal screenshot PNG."""
    lines: list[str] = []
    for cmd in commands:
        display_cmd = " ".join(
            "python" if part == sys.executable else part for part in cmd
        )
        lines.append(f"$ {display_cmd}")
        proc = subprocess.run(
            cmd,
            cwd=ROOT_DIR,
            capture_output=True,
            text=True,
            check=True,
        )
        for line in proc.stdout.rstrip().splitlines():
            lines.append(line)
        lines.append("")

    font = ImageFont.truetype(MONO_FONT_PATH, 14)
    line_height = 20
    padding_x = 22
    header_h = 36
    max_chars = max((len(line) for line in lines), default=60)
    width = max(780, int(max_chars * 8.6) + padding_x * 2)
    height = header_h + len(lines) * line_height + 24

    img = Image.new("RGB", (width, height), color=(17, 24, 39))
    draw = ImageDraw.Draw(img)

    # Window title bar
    draw.rectangle([(0, 0), (width, header_h)], fill=(31, 41, 55))
    for idx, dot_color in enumerate([(239, 68, 68), (245, 158, 11), (34, 197, 94)]):
        cx = 18 + idx * 18
        draw.ellipse([(cx - 5, 13), (cx + 5, 23)], fill=dot_color)
    draw.text((80, 10), title, fill=(229, 231, 235), font=font)

    y = header_h + 12
    for line in lines:
        if line.startswith("$ "):
            color = (96, 165, 250)
        elif "PASSED" in line or "[VERIFIED]" in line or "passed" in line:
            color = (74, 222, 128)
        elif line.startswith("==="):
            color = (250, 204, 21)
        else:
            color = (229, 231, 235)
        draw.text((padding_x, y), line, fill=color, font=font)
        y += line_height

    output_path.parent.mkdir(parents=True, exist_ok=True)
    img.save(output_path)
    return output_path


def main() -> int:
    render_attack_chain_diagram(FIGURES_DIR / "attack-chain-diagram.png")
    render_timeline_chart(
        ROOT_DIR / "reports" / "generated" / "timeline.json",
        FIGURES_DIR / "timeline-sequence.png",
    )
    render_terminal_screenshot(
        commands=[
            [sys.executable, "scripts/verify_evidence.py"],
            [sys.executable, "scripts/analyze_campaign.py"],
        ],
        title="Operation Hydra — Evidence Verification & Offline Pipeline Execution",
        output_path=FIGURES_DIR / "cli-pipeline-screenshot.png",
    )
    render_terminal_screenshot(
        commands=[[sys.executable, "-m", "pytest", "-v"]],
        title="Operation Hydra — Automated Pytest Verification Suite",
        output_path=FIGURES_DIR / "pytest-verification-screenshot.png",
    )
    print(f"[OK] Generated diagrams and genuine CLI screenshots in {FIGURES_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
