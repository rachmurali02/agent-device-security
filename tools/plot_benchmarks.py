#!/usr/bin/env python3
"""Draws docs/benchmarks/comparison.svg from benchmark runs.

Each bar is the median of the runs; the thin line through its end spans the
fastest to slowest run. Uses only the standard library.

Usage:
  target/release/quorum-bench --data docs/benchmarks/runs/run1.tsv   # x3
  tools/plot_benchmarks.py docs/benchmarks/runs/*.tsv > docs/benchmarks/comparison.svg
"""
import statistics
import sys
from html import escape

QUORUM, SOFT = "quorum-hsm", "SoftHSM2"

# Rows in the benchmark output that each panel draws.
SIGN = ("1. Signing a 64-byte message (raw signing)", {
    QUORUM: "quorum-hsm emulator via PKCS#11",
    SOFT: "SoftHSM2 via PKCS#11",
})
ACTION = ("3. Approving one agent action (\"pay $0.01 to shop.example\")", {
    QUORUM: "quorum-hsm emulator, spending saved with fsync (safe default)",
    SOFT: "SoftHSM2 + rules on the host, counters saved with fsync",
})
KEYGEN = ("2. Creating keys", {
    QUORUM: "quorum-hsm: general key via PKCS#11 (fsync)",
    SOFT: "SoftHSM2: key via PKCS#11",
})
THREADS = {
    QUORUM: "quorum-hsm emulator: raw signing via PKCS#11",
    SOFT: "SoftHSM2: raw signing via PKCS#11",
}
REFUSE = (ACTION[0], {
    QUORUM: "quorum-hsm emulator, refusing an action (refusal recorded in the audit log, saved with fsync)",
    SOFT: "SoftHSM2 + rules on the host, refusing an action (nothing recorded)",
})
ADMIN_WORK = [
    ("Create + delete agent key", KEYGEN[0],
     "quorum-hsm: agent key with 2-of-3 admin sign-off + birth certificate (create + delete pair)"),
    ("Change a key's rules", KEYGEN[0],
     "quorum-hsm: change an agent key's rules with 2-of-3 sign-off + new certificate"),
    ("Check 1,000 log entries", ACTION[0],
     "Auditor check: 1,000-entry audit log against a signed checkpoint (no HSM)"),
]
BREAKDOWN = [
    ("Rule check + signing", "quorum-hsm core, in process (no socket, no disk)"),
    ("+ socket, file write", "quorum-hsm emulator, fsync off (unsafe; shows cost of durability)"),
    ("+ 1 disk wait (now)", "quorum-hsm emulator, spending saved with fsync (safe default)"),
    ("+ 2 disk waits (before)", "quorum-hsm emulator, previous storage (rewrite + rename, two disk waits)"),
]


def load(paths):
    """{(section, option): [values per run]} where each value is a tuple of floats."""
    data = {}
    for path in paths:
        with open(path) as f:
            for line in f:
                parts = line.rstrip("\n").split("\t")
                key = (parts[0], parts[1])
                data.setdefault(key, []).append(parts[2:])
    return data


def series(data, section, option, col, scale=1.0):
    vals = [float(r[col]) * scale for r in data[(section, option)] if r[col] != ""]
    return statistics.median(vals), min(vals), max(vals)


def nice_max(v):
    """Rounds an axis maximum up to 1, 2 or 5 times a power of ten."""
    mag = 10 ** (len(str(int(v))) - 1) if v >= 1 else 1
    for m in (1, 2, 2.5, 5, 10):
        if v <= m * mag:
            return m * mag
    return 10 * mag


def fmt(v, unit):
    if unit == "µs":
        return "<1 µs" if v < 1 else f"{v:,.0f} µs"
    if unit == "ms":
        return f"{v:.1f} ms"
    if unit.startswith("of "):
        return f"{v:.0f} {unit}"
    return f"{v:,.0f}"


class Svg:
    W = 960
    PANEL_W, PANEL_H = 440, 190
    LEFT_LABEL = 150  # space for row labels inside a panel
    BAR_H, GAP = 16, 2

    def __init__(self):
        self.parts = []

    def add(self, s):
        self.parts.append(s)

    def bar(self, x, y, w, h, cls, title):
        """A horizontal bar anchored at the left baseline with a 4px rounded data end."""
        r = min(4, w / 2, h / 2)
        if w <= 0:
            return
        d = (f"M{x:.1f},{y:.1f} h{w - r:.1f} a{r},{r} 0 0 1 {r},{r} "
             f"v{h - 2 * r:.1f} a{r},{r} 0 0 1 -{r},{r} h-{w - r:.1f} z")
        self.add(f'<path class="{cls}" d="{d}"><title>{escape(title)}</title></path>')

    def panel(self, px, py, title, subtitle, rows, unit, note=None):
        """rows: [(label, series_class, (median, lo, hi) or None, value_text_override)]"""
        a = self.add
        a(f'<text class="t-title" x="{px}" y="{py + 14}">{escape(title)}</text>')
        a(f'<text class="t-sub" x="{px}" y="{py + 32}">{escape(subtitle)}</text>')
        plot_x = px + self.LEFT_LABEL
        plot_w = self.PANEL_W - self.LEFT_LABEL - 70  # room for value labels
        top = py + 50
        if unit.startswith("of "):
            vmax = int(unit[3:])
            steps = vmax // 2 if vmax % 2 == 0 and vmax <= 10 else vmax
        else:
            vmax = nice_max(max(hi for _, _, (m, lo, hi), _ in rows))
            lead = vmax / 10 ** (len(str(int(vmax))) - 1)
            steps = 4 if lead in (2, 20) else 5
        ticks = [vmax * i / steps for i in range(steps + 1)]
        n = len(rows)
        group_gap = 10
        groups = []
        for r in rows:
            if r[0] is not None and (not groups or groups[-1][0] != r[0]):
                groups.append([r[0], []])
            if r[0] is None:
                groups[-1][1].append(r)
            else:
                groups[-1][1].append(r)
        height = sum(len(g[1]) for g in groups) * (self.BAR_H + self.GAP) + (len(groups) - 1) * group_gap
        bottom = top + height
        # Gridlines and axis labels: recessive.
        for t in ticks:
            x = plot_x + plot_w * t / vmax
            a(f'<line class="grid" x1="{x:.1f}" y1="{top - 4}" x2="{x:.1f}" y2="{bottom + 2}"/>')
            # Units live in the subtitle, so ticks stay short.
            label = f"{t:,.0f}" if t == int(t) else f"{t:,.1f}"
            a(f'<text class="t-axis" x="{x:.1f}" y="{bottom + 16}" text-anchor="middle">{escape(label)}</text>')
        a(f'<line class="baseline" x1="{plot_x}" y1="{top - 4}" x2="{plot_x}" y2="{bottom + 2}"/>')
        y = top
        for gi, (glabel, grows) in enumerate(groups):
            if gi:
                y += group_gap
            for j, (_, cls, (m, lo, hi), text) in enumerate(grows):
                name = QUORUM if cls == "s1" else SOFT
                label = glabel if len(grows) == 1 else (f"{glabel}" if j == 0 else "")
                if len(grows) == 1:
                    a(f'<text class="t-label" x="{plot_x - 8}" y="{y + self.BAR_H - 4}" text-anchor="end">{escape(label)}</text>')
                elif j == 0:
                    mid = y + (len(grows) * (self.BAR_H + self.GAP) - self.GAP) / 2 + 4
                    a(f'<text class="t-label" x="{plot_x - 8}" y="{mid:.1f}" text-anchor="end">{escape(glabel)}</text>')
                w = plot_w * m / vmax
                tip = f"{name}: {fmt(m, unit)}"
                if hi > lo:
                    tip += f" (runs: {fmt(lo, unit)} to {fmt(hi, unit)})"
                self.bar(plot_x, y, w, self.BAR_H, cls, tip)
                if hi > lo:
                    x1, x2 = plot_x + plot_w * lo / vmax, plot_x + plot_w * hi / vmax
                    cy = y + self.BAR_H / 2
                    a(f'<line class="range" x1="{x1:.1f}" y1="{cy}" x2="{x2:.1f}" y2="{cy}"/>')
                    for xx in (x1, x2):
                        a(f'<line class="range" x1="{xx:.1f}" y1="{cy - 4}" x2="{xx:.1f}" y2="{cy + 4}"/>')
                vx = plot_x + plot_w * max(m, hi) / vmax + 6
                a(f'<text class="t-value" x="{vx:.1f}" y="{y + self.BAR_H - 4}">{escape(text or fmt(m, unit))}</text>')
                y += self.BAR_H + self.GAP
        end = bottom + 22
        if note:
            a(f'<text class="t-note" x="{px}" y="{bottom + 38}">{escape(note)}</text>')
            end = bottom + 44
        return end


STYLE = """
<style>
  svg { font-family: system-ui, -apple-system, "Segoe UI", sans-serif; }
  .bg { fill: #fcfcfb; }
  .s1 { fill: #2a78d6; } .s2 { fill: #eb6834; }
  .grid { stroke: #e1e0d9; stroke-width: 1; }
  .baseline { stroke: #c3c2b7; stroke-width: 1; }
  .range { stroke: #52514e; stroke-width: 1.25; }
  .t-h1 { fill: #0b0b0b; font-size: 20px; font-weight: 600; }
  .t-title { fill: #0b0b0b; font-size: 14px; font-weight: 600; }
  .t-sub, .t-legend { fill: #52514e; font-size: 12px; }
  .t-label { fill: #0b0b0b; font-size: 12px; }
  .t-value { fill: #0b0b0b; font-size: 12px; font-variant-numeric: tabular-nums; }
  .t-axis { fill: #898781; font-size: 11px; font-variant-numeric: tabular-nums; }
  .t-note { fill: #52514e; font-size: 11px; font-style: italic; }
  @media (prefers-color-scheme: dark) {
    .bg { fill: #1a1a19; }
    .s1 { fill: #3987e5; } .s2 { fill: #d95926; }
    .grid { stroke: #2c2c2a; }
    .baseline { stroke: #383835; }
    .range { stroke: #c3c2b7; }
    .t-h1, .t-title, .t-label, .t-value { fill: #f0efec; }
    .t-sub, .t-legend, .t-note { fill: #c3c2b7; }
  }
</style>
"""


def main(paths):
    data = load(paths)
    runs = len(paths)
    s = Svg()
    cols = [24, 24 + Svg.PANEL_W + 48]
    s.add('<rect class="bg" width="100%" height="100%"/>')
    s.add('<text class="t-h1" x="24" y="34">quorum-hsm vs SoftHSM2</text>')
    s.add(f'<text class="t-sub" x="24" y="54">Same Ed25519 workload through the same PKCS#11 code. '
          f'Bars: median of {runs} runs; thin line: fastest to slowest run.</text>')
    # Legend (two series: always present, plus direct row labels).
    lx = 24
    for cls, label in (("s1", "quorum-hsm: rules enforced inside the HSM"),
                       ("s2", "SoftHSM2: the usual setup, rules checked on the computer")):
        s.add(f'<rect class="{cls}" x="{lx}" y="66" width="12" height="12" rx="3"/>')
        s.add(f'<text class="t-legend" x="{lx + 18}" y="76">{escape(label)}</text>')
        lx += 330

    def pair(sec_opts, col, scale=1.0):
        sec, opts = sec_opts
        return [
            (QUORUM, "s1", series(data, sec, opts[QUORUM], col, scale), None),
            (SOFT, "s2", series(data, sec, opts[SOFT], col, scale), None),
        ]

    panels = []
    panels.append(("Sign a message", "Median time in µs, lower is better", pair(SIGN, 0), "µs", None))
    panels.append(("Approve one agent action, saved safely", "Median time in µs, lower is better",
                   pair(ACTION, 0), "µs",
                   "Both save to disk; SoftHSM2's rule check runs on the computer and can be skipped."))
    panels.append(("Create a key", "Median time in ms, lower is better",
                   pair(KEYGEN, 0, 1 / 1000), "ms", None))

    names = sorted({name for (sec, name) in data if sec == "attack"})

    def blocked(idx):
        per_run = [sum(int(data[("attack", n)][run][idx] or 0) for n in names) for run in range(runs)]
        return statistics.median(per_run), min(per_run), max(per_run)

    soft_blocks = [n for n in names
                   if all(r[1] == "1" for r in data[("attack", n)])]
    note = ("The one SoftHSM2 blocks: " + soft_blocks[0][:1].lower() + soft_blocks[0][1:] + "."
            if len(soft_blocks) == 1 else None)
    panels.append(("Attacks blocked",
                   f"{len(names)} attacks by someone who controls the computer and knows the PIN",
                   [(QUORUM, "s1", blocked(0), None), (SOFT, "s2", blocked(1), None)],
                   f"of {len(names)}", note))

    thread_rows = []
    for label, col in (("1 thread", 0), ("4 threads", 1)):
        for name, cls in ((QUORUM, "s1"), (SOFT, "s2")):
            thread_rows.append((label, cls, series(data, "threads", THREADS[name], col), None))
    panels.append(("Signatures per second", "Higher is better", thread_rows, "ops",
                   "Our emulator does one command at a time, like a single-core chip."))
    sec = ACTION[0]
    panels.append(("Where an agent action's time goes (quorum-hsm)",
                   "Median time in µs; two-slot storage needs one disk wait, not two",
                   [(label, "s1", series(data, sec, opt, 0), None) for label, opt in BREAKDOWN], "µs",
                   "Disk waits make sure a power cut can't lose a counted payment."))

    panels.append(("Refuse an action", "Median time in µs, lower is better",
                   pair(REFUSE, 0), "µs",
                   "Ours saves every refusal in a tamper-evident log; SoftHSM2 records nothing."))
    panels.append(("Admin and audit work (quorum-hsm)",
                   "Median time in ms; rare operations, each needing 2 of 3 admins",
                   [(label, "s1", series(data, sec, opt, 0, 1 / 1000), None)
                    for label, sec, opt in ADMIN_WORK], "ms",
                   "The audit check runs anywhere: no HSM needed."))

    # Two panels per row; each row starts below the taller panel above it.
    y = 100
    for k in range(0, len(panels), 2):
        ends = [s.panel(cols[c], y, *panels[k + c]) for c in range(2) if k + c < len(panels)]
        y = max(ends) + 24
    height = y

    body = "\n".join(s.parts)
    print(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {Svg.W} {height}" '
          f'width="{Svg.W}" height="{height}" role="img" '
          f'aria-label="Benchmark comparison of quorum-hsm and SoftHSM2">{STYLE}{body}</svg>')


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    main(sys.argv[1:])
