#!/usr/bin/env python3
"""Draws docs/experiments/load.svg from `quorum-lab load --data` output.

Three panels: throughput as clients are added, waiting time as clients are
added (approved payments), and how much other clients slow an ordinary one.
Same colours and styles as tools/plot_benchmarks.py. Standard library only.

Usage:
  target/release/quorum-lab load --data docs/experiments/load.tsv
  tools/plot_load.py docs/experiments/load.tsv > docs/experiments/load.svg
"""
import sys
from html import escape

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from plot_benchmarks import STYLE, nice_max  # noqa: E402

EXTRA_STYLE = STYLE.replace("</style>", """
  .l1 { stroke: #2a78d6; } .l2 { stroke: #eb6834; }
  .line { fill: none; stroke-width: 2; stroke-linejoin: round; stroke-linecap: round; }
  .dash { stroke-dasharray: 6 4; }
  .dot { stroke: #fcfcfb; stroke-width: 2; }
  @media (prefers-color-scheme: dark) {
    .l1 { stroke: #3987e5; } .l2 { stroke: #d95926; }
    .dot { stroke: #1a1a19; }
  }
</style>""")

NOISY = [
    ("none", "Nobody else (baseline)"),
    ("idle", "200 idle connections"),
    ("unauth", "8 flooding, no PIN"),
    ("slowloris", "100 half-sent requests"),
    ("garbage", "8 sending garbage"),
    ("refusals", "8 with PIN: refused actions"),
    ("payments", "8 with PIN: payments"),
]


def load(path):
    sweep, noisy = {}, {}
    with open(path) as f:
        for line in f:
            p = line.rstrip("\n").split("\t")
            if p[0] == "sweep":
                sweep.setdefault(p[1], []).append(
                    (int(p[2]), float(p[3]), float(p[4]), float(p[5])))
            elif p[0] == "noisy":
                noisy[p[1]] = float(p[3])
    return sweep, noisy


class Chart:
    W, H = 960, 430

    def __init__(self):
        self.parts = []

    def add(self, s):
        self.parts.append(s)

    def axes(self, x0, y0, w, h, ymax, yfmt, xs):
        """Grid, y labels and x labels (clients on a doubling scale)."""
        for i in range(5):
            v = ymax * i / 4
            y = y0 + h - h * i / 4
            self.add(f'<line class="grid" x1="{x0}" y1="{y:.1f}" x2="{x0 + w}" y2="{y:.1f}"/>')
            self.add(f'<text class="t-axis" x="{x0 - 6}" y="{y + 4:.1f}" text-anchor="end">{yfmt(v)}</text>')
        for i, c in enumerate(xs):
            x = x0 + w * i / (len(xs) - 1)
            self.add(f'<text class="t-axis" x="{x:.1f}" y="{y0 + h + 16}" text-anchor="middle">{c}</text>')
        self.add(f'<text class="t-axis" x="{x0 + w / 2}" y="{y0 + h + 32}" text-anchor="middle">clients sending at once</text>')

    def line(self, x0, y0, w, h, ymax, pts, cls, dashed, label, tip):
        xy = [(x0 + w * i / (len(pts) - 1), y0 + h - h * v / ymax) for i, v in enumerate(pts)]
        d = " ".join(f"{'M' if i == 0 else 'L'}{x:.1f},{y:.1f}" for i, (x, y) in enumerate(xy))
        self.add(f'<path class="line {cls}{" dash" if dashed else ""}" d="{d}"/>')
        for (x, y), t in zip(xy, tip):
            fill = cls.replace("l", "s")
            self.add(f'<circle class="dot {fill}" cx="{x:.1f}" cy="{y:.1f}" r="4"><title>{escape(t)}</title></circle>')
        lx, ly = xy[-1]
        self.add(f'<text class="t-label" x="{lx + 10:.1f}" y="{ly + 4:.1f}">{escape(label)}</text>')


def main(path):
    sweep, noisy = load(path)
    pay = sorted(sweep["payment"])
    raw = sorted(sweep["rawsign"])
    clients = [c for c, *_ in pay]
    c = Chart()
    c.add(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {c.W} {c.H}" width="{c.W}" height="{c.H}" '
          f'role="img" aria-label="quorum-hsm under load">')
    c.add(EXTRA_STYLE)
    c.add('<rect class="bg" width="100%" height="100%"/>')
    c.add('<text class="t-h1" x="24" y="34">quorum-hsm under load</text>')
    c.add('<text class="t-sub" x="24" y="54">One emulated HSM that handles one command at a time, '
          'like a single-core chip. Every approved payment is saved to disk before it is signed.</text>')

    # Panel 1: throughput.
    x0, y0, w, h = 84, 110, 230, 250
    c.add(f'<text class="t-title" x="24" y="{y0 - 22}">Requests per second</text>')
    ymax = nice_max(max(r for _, r, *_ in raw) * 1.05)
    c.axes(x0, y0, w, h, ymax, lambda v: f"{v / 1000:.0f}k" if v else "0", clients)
    c.line(x0, y0, w, h, ymax, [r for _, r, *_ in raw], "l2", False, "raw signing",
           [f"raw signing, {n} clients: {r:,.0f}/s" for n, r, *_ in raw])
    c.line(x0, y0, w, h, ymax, [r for _, r, *_ in pay], "l1", False, "payments",
           [f"payments, {n} clients: {r:,.0f}/s" for n, r, *_ in pay])
    c.add(f'<text class="t-note" x="24" y="{y0 + h + 54}">Payments level off at the disk: one save each.</text>')

    # Panel 2: waiting time for payments.
    x0b = 400
    c.add(f'<text class="t-title" x="{x0b - 60}" y="{y0 - 22}">Waiting time for a payment</text>')
    ymax = nice_max(max(p99 for *_, p99 in pay) / 1000 * 1.05)
    c.axes(x0b, y0, w - 30, h, ymax, lambda v: f"{v:.0f} ms", clients)
    c.line(x0b, y0, w - 30, h, ymax, [p99 / 1000 for *_, p99 in pay], "l1", True, "99th pct",
           [f"{n} clients: 99% within {p99 / 1000:.1f} ms" for n, _, _, p99 in pay])
    c.line(x0b, y0, w - 30, h, ymax, [p50 / 1000 for _, _, p50, _ in pay], "l1", False, "median",
           [f"{n} clients: median {p50 / 1000:.2f} ms" for n, _, p50, _ in pay])
    c.add(f'<text class="t-note" x="{x0b - 60}" y="{y0 + h + 54}">More clients = a longer line to wait in.</text>')

    # Panel 3: noisy neighbours (horizontal bars, single series).
    px = 680
    c.add(f'<text class="t-title" x="{px}" y="{y0 - 22}">One client\'s median wait while others…</text>')
    base = noisy.get("none", 1) or 1
    rows = [(label, noisy[tag]) for tag, label in NOISY if tag in noisy]
    vmax = max(v for _, v in rows)
    bar_x, bar_w, bh = px, 180, 16
    for i, (label, v) in enumerate(rows):
        y = y0 + i * 36
        c.add(f'<text class="t-label" x="{px}" y="{y + 10}">{escape(label)}</text>')
        bw = max(2, bar_w * v / vmax)
        r = min(4, bw / 2)
        d = (f"M{bar_x},{y + 16} h{bw - r:.1f} a{r},{r} 0 0 1 {r},{r} v{bh - 2 * r} "
             f"a{r},{r} 0 0 1 -{r},{r} h-{bw - r:.1f} z")
        c.add(f'<path class="s1" d="{d}"><title>{escape(label)}: median {v:.0f} µs</title></path>')
        c.add(f'<text class="t-value" x="{bar_x + bw + 6:.1f}" y="{y + 28}">'
              f'{v / 1000:.2f} ms ({v / base:.1f}x)</text>')
    c.add(f'<text class="t-note" x="{px}" y="{y0 + h + 54}">Without the PIN, others barely slow it down.</text>')
    c.add('</svg>')
    print("\n".join(c.parts))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
