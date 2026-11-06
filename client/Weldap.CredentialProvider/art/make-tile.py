#!/usr/bin/env python3
"""Renders WELDAP's default credential-provider tile (art/tile.bmp): a collider event display -- tracker layers,
curling charged tracks, two back-to-back jets, a muon and glowing calorimeter towers -- on deep-space indigo.
Deterministic and standard-library only, so the committed bitmap can always be regenerated:
    python3 -I art/make-tile.py [out.bmp] [--size 192] [--seed 1897]
LogonUI shows the tile cropped to a circle, so everything sits inside the inscribed circle. Any other square image
can replace it at build time: build.ps1 -TileImage <file> (or WELDAP_TILE_IMAGE); see docs/CONFIGURATION.md."""
import math
import random
import struct
import sys

TAU = 2 * math.pi


def rgb(h):
    return tuple(int(h[i:i + 2], 16) / 255 for i in (0, 2, 4))


BG_IN, BG_OUT = rgb("1c1452"), rgb("04050d")
LAYER, CALO = rgb("5a6fd8"), rgb("3a2a7a")
CYAN, MAGENTA, LIME, GOLD, MUON = rgb("3fe3ff"), rgb("ff4fd8"), rgb("a6ff5c"), rgb("ffd24a"), rgb("ff7a3d")
TOWER_IN, TOWER_OUT = rgb("ffd23a"), rgb("ff2d55")
LAYERS = (0.13, 0.21, 0.29, 0.37, 0.45)
CAL_IN, CAL_OUT, MU = 0.60, 0.80, (0.86, 0.91)


class Track:
    """A charged track from the vertex: an arc of a circle through the origin (radius ~ momentum)."""

    def __init__(self, phi, radius, sign, color, r_end):
        self.R, self.s, self.color = radius, sign, color
        self.c = (radius * math.cos(phi + sign * math.pi / 2), radius * math.sin(phi + sign * math.pi / 2))
        self.a0 = math.atan2(-self.c[1], -self.c[0])
        self.loops = r_end >= 2 * radius
        self.b_end = 0.93 * TAU if self.loops else 2 * math.asin(r_end / (2 * radius))
        self.end = self.at(self.b_end)

    def at(self, b):
        a = self.a0 + self.s * b
        return self.c[0] + self.R * math.cos(a), self.c[1] + self.R * math.sin(a)

    def crossing(self, r):
        """Where the track crosses radius r on its way out, or None."""
        return None if r >= 2 * self.R or (not self.loops and r > abs(math.hypot(*self.end)) + 1e-9) \
            else self.at(2 * math.asin(r / (2 * self.R)))

    def dist(self, x, y):
        dx, dy = x - self.c[0], y - self.c[1]
        if (self.s * (math.atan2(dy, dx) - self.a0)) % TAU <= self.b_end:
            return abs(math.hypot(dx, dy) - self.R)
        return min(math.hypot(x, y), math.hypot(x - self.end[0], y - self.end[1]))


def event(rng):
    tracks, towers = [], []
    for axis, color in ((0.70, CYAN), (0.70 + math.pi + 0.18, MAGENTA)):  # two jets, nearly back to back
        for _ in range(5):
            tracks.append(Track(axis + rng.uniform(-0.2, 0.2), rng.uniform(1.3, 6.0), rng.choice((-1, 1)), color, CAL_IN))
    for _ in range(6):  # soft, curling tracks
        tracks.append(Track(rng.uniform(0, TAU), rng.uniform(0.32, 0.6), rng.choice((-1, 1)),
                            rng.choice((LIME, GOLD)), CAL_IN))
    for _ in range(3):  # loopers: too little momentum to leave the tracker
        tracks.append(Track(rng.uniform(0, TAU), rng.uniform(0.05, 0.1), rng.choice((-1, 1)), rng.choice((LIME, GOLD)), CAL_IN))
    muon = Track(2.45, 12.0, 1, MUON, MU[1] + 0.02)
    for t in tracks:
        if not t.loops:
            x, y = t.end
            towers.append((math.atan2(y, x), min(1.0, 0.4 + t.R / 5.0) * rng.uniform(0.75, 1.0)))
    return tracks + [muon], towers, muon


def smooth(edge, px):
    """Coverage of a pixel whose centre is `edge` inside a boundary (negative: outside)."""
    return min(1.0, max(0.0, 0.5 + edge / px))


def render(size, seed):
    rng = random.Random(seed)
    tracks, towers, muon = event(rng)
    hits = [(p, t.color) for t in tracks for r in LAYERS if (p := t.crossing(r))]
    hits += [(p, MUON) for r in MU if (p := muon.crossing(r))]
    px = 2.0 / size
    rows = []
    for j in range(size):
        row = []
        for i in range(size):
            x, y = (i + 0.5) * px - 1, 1 - (j + 0.5) * px
            r, th = math.hypot(x, y), math.atan2(y, x)
            t = min(1.0, r / 1.1) ** 0.85
            c = [BG_IN[k] + (BG_OUT[k] - BG_IN[k]) * t for k in range(3)]

            def add(color, a):
                for k in range(3):
                    c[k] += color[k] * a

            for rl in LAYERS:  # tracker layers
                add(LAYER, 0.30 * smooth(0.45 * px - abs(r - rl), px))
            if CAL_IN <= r <= CAL_OUT:  # calorimeter barrel, segmented
                seg = abs(((th / TAU * 48) % 1) - 0.5) * TAU / 48 * r
                add(CALO, 0.22 + 0.25 * smooth(0.4 * px - abs(seg - TAU / 96 * r), px))
            for rl in (CAL_IN, CAL_OUT) + MU:
                add(CALO if rl in (CAL_IN, CAL_OUT) else LAYER, 0.55 * smooth(0.5 * px - abs(r - rl), px))
            for ang, e in towers:  # energy deposits
                d_ang = abs((th - ang + math.pi) % TAU - math.pi) * r
                length = 0.02 + e * (CAL_OUT - CAL_IN - 0.03)
                inside = smooth(0.034 - d_ang, px) * smooth(r - (CAL_IN + 0.01), px) * smooth(CAL_IN + 0.01 + length - r, px)
                if inside or d_ang < 0.08:
                    f = min(1.0, max(0.0, (r - CAL_IN) / (CAL_OUT - CAL_IN)))
                    tc = [TOWER_IN[k] + (TOWER_OUT[k] - TOWER_IN[k]) * f for k in range(3)]
                    for k in range(3):  # painted over the barrel (not added), so the deposit keeps its heat colour
                        c[k] += (tc[k] - c[k]) * 0.92 * inside
                    add(tc, 0.14 * math.exp(-(d_ang / 0.05) ** 2) * (CAL_IN <= r <= CAL_IN + length + 0.03) * (1 - inside))
            calm = 0.25 + 0.75 * min(1.0, r / 0.12)  # tame the glow where every track meets, at the vertex
            for tr in tracks:
                d = tr.dist(x, y)
                if d < 14 * px:
                    add(tr.color, calm * (smooth(0.55 * px - d, px) + 0.32 * math.exp(-(d / (2 * px)) ** 2)
                                          + 0.10 * math.exp(-(d / (5 * px)) ** 2)))
            for (hx, hy), col in hits:
                if abs(x - hx) < 6 * px and abs(y - hy) < 6 * px:
                    d = math.hypot(x - hx, y - hy)
                    add((1, 1, 1), 0.7 * smooth(1.1 * px - d, px))
                    add(col, 0.5 * math.exp(-(d / (2.5 * px)) ** 2))
            add((1.0, 0.97, 0.9), 1.3 * math.exp(-(r / (2.4 * px)) ** 2))  # primary vertex
            add((1.0, 0.75, 0.45), 0.55 * math.exp(-(r / 0.075) ** 2))
            add((1.0, 0.95, 0.85), 0.5 * (math.exp(-(y / px) ** 2 - abs(x) / 0.2) + math.exp(-(x / px) ** 2 - abs(y) / 0.2)))
            row.append(tuple(v if v <= 0.85 else 0.85 + 0.15 * math.tanh((v - 0.85) / 0.15) for v in c))
        rows.append(row)
    return rows


def write_bmp(path, rows):
    """24-bit BMP, bottom-up, as LoadBitmap wants: what LogonUI gets from the provider's GetBitmapValue."""
    h, w = len(rows), len(rows[0])
    pad = b"\0" * ((-w * 3) % 4)
    data = b"".join(b"".join(bytes(round(v * 255) for v in (b, g, r)) for r, g, b in row) + pad for row in reversed(rows))
    with open(path, "wb") as f:
        f.write(struct.pack("<2sIHHI", b"BM", 54 + len(data), 0, 0, 54))
        f.write(struct.pack("<IiiHHIIiiII", 40, w, h, 1, 24, 0, len(data), 2835, 2835, 0, 0))
        f.write(data)


def main(argv):
    out, size, seed = "tile.bmp", 192, 1897
    args = iter(argv)
    for a in args:
        if a == "--size":
            size = int(next(args))
        elif a == "--seed":
            seed = int(next(args))
        else:
            out = a
    write_bmp(out, render(size, seed))
    print(f"wrote {out} ({size}x{size}, seed {seed})")


if __name__ == "__main__":
    main(sys.argv[1:])
