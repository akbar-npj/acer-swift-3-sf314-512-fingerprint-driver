#!/usr/bin/env python3
"""Convert a reconstructed fingerprint frame (raw 8-bit) to a viewable PNG.

`FUN_18001c810` writes width*height bytes, row-major, one byte per pixel. For
the 10a5:e340 that is 64x176 = 11264 bytes. The byte range is usually narrow
(the reconstruction is (short+0x20)>>6), so by default we contrast-stretch to
the full 0..255 range for visibility; pass --no-stretch to keep raw values.

Usage:
    recon2png.py <in.raw> <out.png> [WxH] [--no-stretch]
"""
import sys

from PIL import Image


def main(argv):
    if len(argv) < 3:
        print(__doc__.strip(), file=sys.stderr)
        return 2

    src, dst = argv[1], argv[2]
    width, height = 64, 176
    stretch = True
    for arg in argv[3:]:
        if arg == "--no-stretch":
            stretch = False
        elif "x" in arg:
            width, height = (int(v) for v in arg.split("x", 1))

    with open(src, "rb") as fh:
        data = fh.read()

    if len(data) != width * height:
        if width and len(data) % width == 0:
            height = len(data) // width
        else:
            print(f"{src}: {len(data)} bytes is not {width}x{height}", file=sys.stderr)
            return 1

    if stretch:
        lo, hi = min(data), max(data)
        span = (hi - lo) or 1
        data = bytes((b - lo) * 255 // span for b in data)

    Image.frombytes("L", (width, height), data).save(dst)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
