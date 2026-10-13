#!/usr/bin/env python3
"""Analyse raw FPC e340 captures (128x88, 22-byte sub-header + 11264 px).

Usage:
    python3 analyse_capture.py <dir-with-*.raw>

Renders several candidate layouts / enhancements to PNGs so the presence or
absence of ridge structure can be judged visually.  See ENCLAVE_IMAGE_PIPELINE.md.

Requires: numpy, pillow  (montage step additionally needs ImageMagick).
"""
import glob
import os
import sys

import numpy as np
from PIL import Image, ImageFilter

HDR = 22          # 22-byte per-frame sub-header
IMG = 11264       # 128 * 88
W, H = 128, 88
NB, CW = 8, 16    # 8 column-blocks of 16 columns


def load(dirpath):
    files = sorted(glob.glob(os.path.join(dirpath, "*.raw")))
    frames = [np.frombuffer(open(f, "rb").read()[HDR:HDR + IMG], dtype=np.uint8)
              for f in files]
    return files, np.array(frames, dtype=np.float64)


def norm(a):
    lo, hi = np.percentile(a, 1), np.percentile(a, 99)
    a = np.clip(a, lo, hi)
    return ((a - a.min()) / (a.max() - a.min() + 1e-9) * 255).astype(np.uint8)


def save(name, arr, scale=3):
    im = Image.fromarray(norm(arr))
    im.resize((im.width * scale, im.height * scale), Image.NEAREST).save(name)
    print("saved", name, arr.shape)


def bgremove(a2d):
    return a2d - a2d.mean(1, keepdims=True) - a2d.mean(0, keepdims=True) + a2d.mean()


def main(dirpath):
    files, frames = load(dirpath)
    avg = frames.mean(0)
    print(f"{len(files)} frames")

    # layouts
    A = avg.reshape(H, W)                     # row-major 88x128
    save("layA_row88x128.png", A)
    save("layB_row128x88.png", avg.reshape(W, H))
    save("layC_colwiseT.png", avg.reshape(H, W).T)

    # 8 x 16-column block de-interleave
    E = np.zeros((H, NB * CW))
    F = np.zeros((H, NB * CW))
    for b in range(NB):
        blk = avg[b * (CW * H):(b + 1) * (CW * H)]
        E[:, b * CW:(b + 1) * CW] = blk.reshape(H, CW)
        F[:, b * CW:(b + 1) * CW] = blk.reshape(CW, H).T
    save("layE_block_row.png", E)
    save("layF_block_col.png", F)

    # background removed / CLAHE-ish
    save("R1_frame0_bgremoved.png", bgremove(frames[0].reshape(H, W)))
    save("R2_avg_bgremoved.png", bgremove(A))

    im = Image.fromarray(norm(A))
    lo = np.asarray(im.filter(ImageFilter.GaussianBlur(10)), dtype=np.float64)
    hi = np.asarray(im.filter(ImageFilter.GaussianBlur(25)), dtype=np.float64)
    save("R4_clahe.png", np.clip(128 + (lo - hi) * 6, 0, 255))

    # stats
    print("per-block means:", [round(float(avg[b * 1408:(b + 1) * 1408].mean()), 1)
                               for b in range(NB)])
    row = A[40]
    ac = np.correlate(row - row.mean(), row - row.mean(), "full")[len(row) - 1:]
    ac /= ac[0]
    print("horiz autocorr lag1..6:", [round(float(ac[k]), 3) for k in range(1, 7)])
    print("temporal std per px:", round(float(frames.std(0).mean()), 2))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
