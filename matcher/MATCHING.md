# FPC 2040 matcher — `matcher/`

Host-side fingerprint **matcher** for the FPC 2040 (Disum / Acer Swift 3
SF314-512, Honor MagicBook) sensor.  It consumes the **clean-room BEP**
ridge image (64×176 8-bit grayscale) and decides same-finger / different-finger.

## Why correlation, not minutiae

The sensor is a small strip (128×88 raw → 64×176 ridge, ~3.2 × 8.8 mm).
A single frame holds only ~5–8 ridges across, which yields 2–6 minutiae —
below `MIN_COMPUTABLE_BOZORTH_MINUTIAE = 10`, so NBIS `bozorth3` cannot
match these images at all (it returns 0 for every pair).  FPC's own matcher
is correlation based; this is the clean-room equivalent:

1. band-pass the ridge image (gaussian subtraction, keeps ~11 px ridges,
   removes shading),
2. local contrast normalisation (15×15 window) so wet/dry regions weigh equally,
3. masked, rotation-searched normalised cross-correlation (±30°, refined to
   ±2°), coarse 4× downsample search then full-res refinement.

Score range **0..1000** (`fpc_tpl_match`).

## API (`fpc_match.h`)

* `fpc_tpl_build(img, w, h, &tpl)` — preprocess a ridge image into a template.
  Returns -1 if there is no usable ridge area (coverage < 200 px).
* `fpc_tpl_match(&a, &b)` — pairwise score 0..1000.
* `fpc_tpl_match_gallery(&probe, gallery, n, &best_index)` — **best-of-N**
  over a multi-template enrolment gallery; this is the recommended enrol
  path.  A probe's genuine score becomes the max over all enrolled frames, so
  one weak enrolment frame no longer sinks the match.
* `FPC_MATCH_THRESHOLD` = **550**.

## Build

```
cd matcher && make          # builds libfpc_match.a + fpc_match_tool
```

`fpc_match_tool a.raw b.raw` prints `score=N (coverage X% / Y%)`.

## Validation (2026-10 capture corpus)

Closed-set, multi-template (best-of-N) protocol.  Each probe is scored
against a per-finger gallery built from the *other* same-finger frames; the
impostor score is the max over all other-finger galleries.

| set                                   | genuine (max) | impostor (max) | thr | FAR | FRR |
|----------------------------------------|---------------|----------------|-----|-----|-----|
| 3 fingers, 2 sessions (21 probes)      | min 613, med 850 | max 542      | 550 | 0/21 | 0/21 |
| 2 fingers, corpus only (15 probes)     | min 610, med 830 | max 486      | 550 | 0/15 | 0/15 |

Both runs were produced **entirely on the target x86-64 laptop** using
`fpc_recon_native --cleanroom` (clean-room BEP) for the ridge images, then
`fpc_match_tool`.  Zero errors.  Genuine same-finger scores land 600–900;
impostors ≤ 500.

## Live demo

`live_enroll_verify.sh [ENROL=5] [VERIFY=3]` (run as root on the laptop):

1. captures ENROL presses → clean-room BEP → enrol gallery,
2. captures VERIFY presses and scores each against the gallery,
3. prints ACCEPT (score ≥ 550) / REJECT.

Note: `--cleanroom` only replaces the BEP *image* op.  The enclave lifecycle
(`fpc_setup_enclave`, `FpcTaInitialize_ecall`, `fmi`) still runs inside the
vendor `fpc_enclave.dll`, which is therefore still required at runtime
**for bootstrap only** — no vendor image-processing code executes on the
captured data.  A fully standalone clean-room (re-implementing setup/init/
fmi) is tracked as Phase 2 of the project plan.
