#!/usr/bin/env python3
"""Frontier finder for the clean-room rewrite.

A function is "ready" when it is not yet implemented and every one of its
in-module callees is implemented.  Inputs (all in this directory):
  * ../reachable.txt  — the 355 target functions (RVA, size, depth, symbol)
  * done.txt          — RVAs already parity-verified
  * callees.txt       — per-function in-module call targets (from r2)
"""
import os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

reach = {}
for ln in open(os.path.join(ROOT, 'reachable.txt')):
    p = ln.split()
    if len(p) >= 4:
        reach[int(p[0], 16)] = (int(p[1].split('=')[1]), p[3])

done = set()
for ln in open(os.path.join(HERE, 'done.txt')):
    ln = ln.strip()
    if ln:
        done.add(int(ln, 16))

callees = {}
for ln in open(os.path.join(HERE, 'callees.txt')):
    p = ln.split()
    if p:
        callees[int(p[0], 16)] = [int(x, 16) for x in p[1:]]

not_done = [r for r in sorted(reach) if r not in done]
ready, blocked = [], []
for r in not_done:
    missing = [c for c in callees.get(r, []) if c not in done]
    if missing:
        blocked.append((r, reach[r][0], reach[r][1], missing))
    else:
        ready.append((r, reach[r][0], reach[r][1], len(callees.get(r, []))))

print("reachable: %d   done: %d   not-done: %d" % (len(reach), len(done), len(not_done)))
print("READY: %d" % len(ready))
for r, sz, nm, nc in ready:
    print("  %09x  size=%-5d ncallee=%-2d %s" % (r, sz, nc, nm))
if '-b' in sys.argv:
    print("\nBLOCKED: %d" % len(blocked))
    for r, sz, nm, miss in blocked:
        print("  %09x  size=%-5d needs %s" % (r, sz, [hex(x) for x in miss]))
