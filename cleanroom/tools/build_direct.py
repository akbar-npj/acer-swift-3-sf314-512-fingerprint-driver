#!/usr/bin/env python3
"""Build a DIRECT call graph for the 355 target functions.

For each function we disassemble exactly its byte range (pD size @ addr) and
collect `call`/`jmp` targets that land on another *target* function.  Intra-
function jumps (target inside the caller's own byte range) are dropped.
"""
import os, re, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DLL = "/home/shaanair/Projects/FingerPrintSensors/Acer Swift 3 SF314-512/" \
      "FingerPrint_Carewe_20.26.23.27_W11x64/" \
      "12b431fd-7d7e-4dd7-b87c-9ab3f9a3d01b/x64/fpc_enclave.dll"

funcs = {}  # addr(int) -> (size, name)
for ln in open(os.path.join(ROOT, 'reachable.txt')):
    p = ln.split()
    if len(p) >= 4:
        funcs[int(p[0], 16)] = (int(p[1].split('=')[1]), p[3])
targets = set(funcs)

cmds = []
for a in sorted(funcs):
    sz, _ = funcs[a]
    cmds.append("?e ===MARK %x===" % a)
    cmds.append("pD %d @ 0x%x" % (sz, a))

argv = ["r2", "-e", "scr.color=0", "-e", "asm.bytes=0"]
for c in cmds:
    argv += ["-c", c]
argv += ["-c", "q", DLL]

out = subprocess.run(argv, capture_output=True, text=True).stdout

cur = None
graph = {a: set() for a in funcs}
mre = re.compile(r'^(call|jmp)\s+(0x[0-9a-f]+)')
for line in out.splitlines():
    m = re.match(r'===MARK ([0-9a-f]+)===', line.strip())
    if m:
        cur = int(m.group(1), 16)
        continue
    if cur is None:
        continue
    # strip leading whitespace / tree glyphs, then split on mnemonic
    body = line.strip()
    # find the token 'call'/'jmp' possibly preceded by tree glyphs
    mm = re.search(r'\b(call|jmp)\b\s+(0x[0-9a-f]+)', body)
    if not mm:
        continue
    tgt = int(mm.group(2), 16)
    if tgt not in targets:
        continue
    if cur <= tgt < cur + funcs[cur][0]:
        continue  # intra-function
    graph[cur].add(tgt)

with open(os.path.join(HERE, 'callees_direct.txt'), 'w') as f:
    for a in sorted(funcs):
        f.write("%x %s\n" % (a, " ".join("%x" % c for c in sorted(graph[a]))))

nleaf = sum(1 for a in graph if not graph[a])
print("wrote %d functions, %d leaves" % (len(graph), nleaf))
