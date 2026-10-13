# IDA / Ghidra RE workflow for `fpc_enclave.dll`

How the FPC e340 enclave was reverse-engineered, and how to reproduce it in a new
session. The key enabler: **`fpc_enclave.dll` is unstripped** — it embeds a
`.text$<name>\0 + u32 RVA + u32 size` symbol table (1093 named functions). Ghidra's PE
loader misses every function below `0x18004f0b0` (they have no `.pdata` unwind entries),
so the "core" looks unanalyzable until you feed the symbol table back in.

---

## 0. Paths / facts

| Thing | Path |
| --- | --- |
| Target | `FingerPrint_Carewe_20.26.23.27_W11x64/12b431fd-7d7e-4dd7-b87c-9ab3f9a3d01b/x64/fpc_enclave.dll` |
| Image base / `.text` | `0x180000000`; `.text` VA `0x180001000` = file `0x400` (`file = VA - 0xc00`) |
| `.rdata` | VA `0x180081000` = file `0x7e800` |
| IDA Free | `/opt/idafree-9.4/ida` (also `/usr/local/bin/ida64`, `/usr/local/bin/ida`) |
| IDA-MCP plugin | `~/.idapro/plugins/ida_mcp.so` (user plugin dir; built from `~/Projects/ida-mcp/ida-free-mcp`) |
| IDA-MCP HTTP | `http://127.0.0.1:<port>/mcp` (default port 13337) |
| Instance registry | `~/.ida-mcp/instances/<pid>.json` = `{idb_path,pid,port}` |
| REA↔IDA adapter | `~/Projects/ida-mcp/rea-ida-adapter/adapter.py`; config `~/.codebuddy/rea-ida-mcp.json` |
| Ghidra | `/opt/ghidra` (12.1.4), `support/analyzeHeadless` |
| Working artefacts | `~/fpwork/` (scripts below) |

---

## 1. Parse the embedded symbol table (do this first, always)

```bash
python3 ~/fpwork/parse_enclave_syms.py
# -> ~/fpwork/enclave_syms.txt   (addr  size= N  .text$name)
#    ~/fpwork/enclave_syms.txt is 1093 .text$ entries
```

Format of each record: `".text$"+name+0x00`, then (4-aligned) `u32 RVA`, `u32 size`.
The parser also prints pipeline-relevant names.

---

## 2. Route 1 — IDA Free + `ida-free-mcp` (decompile by name)

IDA Free 9.4's Hex-Rays SDK is **not** initialized, so the plugin uses *GUI-based*
decompilation (works, but is occasionally flaky — see §5). It still gives you
`define_func`/`rename`, which is what we need for the symbol-table functions.

### 2a. Launch IDA on the target with autostart

```bash
IDA_MCP_AUTOSTART=1 IDA_MCP_PORT=13337 DISPLAY=:0 \
  nohup /opt/idafree-9.4/ida \
  "/home/shaanair/Projects/FingerPrintSensors/Acer Swift 3 SF314-512/FingerPrint_Carewe_20.26.23.27_W11x64/12b431fd-7d7e-4dd7-b87c-9ab3f9a3d01b/x64/fpc_enclave.dll" \
  > ~/fpwork/ida_run.log 2>&1 &
```

- `IDA_MCP_AUTOSTART` = any value → the plugin starts the HTTP MCP server on load
  (otherwise press **Ctrl+Alt+M**).
- The plugin writes `~/.ida-mcp/instances/<pid>.json`; read it for the real port
  (it auto-increments if 13337 is taken).
- IDA runs a full auto-analysis on first open (a minute or two for this DLL).

### 2b. Define + rename every symbol (batch)

```bash
python3 ~/fpwork/ida_define_all.py
# -> define_funcs ok=1079 err=14 ; renames all 1093 via batch.func
```

### 2c. Decompile / disassemble by name

```bash
python3 ~/fpwork/ida_dc.py  fpc_bep_capture fpc_bep_cal_get fpc_sensor_internal_capture_image
python3 ~/fpwork/ida_asm.py fpc_sensor_internal_dfd_calibrate
```

### 2d. Raw MCP calls (the client is `~/fpwork/ida.py`)

```python
import ida
ida.decompile("0x18000b870")                       # -> {"ok":True,"pseudocode":...}
ida.disasm("0x18000b640", max_instructions=400)    # -> {"asm":{"lines":"..."}} names resolved
ida.define_funcs([("0x18000b870","0x18000bb80")])  # create a function
ida.rename([("0x18000b870","fpc_bep_capture")])    # rename (wraps {"batch":{"func":[...]}})
ida.get_bytes([{"addr":"0x18000b870","size":32}])
ida.xrefs_to("0x18000b870") ; ida.callees("0x18000b870")
```

Native IDA-MCP tools available: `decompile, disasm, define_func, rename, get_bytes,
list_funcs, xrefs_to, callees, callgraph, find_regex, find_bytes, imports, export_funcs,
get_string, get_global_value, set_comments, declare_type, hexrays_diag, …`

### 2e. Via REA (optional)

`~/.codebuddy/mcp.json` sets `REA_IDA_MCP_CONFIG=~/.codebuddy/rea-ida-mcp.json`, which
spawns `adapter.py` (stdio) bridging REA's legacy IDA provider to `ida-free-mcp` (HTTP).
Then in REA: `open_binary(path=..., provider_id="ida")`. **Caveat:** the adapter only
exposes 10 legacy tools (`get_metadata, list_functions, get_function_by_name/address,
list_strings, disassemble_function, decompile_function, get_xrefs_to, get_callers,
get_callees`) and REA's ida provider rejects some operations (e.g. `binary_overview`).
Direct HTTP (§2d) is more capable.

---

## 3. Route 2 — Ghidra headless (reliable batch decompile of ALL functions)

This is what produced the 1093 C files. Ghidra's decompiler is solid; we just create the
functions it missed from the symbol table.

```bash
cd ~/fpwork
mkdir -p ghidraproj enclave_decompiled
export JAVA_HOME=/home/shaanair/.sdkman/candidates/java/21.0.11-amzn
export PATH="$JAVA_HOME/bin:$PATH"
/opt/ghidra/support/analyzeHeadless ~/fpwork/ghidraproj fp_e340 \
  -import "/home/shaanair/Projects/FingerPrintSensors/Acer Swift 3 SF314-512/FingerPrint_Carewe_20.26.23.27_W11x64/12b431fd-7d7e-4dd7-b87c-9ab3f9a3d01b/x64/fpc_enclave.dll" \
  -scriptPath ~/fpwork \
  -postScript ReaCreateDecompile.java \
  -deleteProject > ~/fpwork/ghidra_headless.log 2>&1 &
```

- `ReaCreateDecompile.java` reads `enclave_syms.txt`, calls `createFunction(addr,name)` for
  every RVA, then `DecompInterface`-decompiles each into `enclave_decompiled/<name>.c`.
- The project dir must exist first (`mkdir -p ghidraproj`), else headless aborts.
- Result: `~/fpwork/enclave_decompiled/` — 1093 `.c` files, 0 failures.
- **Note:** Ghidra's re-export *name resolution is imperfect*; IDA's `disasm` resolves call
  targets to the renamed symbols more reliably. Cross-check between the two.

---

## 4. Pipeline map (real names, from the symbol table)

```
FpcTaOp_ecall (0x180068360)                     host TA command entry
  └─ sub_18006A2C0                              TA opcode dispatcher
       ├─ fpc_bep_capture (0x18000b870)         capture a sub-image
       └─ fpc_bep_cal_get (0x18000b640)         capture + CAC image processing
            ├─ cac_dev_fb3ea0eb81               build per-device context (chip driver)
            ├─ cac_capture_config_default_get   fill capture config
            ├─ fpc_sensor_internal_convert_column_wise_image (0x18004c0c0)
            ├─ fpc_cac_pn_image_capture         issue capture to sensor
            └─ cac_reg_write / cac_if_reg_*     sensor register I/O
       └─ fpc_bep_image_extract (0x18000c290) → fpc_bep_image_extract_fq (0x18000c2d0)
            └─ fpc_bio_bep_sw23_* (≈80)         the BEP algorithm ("sw23")
```

Static per-variant tables: `fpc_bep_sensor_1262g175_SMIC/TSMC`, `dfd_settings_1262g175_*`
(sensor variant = **1262g175**, build string `FPCBEP: fpc_pc_1262_acer_swift21_20.26.23.27`).

---

## 5. Gotchas

- **IDA Free Hex-Rays**: `hexrays_diag` reports `init_hexrays_plugin:false` — decompile is
  GUI-based. Some functions return `"No pseudocode widget for this function after
  decompilation"` (intermittently, even for functions that worked before). Retry, or fall
  back to `disasm`, or use Ghidra (Route 2).
- **Ghidra skips no-`.pdata` code**: don't trust Ghidra's function list for addresses
  `< 0x18004f0b0`; create them from `enclave_syms.txt`.
- **Addresses**: symbol VAs are `0x180000000 + RVA`; pass IDA/MCP addresses with a `0x`
  prefix (the IDA MCP rejects bare hex).
- **objdump** does not disassemble parts of `.text` here — use `~/fpwork/disenclave.py`
  (capstone) or IDA `disasm`.
- Stop the IDA server with Ctrl+Alt+M (or just close IDA); the instance json is cleaned up
  automatically on next start.

---

## 6. Quick start checklist for a new session

1. `python3 ~/fpwork/parse_enclave_syms.py`  (regenerate `enclave_syms.txt`)
2. Start IDA with `IDA_MCP_AUTOSTART=1` (§2a); wait for `~/.ida-mcp/instances/*.json`.
3. `python3 ~/fpwork/ida_define_all.py`  (define + rename all functions)
4. `python3 ~/fpwork/ida_dc.py <name…>` / `ida_asm.py <name…>` to read specific functions.
5. For a full batch of C sources, run the Ghidra-headless job (§3) → `enclave_decompiled/`.
