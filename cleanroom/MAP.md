# Vendor RVA <-> clean-room name map

Every entry records: the vendor RVA, the (unreliable) vendor symbol, the
clean-room name, and what the function **actually** does — established from the
disassembly, not the symbol.

## Completed (parity-verified by `tools/difftest.c`)

| vendor RVA | vendor symbol | clean-room name | actual semantics |
|---|---|---|---|
| `0x180003080` | `FpcSin` | `cr_sqrtf` | `sqrtf`. 256-entry inverse-sqrt seed table at `0x180159500`, then two Newton iterations `y <- y*(3 - x*y*y)/2`; result `x*y`. |
| `0x180002dd0` | `FpcCos` | `cr_expf` | `expf`. Range-reduce by `ln2`, degree-6 rational kernel `1 + 2t/(2 - t*P(t*t))`, then scale by `2^k` by adding to the raw exponent bits. Clamps: `x>88.7228 -> 0.9999618*2^128`, `x<-87.3365 -> 1.0000458*2^-126`. |
| `0x180003020` | `FpcMalloc` | `cr_roundf_to_int` | `roundf` to int: `x>0 ? (int)(x+0.5) : (int)(x-0.5)`, truncating cast. |
| `0x180002f70` | `FpcExp` | `cr_floorf_to_int` | `floorf` to int: `e=trunc(x±0.5); if (x-e<0) e-=1`. |
| `0x1800490d0` | `fpc_buffer_get_pixels_buffer` | `cr_buf_is_pixels` | `buf && *(u32*)buf == 1`. |
| `0x180049120` | `fpc_buffer_is_meta` | `cr_buf_is_metadata_class` | `buf && (s32)(type-8) >= 0 && (type & 1) == 0`. |
| `0x1800490f0` | `fpc_buffer_is_debug` | `cr_buf_is_debug_class` | `!buf -> 0; type==0 -> 1; type<=8 -> 0; else ((type-7)^1)&1`. |
| `0x18004b670` | `fpc_metadata_put_uint16` | `cr_meta_put_u32` | Append/overwrite a `{key,size=4,value}` record in a metadata store (`used`/`capacity` at +8/+4, records from +0xc). Returns 0, -7 (size mismatch), or -1 (no space). |
| `0x18004b4e0` | `fpc_metadata_get_uint16` | `cr_meta_get_u32` | Look up a key; returns 0 / -3 (empty) / -4 (bad used) / -5 (not found) / -7 (size mismatch). |
| `0x18004aa70` | `fpc_image_data_get_size_from_defs` | `cr_image_slot_defined` | `defs && idx<=0x15 && defs->slot[idx] != NULL`. |
| `0x18004a250` | `fpc_image_create` | `cr_image_slot_empty` | `!(defs && idx<=0x15 && slot && *(int*)(slot+8)==0)`. |

## Notes on the naming

The DLL is unstripped (a `.text$<name>` symbol table), but the names are
deliberately scrambled — they look plausible but are wrong:

| vendor name | actually |
|---|---|
| `FpcSin` | sqrtf |
| `FpcCos` | expf |
| `FpcMalloc` | roundf |
| `FpcExp` | floorf |
| `FpcFloor` | free-wrapper |
| `FpcFree` | malloc-wrapper |
| `fpc_buffer_get_pixels_buffer` | a *predicate* (returns bool), not a getter |
| `fpc_metadata_put_uint16` | stores a 32-bit value (size field is 4) |

Two more names in the file are pure noise: the giant
`init_swinging_checkerboard_test_based_on_test_level` symbol spans a bogus
192,224 bytes, and many `fpc_bio_bep_sw23_<hex>` names are just the address
hash. Semantics must always come from the body.
