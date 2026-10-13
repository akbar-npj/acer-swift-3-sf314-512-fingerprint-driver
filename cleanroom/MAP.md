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

### Batch 2 — util kernel

| vendor RVA | vendor symbol | clean-room name | actual semantics |
|---|---|---|---|
| `0x180016720` | `fpc_bio_bep_sw23_1dbe7da717` | `cr_status_from_flag` | `flag == 0 ? 0 : 0x69` (asm `cmp dl,1; sbb; not; and 0x69`). |
| `0x1800216d0` | `fpc_bio_bep_sw23_4d4be3ba3b` | `cr_status_from_ctx` | `(*(u8*)(*(void**)(ctx+0x78) + 0x3c) == 0) ? 0 : 0x69`. |
| `0x180011000` | `fpc_bio_bep_sw23_110d16790e` | `cr_fill` | `memset(dst,val,n)` **only for n>0** (n<=0 is a no-op, unlike libc). |
| `0x180040de0` | `fpc_bio_bep_sw23_db3e766540` | `cr_copy` | `memcpy(dst,src,n)` only for n>0. |
| `0x180040e20` | `fpc_bio_bep_sw23_db476a7e1b` | `cr_modff` | `modff`: `i=(int)x; *intpart=(float)i; return x-(float)i`. |
| `0x180027380` | `fpc_bio_bep_sw23_688cc93710` | `cr_bitmap_get` | bitmap bit test; bit index `y*width+x`, word `>>5`, bit `x&31`. |
| `0x18003c540` | `fpc_bio_bep_sw23_c31521ad32` | `cr_bitmask_range` | mask for bits `[start,end]` within 32-bit `word`; all-ones if the range leaves the word. |

### Batch 2 — image leaves

The image descriptor layout (established from these functions):
`+0x00 w`, `+0x04 h`, `+0x08 data`, `+0x10 w`, `+0x14 h`, `+0x18 offx`, `+0x1c offy`.

| vendor RVA | vendor symbol | clean-room name | actual semantics |
|---|---|---|---|
| `0x180023a60` | `fpc_bio_bep_sw23_53297280e7` | `cr_image_fill_const2` | fill `data[0..w*h)` with the constant `2`. |
| `0x18003b250` | `fpc_bio_bep_sw23_b9f68de6cb` | `cr_image_set` | init descriptor; `NULL->1`, `w<0||h<0 -> 0x69`, else 0. |
| `0x18003fbc0` | `fpc_bio_bep_sw23_d5d1681a28` | `cr_image_set` | **byte-identical duplicate** of `0x18003b250`. |
| `0x180010ef0` | `fpc_bio_bep_sw23_0fdf5f04f4` | `cr_image_subview` | sub-view: copy a/b/data from src; set w,h from args; `off += (dx,dy)`. |
| `0x180017a80` | `fpc_bio_bep_sw23_265153bede` | `cr_image_subview` | **byte-identical duplicate** of `0x180010ef0`. |
| `0x1800305b0` | `fpc_bio_bep_sw23_900aab35d7` | `cr_image_mark_indices` | for each index in the list, set `data[index] = 4`. |
| `0x180033ae0` | `fpc_bio_bep_sw23_9c60738574` | `cr_image_threshold_mark` | where `src16[i] >= thr`, set `data[i] = 0x10`. |

### Batch 3 — math / util / image leaves

| vendor RVA | vendor symbol | clean-room name | actual semantics |
|---|---|---|---|
| `0x1800413a0` | `fpc_bio_bep_sw23_dc5cdd7edc` | `cr_ldexpf` | `ldexpf`: `x != 0.0 ? u2f(f2u(x) + (k<<23)) : 0.0`. **Ghidra mistypes this as returning int** — the asm returns a float in `xmm0` (`movd eax,xmm0; add eax,edx; movd xmm1,eax`). |
| `0x180002d60` | `FpcBioTemplateSave` | `cr_lroundf` | `lroundf`: `e=trunc(x±0.5); return e + ((float)e - x < 0.0)`. First test is `ucomiss; jbe` so NaN takes the subtract branch. |
| `0x180012060` | `fpc_bio_bep_sw23_14aab7a29c` | `cr_s16_clamp_nonneg` | copy `n` int16, mapping negatives to 0 (`cmovns`). |
| `0x18002fd00` | `fpc_bio_bep_sw23_8bbb505c96` | `cr_prng_range` | LCG: `s = (s>>32) + (u32)s * 0xf83f630a` (64-bit); then `hi = (u32)s % (hi-lo) + lo` when `hi != lo`. |
| `0x1800393b0` | `fpc_bio_bep_sw23_b54df0b0f5` | `cr_clz` | count-leading-zeros. Vendor spreads bits, adds 1, multiplies by the de Bruijn constant `0x76be629`, shifts `>>27` and indexes a 32-byte table; net result is `__builtin_clz(x)` for `x!=0`, `0` for `x==0`. |
| `0x18001b990` | `fpc_bio_bep_sw23_3123fca792` | `cr_sincos` | quadrant sine/cosine from a 65-entry int16 table `round(16384*sin(k*pi/128))`. Args are `(int *a, int *b, uint phase)` — phase is the **3rd** arg. |
| `0x18003b800` | `fpc_bio_bep_sw23_bbdc68c33d` | `cr_dot_f32` | single-precision dot product; `n<=0 -> 0.0f`. |
| `0x1800182b0` | `fpc_bio_bep_sw23_27c8bbdf12` | `cr_image_mark_nonpos` | where `src16[i] <= 0`, set `data[i] = 1`. |
| `0x180034490` | `fpc_bio_bep_sw23_a0bbe17d94` | `cr_image_set_pitch` | like `cr_image_set` but the first width word is a 32-aligned stride: `a = (w+31) & ~31`. |
| `0x180036460` | `fpc_bio_bep_sw23_a8929aa58a` | `cr_image_set` | **byte-identical duplicate** of `0x18003b250` (3rd copy). |

### Batch 4 — rect fills / bitmap ops / misc leaves

| vendor RVA | vendor symbol | clean-room name | actual semantics |
|---|---|---|---|
| `0x1800465a0` | `fpc_bio_bep_sw23_f2c350625f.part.1` | `cr_rect_fill_u8` | fill the `w x h` block at `(offx,offy)` (stride `a`) with a byte. |
| `0x18001d700` | `fpc_bio_bep_sw23_38215f32ef` | `cr_rect_fill_u16` | same, 16-bit elements; value arrives in `dx` (integer arg). |
| `0x18001edb0` | `fpc_bio_bep_sw23_3d13ea8103` | `cr_rect_fill_f32` | same, 32-bit **float** elements (`movss [..],xmm1`); the value is a float arg. |
| `0x180037fb0` | `fpc_bio_bep_sw23_af53e5058d` | `cr_bitmap_clear_rect` | clear the bits of `[y0,y1) x [x0,x1)`; bit idx `(offy+y)*a + (offx+x)`. |
| `0x180023bb0` | `fpc_bio_bep_sw23_5637713915` | `cr_bitmap_set_from_image` | set bitmap bits where the source image byte has `(b & 0xe) != 0`. |
| `0x180041cc0` | `fpc_bio_bep_sw23_e285f0085a` | `cr_bitmap_unpack` | expand a bitmap into dst bytes: `bit ? 0xff : 0x00`. |
| `0x180041bb0` | `fpc_bio_bep_sw23_e218884414` | `cr_classify_mark` | for indices where the pixel tag is 8: `v<=0 -> 1`, `v>=255 -> 0x10` (NaN -> 0x10). |
| `0x180030270` | `fpc_bio_bep_sw23_8ca6f25abc` | `cr_copy_or_relu` | mode 0: word copy; mode 1: `maxss(v,0)` ReLU (NaN -> 0); else `0x69`. |
| `0x18001d7b0` | `fpc_bio_bep_sw23_38df1c2726` | `cr_array_rotate` | rotate the head of a u64 array about pivot `(n>>1)-1`. |
| `0x18003d8f0` | `fpc_bio_bep_sw23_c9c1caf0a0.constprop.2` | `cr_type_desc_getter` | init a 32-byte descriptor; type 2 -> byte 0x10, type 4 -> 4, tag `0x1_00000019`; else 1. |

### Batch 5 — image copies / stats / affine

| vendor RVA | vendor symbol | clean-room name | actual semantics |
|---|---|---|---|
| `0x1800308d0` | `fpc_bio_bep_sw23_901c599831.isra.1` | `cr_image_copy_u8` | copy the `w x h` byte block (each image's own stride `a` and origin `offx/offy`); returns `0x69` if `src->w/h != dst->w/h`, else 0. |
| `0x18000f600` | `fpc_bio_bep_sw23_06c5524131` | `cr_image_copy_u32` | same, 32-bit elements (`movss` load/store, so also usable for floats); same `0x69` w/h check. |
| `0x18002ade0` | `fpc_bio_bep_sw23_768fe83277` | `cr_image_copy_u16_shl` | copy `dst->w x dst->h` int16 elements, each shifted left by `shift & 0x1f`; no dimension check. |
| `0x180037e70` | `fpc_bio_bep_sw23_aed252bf13` | `cr_masked_variance` | column-major `count*sumsq - sum^2` over samples whose mask byte (`(*mask)[i + j*rows]`) is 0; `rows<=0 -> 0`. |
| `0x1800469e0` | `fpc_bio_bep_sw23_f3d41f1091` | `cr_read_quad` | big-endian 4-byte probe of an image-like descriptor (`+0 stride`, `+8 data`, `+0x10 A`, `+0x14 B`) at rows/cols `{A/3,2A/3} x {B/3,2B/3}`; returns -1 if NULL or the value is 0. |
| `0x1800491e0` | `fpc_buffer_pixels_check_size` | `cr_buffer_pixels_setup` | validate `len` against capacity-0x18 (with signed-overflow guard), `memmove` into `+0x24`, then record `a,b,c` at `+0xc/+0x10/+0x14`, `a*b` at `+8`, `0x100000000` at `+0x18`, `(a*c<0?a*c+7:a*c)>>3` at `+0x20`. |
| `0x180014b30` | `fpc_bio_bep_sw23_1cbe178998` | `cr_affine_transform` | pick `k` = first argmin of `scores[0..9)`, then `out[i] = pts[3k]*T[k][i] + pts[3k+1]*T[k][16+i] + pts[3k+2]` for `i<16`, using the 9x32 basis table at `0x18008ec40`. |

### Batch 6 — 256-byte leaves

| vendor RVA | vendor symbol | clean-room name | actual semantics |
|---|---|---|---|
| `0x18000fb20` | `fpc_bio_bep_sw23_097e23479a` | `cr_vfir4_u8` | Q15 vertical FIR: `out[g*4+j] = (int8)((Σ_k in[k*n+g*4+j]*coeff[k] + 0x4000) >> 15)`, 4 columns per group, `((n-4)>>2)+1` groups; `n<=3` no-op. |
| `0x180020130` | `fpc_bio_bep_sw23_45d26c97de` | `cr_masked_minmax` | over set bits of a bitmap sub-rectangle, min/max/count of the corresponding byte-image pixels; `h<=0 -> (0xff,0,0)`. |
| `0x1800309a0` | `fpc_bio_bep_sw23_90875da224` | `cr_orient_pick` | correlate `*src` with `coeff` forwards and backwards over `k*k` taps; if `|rev|>|fwd|` flip flag bit 7, swap the first `d` bytes of `arr` with the next `d` (`d` from `half`), report 1; else report 0. |
| `0x1800391b0` | `fpc_bio_bep_sw23_b4118e23cd` | `cr_atan2_deg` | `atan2(a,b)` in **degrees**, range `[0,360)`, via an odd polynomial `(((C2*u+C3)*u-C4)*u+C5)*t` plus the quadrant fixes (C6=90, C7=180, C8=360). |

### Batch 7 — 272-byte leaves

| vendor RVA | vendor symbol | clean-room name | actual semantics |
|---|---|---|---|
| `0x18003e9f0` | `fpc_bio_bep_sw23_cbfed5bc7c` | `cr_matmul_nt` | `out[i*ncols+j] = Σ_k in[i*K+k] * W[j*K+k]` (`in` is N x K, `W` is ncols x K); returns 1 when `K != Kcheck`, else 0. |
| `0x18003f460` | `fpc_bio_bep_sw23_d1adcab3af` | `cr_mean_stddev` | `mean = sum/n`, `var = sumsq/n - mean²`, `*out_std = sqrt(var)` (reuses `cr_sqrtf`); `n<=0 -> NaN`. |
| `0x1800277e0` | `fpc_bio_bep_sw23_69f82fab13` | `cr_masked_minmax_s16` | min/max/count of int16 samples selected by `(mask[i] & and_mask) != 0` (or all when `mask == NULL`); defaults `+32767 / -32768`. |

### Batch 8 — 288-byte leaves

| vendor RVA | vendor symbol | clean-room name | actual semantics |
|---|---|---|---|
| `0x180017840` | `fpc_bio_bep_sw23_253a6224d6` | `cr_masked_minmax_f32` | float twin of `cr_masked_minmax_s16`: min/max/count of `img->h*img->w` contiguous floats selected by `(mask[i] & and_mask) != 0`; defaults `+FLT_MAX / -FLT_MAX`; SSE `minss`/`maxss` (NaN → sample). |
| `0x1800334c0` | `fpc_bio_bep_sw23_9a9c3581cf` | `cr_i16_to_f32_scaled` | convert int16 image → float image, scale `= 1/(float)(1<<(shift&31))` for `shift>0`, `1.0f` for `shift==0`, `(float)(1<<((-shift)&31))` for `shift<0`; each image's own stride/origin, `dst`'s w/h. |

### Batch 9 — 304-byte leaves

| vendor RVA | vendor symbol | clean-room name | actual semantics |
|---|---|---|---|
| `0x18001f790` | `fpc_bio_bep_sw23_4172e0ed57` | `cr_bilinear_sample_u8` | Q15 bilinear resample of a byte image along the affine path `x=xcoef*idx+xbase+i*xstep`, `y=ycoef*idx+ybase+i*ystep` (see `cr_sampler`); weights `((0x8000-fx)*(0x8000-fy))>>15` etc., result `(Σ w*p)>>15`; honours the image stride/origin. |
| `0x18002cc00` | `fpc_bio_bep_sw23_7b12c18a30` | `cr_box_blur_h_f32` | if `win` even, copy `nrows*ncols` floats; else horizontal box blur of width `win` (clamp-to-edge, `lo=-(win-1)/2`), each output `= Σ win clamped samples / (float)win`; column-major (`stride==nrows`). `*dst_ref` is the dest pointer. |
| `0x180037330` | `fpc_bio_bep_sw23_ab8df24280` | `cr_masked_box_sum` | sum+count of masked pixels in the centred `(2r+1)²` box (`r=win/2`) around linear index `idx` (`cy=idx/W`, `cx=idx%W`), clamped to the image; `*out_sum += img[y*W+x]` and `*out_count++` when `mask[y*W+x] & and_mask`. |

### Batch 10 — 320-byte leaves

| vendor RVA | vendor symbol | clean-room name | actual semantics |
|---|---|---|---|
| `0x18000f9d0` | `fpc_bio_bep_sw23_08800726c8` | `cr_f32_to_i16_scaled` | float image → int16 image, scale `(float)(1<<(shift&31))` for `shift>0`, `1.0f` for `shift==0`, `1/(float)(1<<((-shift)&31))` for `shift<0`; rounds half-away-from-zero (`t = v>0 ? v+0.5 : v-0.5`, then `(int16)(int)t`); uses dst's w/h, both strides/origins. |
| `0x180019490` | `fpc_bio_bep_sw23_30229e9ac0` | `cr_block_extreme_bitmap` | per 32-byte block of the input image (row stride `out->w`), build a word whose bit is 1 iff the byte is 0 or 255, then complement it (set bit = "intermediate" byte 1..254); stored in `out->data` with row stride `out->a>>5` words. |
| `0x180034190` | `fpc_bio_bep_sw23_9e452a5621.isra.7.constprop.13` | `cr_bitmap_popcount` | total popcount of a bitmap with row stride `a` bits and `w` significant bits per row: sums the `w/32` full words per row, plus (when `w!=a`) the partial word masked to `0xffffffff >> ((a-w)&31)`. |
| `0x180026fb0` | `fpc_bio_bep_sw23_66bb0714da` | `cr_downsample_mean` | integer-factor block-average downsample: `out[r*ow+c] = (int16)(Σ over f×f block of in / (f*f))` (signed, truncated); returns `0x69` if `ow*f < iw` or `oh*f < ih`, else 0; packed images, no stride/origin. |

### Batch 12 — 384-byte sin/cos leaf

| vendor RVA | vendor symbol | clean-room name | actual semantics |
|---|---|---|---|
| `0x18000eca0` | `fpc_bio_bep_sw23_045ad05bbf` | `cr_sincos_f32` | high-accuracy `sin`/`cos` pair (float). Range-reduce `x` by `2π`, split at `π` (sign flip) and `π/2` (branch), evaluate `sin(u)`/`cos(u)` by 8th-order Taylor polynomials, combine through the `√2/2` angle-split identity. Angle arrives in `xmm0`; out-pointers map to `rcx`/`rdx`. |

### Batch 13 — 384-byte border-fill leaf

| vendor RVA | vendor symbol | clean-room name | actual semantics |
|---|---|---|---|
| `0x18001c4e0` | `fpc_bio_bep_sw23_3281879ff9` | `cr_image_fill_border` | fills the int16 frame around an image window with a constant `fill`. Args (ms_abi): `rcx=img`, `rdx=top`, `r8=bottom`, `r9=left`, `[rsp+0x20]=right`, `[rsp+0x28]=fill`. `r12 = data + (offy*a + offx)` (window top-left). Region 1: `top` rows above the window, `w` wide. Region 2: `bottom` rows below. Region 3: `left` columns left of the window (cols `offx-1 … offx-left`), each `h+top+bottom` tall. Region 4: `right` columns right of the window (cols `offx+w … offx+w+right-1`), same height. Row step = `a` int16 elements. The loop counters decrement/increment **before** the fill (off-by-one trap). |

## Deferred (identified, not yet rewritten)

| vendor RVA | vendor symbol | why deferred |
|---|---|---|
| `0x180030340` | `fpc_bio_bep_sw23_8d79fe3601` | returns static table pointers — needs the table contents. |
| `0x18002aeb0` | `fpc_bio_bep_sw23_769acc1eef` | returns a pointer to the static table `DAT_180159ea0` (type 4) — needs the table contents. |
| `0x180020860` | `fpc_bio_bep_sw23_46f04b866a` | static tables `DAT_180122980` (type 0xc), `DAT_1801598e0` (0xd). |
| `0x180012f30` | `fpc_bio_bep_sw23_16c9802c18` | static table `DAT_1801174e0` (type 6) + writes `0x100`. |
| `0x1800448f0` | `fpc_bio_bep_sw23_eb7a7b573f` | static tables `DAT_180120480` (0), `DAT_18011dd40` (1). |
| `0x180048d40` | `fpc_bio_init` | returns `*(void**)0x18016f4c8 + 8` — a global-context getter (pointer-valued). |
| `0x180002fb0` | `FpcFloor` | free-wrapper around `0x180069b60`. |
| `0x180002fe0` | `FpcFree` | malloc-wrapper around `0x18006afa0`. |

These are pointer/table/allocator-valued, so bit-exact comparison needs a
structural (not address) check; they will be handled once the referenced tables
and the allocator semantics are established.

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
