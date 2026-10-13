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

### Batch 14 — border-extend + saturation leaves

| vendor RVA | vendor symbol | clean-room name | actual semantics |
|---|---|---|---|
| `0x18001fb80` | `fpc_bio_bep_sw23_442776bb33` | `cr_image_border_extend` | byte-per-pixel **edge replication** (the u8 twin of `cr_image_fill_border`): same four-region frame, but each region copies the window's edge row/column outward instead of writing a constant. Args `rcx=img, rdx=top, r8=bottom, r9=left, [rsp+0x20]=right` (5 args). `a` = row stride in **bytes**; row step `a`. |
| `0x180016df0` | `fpc_bio_bep_sw23_214aef3596` | `cr_image_border_extend_s16` | the **int16 twin** of `cr_image_border_extend`: identical four-region edge-replication frame logic, but pixels are `int16_t` and `a` is the row stride in **elements**. |
| `0x1800356e0` | `fpc_bio_bep_sw23_a45214d052.part.7` | `cr_saturation_score` | `n = (int16)h * (int16)w`; if `n<=0` → `*out = 1000`. Else count pixels where `(uint8)(b-1) > 253` (i.e. `b==0 || b==255`), then `*out = 1000 + (count * -1000) / n` (32-bit `imul`+`idiv`, truncating). Struct: `{int16 w@0, int16 h@2, ..., uint8 *data@0x10}`. |

### Batch 16 — allocator wrappers

| vendor RVA | vendor symbol | clean-room name | actual semantics |
|---|---|---|---|
| `0x180002fe0` | `FpcFree` | `cr_malloc` | malloc wrapper. `int fn(void **out, size_t size)`: `size==0` → `*out=NULL`, return 1; else `*out=malloc(size)`, return `(ptr==NULL)`. |
| `0x180002fb0` | `FpcFloor` | `cr_free` | free wrapper. `void fn(void **p)`: `if (*p) { free(*p); *p = NULL; }`. |
| `0x18003bf40` | `fpc_bio_bep_sw23_bdbfe0d964` | `cr_sized_free` | sized free. `void fn(void **p)`: `if (*p) { base = *p - *((uint8_t*)*p - 1); free_wrapper(&base); *p = NULL; }` — the 1-byte value just before the pointer is the offset back to the allocation base. |

> The allocator wrappers call the platform allocator; the differential test compares only the observable contract (status codes, null-ing), since raw pointer values differ between allocators.

### Batch 17 — bitmap morphology (dilate / erode pair)

| vendor RVA | vendor symbol | clean-room name | actual semantics |
|---|---|---|---|
| `0x180024cb0` | `fpc_bio_bep_sw23_5f21879897` | `cr_bitmap_dilate` | `void fn(cr_image *dst, const cr_image *src, int count)`. Word stride = `ceil(dst->a/32)`; rows = `dst->h`. Each of `count` passes does a horizontal 3-wide OR window then a vertical one. Interior word `k`: `dst[k] = (prev>>31) | cur | cur*2 | cur>>1 | (next<<31)`; last word `dst[words-1] = (cur>>1) | prev | cur | cur*2` with `prev = prev>>31`. Vertical: `acc = cur | prevrow; *d = prevacc | acc`. From pass 2 the source is `dst` itself (self-feed). |
| `0x1800220e0` | `fpc_bio_bep_sw23_5029eb7cfe` | `cr_bitmap_erode` | the AND-twin of `cr_bitmap_dilate`. Word count = `dst->w >> 5`; rows = `dst->h`. Interior word: `dst[k] = (prev>>31 | cur*2) & cur & (cur>>1 | next<<31)` with leading carry `0xffffffff`; last word `dst[words-1] = cur & (prev | cur*2) & (cur>>1 | 0x80000000)`; vertical `acc = cur & prevrow; *d = prevacc & acc`. Repeated `count` times, self-feeding after pass 1. |

> Both functions take the destination image (which supplies the stride/height and is written in place) and a separate source image; the difftest exercises 1..4 words/row, 1..6 rows and 1..3 passes so the multi-word carry path and the self-feed path are both covered.

### Batch 18 — affine resample + 4-phase FIR

| vendor RVA | vendor symbol | clean-room name | actual semantics |
|---|---|---|---|
| `0x18002ca30` | `fpc_bio_bep_sw23_79a4530e21.part.4` | `cr_affine_sample_u8` | `void fn(cr_image *dst, const cr_image *src, const cr_affine_map *s)`. Q15 bilinear resample: for each dst pixel `x = x_org + row*x_row + col*x_col`, `y = y_org + row*y_row + col*y_col` (all Q15, `xi=x>>15`, `xf=x&0x7fff`); `idx = yi*src->a + xi`; `out = (int8_t)((w00*P00 + w01*P01 + w10*P10 + w11*P11) >> 15)` with `w00=((0x8000-xf)(0x8000-yf))>>15`, `w10=((0x8000-yf)xf)>>15`, `w01=((0x8000-xf)yf)>>15`, `w11=(xf*yf)>>15`. Origin = `data + (offy*a + offx)` for both images; `dst->w x dst->h` pixels. |
| `0x18000ee70` | `fpc_bio_bep_sw23_04faa0a17d.part.1` | `cr_polyphase_fir4` | `void fn(uint8_t *out, const uint8_t *in, const int16_t *coef, int nbytes, int ncoef)`. A 4-phase FIR: for each 4-byte input group at offset `4p`, `out[4p+r] = (int8_t)((0x4000 + Σ_{j=0}^{2*iters} in[4p+r+j]*coef[j]) >> 15)` where `iters = ((unsigned)(ncoef-2)>>1)+1`. `nbytes <= 3` is a no-op; accumulators are 32-bit signed; each output byte is the low byte of the SAR-15 result. |

### Batch 19 — 464-byte bilinear splat

| vendor RVA | vendor symbol | clean-room name | actual semantics |
|---|---|---|---|
| `0x180044b10` | `fpc_bio_bep_sw23_ed385570f8` | `cr_splat_bilinear` | `void fn(const float *w, float *bufA, float *bufB, const float *alpha, float x0, float y0, float scale)`. Splats 16 weighted points into two float buffers with a 17-float row stride. `x0`/`y0` are **both** the start coordinate and the per-step delta (`x_k = x0*(k+1)`); `scale` multiplies `w[k]`. Per point: `xi=(int)x`, `xf=x-(float)(int)x`, `yi=(int)y-(y0<0)`, `yf=y-(float)yi`, `wf=w[k]*scale`; `w00=((1-xf)(1-yf))*wf` → `idx`, `w10=((1-yf)xf)*wf` → `idx+1`, `w01=((1-xf)yf)*wf` → `idx+17`, `w11=(xf*yf)*wf` → `idx+18`; `bufB[tap]+=wxy`, `bufA[tap]=wxy*alpha[k]+bufA[tap]`. Single precision, exact evaluation order (built `-ffp-contract=off`). |

### Batch 20 — bitmap border set

| vendor RVA | vendor symbol | clean-room name | actual semantics |
|---|---|---|---|
| `0x180017ac0` | `fpc_bio_bep_sw23_267120cd30` | `cr_bitmap_border_set` | `int fn(cr_image *d, int left, int top, int right, int bottom, int value)`. Sets a border frame of a packed bitmap to all-ones (`value!=0`) or all-zeros. Guard: the descriptor's 8-byte `(a,b)` must equal `(w,h)` (**duplicate dimension fields** — `b==h`, not `b==0`), `(offx,offy)==0`, and `w` a multiple of 32; else returns `0x69`. Fills the whole first `top` and last `bottom` rows, then the left `left` bits and right `right` bits of every row (partial edge words masked by `0xffffffff << (left&31)` / `0xffffffff >> (right&31)`). Returns 0. |

### Batch 21 — 8-neighbour 3x3 Laplacian

| vendor RVA | vendor symbol | clean-room name | actual semantics |
|---|---|---|---|
| `0x1800169b0` | `fpc_bio_bep_sw23_1fe4634733` | `cr_laplacian_3x3` | `void fn(int16_t *out, const int16_t *A, const int16_t *C, const int16_t *B, int w)`. 8-neighbour 3x3 Laplacian of one row: `out[i] = 8*C[i+1] - (A[i]+A[i+1]+A[i+2] + C[i]+C[i+2] + B[i]+B[i+1]+B[i+2])`, where `C` is the centre row and `A`/`B` the neighbours. Two-pass 4-wide vectorised loop (bulk `[0,w-4)`, tail `[w-4,w)`); the tail pass offsets its output pointer by `-((-w)&3)` shorts. 32-bit arithmetic, low 16 bits stored. |

### Batch 22 — 7-tap edge-clamped int16 FIR

| vendor RVA | vendor symbol | clean-room name | actual semantics |
|---|---|---|---|
| `0x180020d80` | `fpc_bio_bep_sw23_49a7dfde4e` | `cr_fir7_s16` | `int fn(cr_image *dst, const cr_image *src, const int16_t *coef)`. Applies a 7-tap FIR to every row of `src` into `dst`: `out[j] = (Σ_{k=0..6} coef[k]*x[j-3+k]) >> 15`, with the taps clamped to the row (left edge repeats `x[0]`, right edge repeats `x[w-1]`). Both descriptors must be canonical (`a==w`, `b==h`, `offx==offy==0`) and share the same `(a,b)` pair, else returns `0x69`. The vendor splits each row into a rolling-history loop for columns `0..w-5` and a second loop for the last four columns whose newest tap is pinned at `x[w-1]`; widths `< 5` take only the second loop (reading `x[3]` as the pinned tap). 32-bit wrapping arithmetic; result is the low 16 bits of the arithmetic `>>15`. |

### Batch 23 — in-place row permutation

| vendor RVA | vendor symbol | clean-room name | actual semantics |
|---|---|---|---|
| `0x180024200` | `fpc_bio_bep_sw23_598b2d29a0` | `cr_permute_rows` | `int fn(uint8_t *data, int32_t *perm, int n, int stride)`. In-place row permutation of an `n`×`stride` byte matrix: destination row `j` takes source row `perm[j]`, where `perm` is an array of 8-byte entries (only the first int of each is used). Implemented by walking each permutation cycle, shifting rows backwards, and marking visited entries with a temporary `+0x4000000` flag that is stripped from every entry at the end. `stride` must be `< 0x41` else returns `0x69`; `stride <= 0` moves no data but still walks the cycles. |

### Batch 24 — bit-shifted bitmap blit

| vendor RVA | vendor symbol | clean-room name | actual semantics |
|---|---|---|---|
| `0x18000fd90` | `fpc_bio_bep_sw23_0a86d32299` | `cr_bitmap_copy_shift` | `int fn(cr_image *dst, const cr_image *src, uint32_t bitoff, int rowoff)`. Blit a source bitmap into a destination bitmap at bit column `bitoff` and row `rowoff`, shifting source bits **left** by `bitoff & 31`. Both descriptors need `offx==offy==0` and `src->a <= dst->a`, else `0x69`. Source row length is `src->a` bits (`src->a>>5` words/row), `src->h` rows copied, destination stride `dst->a` bits. Word-aligned offset (`bitoff&31==0`): verbatim word copy. Otherwise: first dst word = `((d<<s)>>s) | (src[0]<<s)` (keeps low bits of dst), then `dst[k] = (src[k]<<s)|(src[k-1]>>(32-s))`, and — only when `dst->a > src->a` — one carry word `(src[last]>>(32-s)) | ((d>>s)<<s)` one past the region. Verified against the assembly (the `(d<<s)>>s` is a logical `shr`, clearing the top bits). |

### Batch 25 — right-shifted bitmap extract

| vendor RVA | vendor symbol | clean-room name | actual semantics |
|---|---|---|---|
| `0x18003e590` | `fpc_bio_bep_sw23_cb8639ce35` | `cr_bitmap_extract_shift` | `int fn(cr_image *dst, const cr_image *src)`. Extract a `dst->a`-bit-wide, `dst->h`-row window from `src` at bit column `src->offx` and row `src->offy`, shifting source bits **right** by `src->offx & 31`; the last destination word is masked with `0xffffffff >> ((dst->a - dst->w) & 31)`. `dst` must have `offx==offy==0` and `src->a >= dst->a`, else `0x69`. Word-aligned: verbatim copy. Otherwise `dst[k] = (src[k+1]<<(32-s)) | (src[k]>>s)` and the last word `(src[dst_words-1]>>s) [| src[dst_words]<<(32-s) when src->a > dst->a]`, all `& mask`. |

### Batch 26 — column-wise 7-tap clamped int16 FIR

| vendor RVA | vendor symbol | clean-room name | actual semantics |
|---|---|---|---|
| `0x18001c280` | `fpc_bio_bep_sw23_326e82e939` | `cr_fir7_s16_col` | `int fn(cr_image *dst, const cr_image *src, const int16_t *coef)`. The **column-wise twin** of `cr_fir7_s16`: the same 7-tap edge-clamped FIR, run down each of the `w` columns (`h` samples, step `a`) instead of across each row. Same canonical-descriptor guard (returns `0x69`). Factored with `cr_fir7_s16` into a shared 1-D helper `fir7_1d(out, base, n, stride, coef)`. |

### Batch 27 — masked per-column mean correction

| vendor RVA | vendor symbol | clean-room name | actual semantics |
|---|---|---|---|
| `0x18000d8e0` | `fpc_bio_bep_sw23_02a79f65fe` | `cr_bitmap_mean_correct` | `int fn(cr_image *img, const cr_image *bm, const uint8_t *cfg)`. `cfg[9]` is a mode byte: `0` → `0`, `2` → run, else `0x69`; mode 2 needs `r0=cfg[0xc]`, `r1=cfg[0x10]+r0`, `r1 <= img->w` and `img->h > 29`, else `0x69`. A **global** mean is taken over set bits of bitmap rows `bm->offy+r0 .. r1-1`, columns `bm->offx .. offx+h-1` (sampling `img->data[row + k*img->w]`). Then for every image column `col` in `[0,img->w)` a **local** mean is taken over bitmap row `bm->offy+col` (same span) and, if that row has a set bit, every pixel of the column becomes `clamp((int)(p + global - local), 0, 255)`. All sums 32-bit; single-precision division/addition in exactly the written order. |

### Batch 28 — bit-packed sign signature of a filter bank

| vendor RVA | vendor symbol | clean-room name | actual semantics |
|---|---|---|---|
| `0x180043db0` | `fpc_bio_bep_sw23_e809dd007c` | `cr_signpack_dot` | `int fn(uint8_t *out, const void *const *inpp, const uint8_t *cfg)`. `cfg[0x10]` = 16-byte-aligned matrix pointer, `cfg[4]` = window size `m`, `cfg[8]` = signed byte `b8` with output count `n = b8/2`; `*inpp` = input window. Guards: NULL matrix → `0x69`, misaligned → `1`, `n <= 0` → `0`. For each matrix row `i` the window (`m*m` bytes) is scanned forward and backward; each matrix entry (16 bytes = 8 int16, stride `b8*8` bytes) is split `lo`=entries 0..3 / `hi`=4..7 (sign-extended to int32). Four 4-lane 32-bit SIMD dot products `A=Σlo*in[k]`, `B=Σhi*in[k]`, `C=Σlo*in[nwin-1-k]`, `D=Σhi*in[nwin-1-k]` are reduced to sign bits: `out[i]=pack(A,B)`, `out[i+n]=pack(C,D)` with `pack(P,Q)=Σ_l (P[l]>0?1<<l:0)|(Q[l]>0?0x10<<l:0)`. The packing constants at `0x18008c470`/`0x18008c480` are `{1,2,4,8}` and `{0x10,0x20,0x40,0x80}`. |

### Batch 29 — u8→i16 shift widen + symmetric border extend

| vendor RVA | vendor symbol | clean-room name | actual semantics |
|---|---|---|---|
| `0x1800337e0` | `fpc_bio_bep_sw23_9bbd6b7a97` | `cr_u8_to_u16_shifted` | `void fn(cr_image *dst, const cr_image *src, int16_t shift)`. Widens each byte of `src` to int16 in `dst` (both packed, row stride = `src->w`). `shift>0`: `(uint16)in << (shift&31)`; `shift==0`: `in`; `shift<0`: `sh=(-shift)&31`, `rnd=(int16)(1u<<sh)>>1`, `out=(int16)(((uint32)in+(uint32)rnd)>>sh)`. |
| `0x180028930` | `fpc_bio_bep_sw23_6f845fb02c` | `cr_mirror_extend_s16` | `void fn(cr_image *img, int top, int bottom, int left, int right)`. Symmetric (BORDER_REFLECT, edge repeated) extension of an int16 image. Reflection index `idx = v % (2n); if (idx>=n) idx = 2n-idx-1;` with `v` counting down from `n<<16` (top/left) or up from `(n<<16)+n` (bottom/right). Top/bottom bars fill only the middle `w` columns; left/right bars then fill the full frame height, so corners come from the already-extended frame. |

### Batch 30 — box sum excluding an index list

| vendor RVA | vendor symbol | clean-room name | actual semantics |
|---|---|---|---|
| `0x18000d040` | `fpc_bep_template_serialize` | `cr_box_sum_excl` | `void fn(int width, int height, const uint8_t *data, const uint16_t *count, const uint16_t *const *indices, int win, int idx, int *out_count, float *out_sum)`. Window `[cy-hw,cy+hw] x [cx-hw,cx+hw]` (`hw=win>>1`, `cy=idx/width`, `cx=idx%width`, clamped to the image). For every pixel whose linear index `r*width+c` is **not** among the `*count` u16 entries of `*indices`, add the byte to `*out_sum` (as float) and bump `*out_count`. `*count==0` sums everything. Both outputs zeroed up front. (The vendor symbol name is noise.) |

### Batch 31 — 15x15 separable box filter (int16) + edge replication

| vendor RVA | vendor symbol | clean-room name | actual semantics |
|---|---|---|---|
| `0x180032830` | `fpc_bio_bep_sw23_97ae28484f` | `cr_boxsum15_s16` | `void fn(int16_t *base, int W, int H)`. Four in-place passes producing `(sum*0x1111+0x8000)>>16` (≈ `sum/15`): (1) horizontal 15-tap running sum into cols `0..W-15` of every row; (2) vertical 15-tap running sum, reading columns `W-15..0` right-to-left and writing 7 columns/rows to the right, so the result lands at rows `7..H-8`, cols `7..W-8`; (3) horizontal edge replication over rows `7..H-8` (col 7 → cols 0..6, col W-8 → cols W-7..W-1); (4) vertical edge replication over every column (row 7 → rows 0..6, row H-8 → rows H-7..H-1). The top-left 8x8 block ends up constant. |

### Batch 32 — byte twin of the 15x15 separable box filter

| vendor RVA | vendor symbol | clean-room name | actual semantics |
|---|---|---|---|
| `0x18001aaa0` | `fpc_bio_bep_sw23_311b05823c` | `cr_boxsum15_u8` | `void fn(uint8_t *base, int W, int H)`. Byte twin of `cr_boxsum15_s16`: same four in-place passes (horizontal running sum, vertical running sum, horizontal edge replication, vertical edge replication) but byte samples and the rounding constant `0x800` (sums ≤ 15*255), output `(sum*0x1111+0x800)>>16`. |

### Batch 33 — u8 row widen + reflect-101 padding + m-tap symmetric FIR

| vendor RVA | vendor symbol | clean-room name | actual semantics |
|---|---|---|---|
| `0x18003ecc0` | `fpc_bio_bep_sw23_cd9632fb7f` | `cr_u8_expand_convolve` | `void fn(int16_t *out, uint16_t *scratch, const uint8_t *in, const int16_t *coef, int n, int m)`. Widen a byte row to int16 with reflect-101 (BORDER_REFLECT_101) padding into `scratch` (`pad = m>>1`; `scratch[pad+i]=in[i]`, left `scratch[j]=in[pad-j]`, right `scratch[pad+n+j]=in[n-2-j]`), then run an m-tap FIR: `out[i] = (int16)((Σ_{k<taps} coef[k]*scratch[i+k] + 0x100) >> 9)`. The output is split into a 4-wide unrolled region (`i < bound`, `bound = 4 + 4*((n-4)>>2)`, 0 when `n<=3`) and a scalar tail (`i >= bound`). **Quirk:** the unrolled region consumes `3 + 2*((m-2)>>1)` taps = `m` for **odd** m but `m+1` for **even** m (it reads `coef[m]`); the tail always consumes exactly `m`. The public entry `FUN_180021700` rejects even m (`if ((m&1)==0) return 1`), so the extra tap only fires via the two other callers `FUN_180010440` / `FUN_18002af00`. Both regions are reproduced verbatim so parity holds for every m. |

### Batch 34 — spatial top-K accumulator

| vendor RVA | vendor symbol | clean-room name | actual semantics |
|---|---|---|---|
| `0x18002f070` | `fpc_bio_bep_sw23_861d4887f0` | `cr_grid_insert` | `int fn(cr_grid *g, uint8_t x, uint8_t y, float v, cr_grid_cfg *cfg)`. Map `(x,y)` to a `W*H` cell (`px = x*W/divx`, `py = y*H/divy`, both clamped), then push the sample onto that cell's singly-linked list of `cap` pooled slots, kept in **ascending** value order (head = smallest). When the pool is full, pick the cell with the largest `key*val` score (the target cell is seeded with `(key+1)*val` — a quirk; all other cells use `key*val`), evict its list head and reuse the freed slot. `cfg->mode==2` instead appends to flat `coords2`/`values2` arrays (bounded by `cfg->cap2`); any other mode returns `0x69`. `node.val` is read but never written by this leaf (a caller accumulates it). |

### Batch 35 — bitmap set-bit centroid

| vendor RVA | vendor symbol | clean-room name | actual semantics |
|---|---|---|---|
| `0x18002ddd0` | `fpc_bio_bep_sw23_82f9a9e315.part.9` | `cr_bitmap_centroid` | `int fn(const cr_bitmap_desc *bm, int win_h, int win_w, int *out_y, int *out_x, int margin)`. Scans the masked bitmap accumulating count, Σ row and Σ column of the set bits, then returns the centroid shifted by half the window and clamped: `out_y = min(h-win_h-margin, max(rowsum/count - win_h/2, margin))`, likewise `out_x`. Guards `win_h <= h-2*margin && win_w <= w-2*margin`, else `0x82` **without writing the outputs**. Only the last word of each row is masked (first loop pass); 32-bit accumulators; the all-zero/all-one word/byte fast paths are closed forms of the same sums. |
| `0x18002aeb0` | `fpc_bio_bep_sw23_769acc1eef` | `cr_desc_get_ptr1` | `uint64_t fn(void *p, char sel)`. Single pointer getter: `sel==4` → write table ptr, return 0; else write NULL, return 1. Cleanroom zeroes the pointer slot (no vendor tables); difftest compares return code only. |
| `0x180012f30` | `fpc_bio_bep_sw23_16c9802c18` | `cr_desc_get_ptr_size` | `uint64_t fn(void *p1, uint32_t *p2, char sel)`. `sel==0` → return 0 (zeroes); `sel==6` → write size 0x100, return 0; else return 1. Pointer slot zeroed in cleanroom. |
| `0x180020860` | `fpc_bio_bep_sw23_46f04b866a` | `cr_desc_get_ptr2` | `uint64_t fn(void *p, char sel)`. `sel==12` or `sel==13` → return 0; else return 1. Pointer slot zeroed. |
| `0x18002dab0` | `fpc_bio_bep_sw23_81499c2105` | `cr_desc_get_tag_ptr` | `uint64_t fn(void *p, char sel)`. NULL-guarded; `sel==0` → write u64 tag `0x1f5_00000009`, return 0; else return 1. Pointer at +8 zeroed. |
| `0x1800448f0` | `fpc_bio_bep_sw23_eb7a7b573f` | `cr_desc_get_ptr2_69` | `uint64_t fn(void *p, char sel)`. `sel==0` or `sel==1` → return 0; else return 0x69. Pointer slot zeroed. |
| `0x180018e50` | `fpc_bio_bep_sw23_2db989eca6` | `cr_desc_get_ptr_ints` | `uint64_t fn(void *p1, uint32_t *p2, uint32_t *p3, char sel)`. `sel==0` or `sel==1` → write 9,9, return 0; else return 1. Pointer slot zeroed. |
| `0x180017960` | `fpc_bio_bep_sw23_25c6d755fa` | `cr_desc_get_ptr_size_69` | `uint8_t fn(void *p1, uint32_t *p2, char sel)`. `sel==15` → size 0x620; `sel==16` → size 0x100; `sel==0` → return 0 (zeroes); else return 0x69. |
| `0x180028de0` | `fpc_bio_bep_sw23_702329d57c` | `cr_desc_get_tag_byte_ptr` | `uint64_t fn(void *p, char sel)`. NULL-guarded; `sel==2` → byte 0x10 + tag `0x1_00000019`; `sel==4` → byte 4 + same tag; else return 1. Pointer at +0x10 zeroed. |
| `0x18002d4e0` | `fpc_bio_bep_sw23_7c99980763` | `cr_desc_get_triple` | `uint64_t fn(void *p, uint8_t sel)`. `sel>=6` → 0x69; NULL-guarded; `sel==0` → zeroes, return 0; `sel==5` → tag `0x2_00000010`, return 0; else 1. Pointers at +8,+0x10 zeroed. |
| `0x180043a50` | `fpc_bio_bep_sw23_e789d2446e` | `cr_tri9_filter` | `void fn(float *in, float *out, int n)`. 9-tap triangular (Bartlett) filter (weights `[1,2,3,4,5,4,3,2,1]`) applied along each of the 9 lines of an `n x 9` float buffer (row stride 9; line `t` = elements `t, t+9, ...`). Sliding-window recurrence `out[r] = out[r-1] - Σ_{i=r-5}^{r-1} c[i] + Σ_{i=r}^{r+4} c[i]` (`c[k]=in[t+9k]`), with a triangular warm-up for rows 0..4 (out-of-range taps contribute 0) and the last four rows using the same recurrence with the out-of-range "add" taps dropped (4/3/2/1 adds for rows n-4/n-3/n-2/n-1). No guard; the vendor assumes `n >= 9` (reads/writes stay within `9*n`). **Loop-count quirk:** the outer line loop is fixed at 9 (computed from `[RSP+8] - R9 = 36` bytes), independent of `n`. **Pointer-bias trap:** the R10/R11/RBX tail blocks pre-increment their base pointer (`q = base+1`), so the *raw* byte offsets `-0xb8,-0x94,...` (= `-46,-37,...` floats) must be used verbatim, not `-45,-36,...`. Float op order transcribed verbatim. |
| `0x180030fc0` | `fpc_bio_bep_sw23_91ea5ea28d.isra.6` | `cr_fir_reflect` | `int fn(int16_t *out, const int16_t *in, const int16_t *coef, int p4, int W, int L)`. Reflect-101-padded int16 FIR down each column: gather `buf[i] = in[c + i*W]`, then `K = clamp(p4, 0, L-1)`, `H = K>>1`, `out[c + j*W] = (int16)((Σ_{k=0}^{K-1} coef[k]*buf[refl(j-H+k)] + 0x4000) >> 15)` for `j = 0..L-1`, with BORDER_REFLECT_101 (`refl(i) = -i` for `i<0`, `2*(L-1)-i` for `i>=L`). The vendor splits this into a descending left pass, a plain middle pass (`j ∈ [H, L-H)`) and a descending right pass; since the accumulation is integer and order-independent the closed form is bit-identical (passed the difftest on the first run). Uses a 256-short stack buffer (so `L <= 256`); returns 0; `W <= 0` is a no-op. |
| `0x180040560` | `fpc_bio_bep_sw23_d8d4223a88` | `cr_fir_reflect_rows` | `int fn(int16_t *out, const int16_t *in, const int16_t *coef, int p4, int W, int R)`. The **row-wise twin** of `cr_fir_reflect`: the same reflect-101 FIR but applied along contiguous rows (stride 1) and run over `R` rows. `K = clamp(p4, 0, W-1)`, `H = K>>1`, `out[r*W + j] = (int16)((Σ_k coef[k]*buf[refl(j-H+k)] + 0x4000) >> 15)`. Shares the static helper `fir_reflect_line`. Passed the difftest on the first run. |
| `0x180033b40` | `fpc_bio_bep_sw23_9d0de274f8` | `cr_fir7_reflect` | `void fn(int16_t *out, const int16_t *in, const int16_t *coef, int W, int R)`. The **fixed 7-tap** member of the reflect-101 FIR family: same as `cr_fir_reflect_rows` but with `K=7`, `H=3` hard-coded, so `out[r*W + j] = (int16)((Σ_{k=0}^{6} coef[k]*in[r*W + refl(j-3+k)] + 0x4000) >> 15)`. Args are `(out, in, coef, W, R)` — note `W` in `r9d` and `R` as the 5th stack arg (opposite order from the twins). The vendor unrolls two outputs per iteration with an odd/even-dependent tail; the closed form is bit-identical. Because the kernel is *not* clamped to `n-1`, the 7-wide window spans more than one reflect period for `W < 4`; in that degenerate domain the vendor's overlapping single-fold edge passes read into the neighbouring row (confirmed by an index-map probe `difftest … probe7`). The rewrite is the well-defined `refl101` and matches for all `W >= 4`; the difftest exercises `W >= 4`. |
| `0x18002c600` | `fpc_bio_bep_sw23_79a4530e21` | `cr_box_mean_f32` | `int fn(void *dst_desc, void *src_desc, int mode)`. In-place separable box mean over a float image. Descriptor: `+0x08 = float *data`, `+0x10 = w (uint)`, `+0x14 = h (uint)`. `w` and `h` must both be even, else `0x69`. `mode == 3` → 3×3 box mean (×`0x3de38e39` ≈ 1/9); `mode != 3` → 5×5 box mean (×`0x3d23d70a` ≈ 0.04). Two passes — horizontal then vertical — each a clamp-to-edge box sum accumulated left-to-right (ascending index); the vertical pass multiplies by the 1/k² constant. The vendor runs both passes in place, reading ahead and retaining the overwritten samples in shift registers; the rewrite reproduces this with a two-deep per-line history so the result is identical for `dst == src` and `dst != src`. The separable clamp-box structure and the exact divisor constants were recovered with an impulse-response probe (`difftest … probe_box`); passed the difftest on the first run. Note `mode` is passed as an `int` in `r8d`, not a byte. |

| `0x18003bf90` | `fpc_bio_bep_sw23_beb4df26c0` | `cr_sort_records` | `int fn(void *recs, int n, int key_type, int dir)`. Stack-based Hoare quicksort over `n` records of `{uint32_t v; uint32_t key;}` (8 bytes, key at `+4`). `key_type == 0` compares the key as `int32_t`, `1` as `float32`; `dir == 0` sorts ascending, `1` descending; any other selector returns `0x69`. `n > 0x100000` is a no-op returning `1`; otherwise returns `0`. Pivot index is `(lo + hi + 1) >> 1`. The partition walks `i` up while the key stays on the ordered side of the pivot and walks `j` down, swapping the first out-of-place pair (for ascending: advance while `key_i < pivot`, swap when `key_j <= pivot`; descending mirrors the operands). After partitioning it pushes both sub-ranges and immediately processes the **smaller** one, deferring the larger on an explicit stack of `(lo, hi)` dword pairs (40 dwords in the vendor frame). A plain C `<` reproduces the vendor's `UCOMISS`/`JA` (float) and `CMP`/`Jcc` (int) exactly, including NaN keys (an unordered `UCOMISS` clears neither CF nor ZF, so `JA` is not taken just as `<` yields false). |

| `0x180020230` | `fpc_bio_bep_sw23_45dc1beabd` | `cr_line_orient_fit` | `void fn(float *samples, int px, int py, float stepx, float stepy, const void *desc, float *out_m, float *out_res)`. Samples 10 points along a line through a 16-bit image (bilinear, clamp-to-edge; the line starts at `(px+stepx, py+stepx)` and steps by `(stepx, stepy)`), then fits 9 orientation hypotheses against those samples. Descriptor: `+0x00 int stride`, `+0x08 const int16_t *data`, `+0x10 int w`, `+0x14 int h`, `+0x18 int offA`, `+0x1c int offB`; pixel index = `x + offA + stride*(y + offB)`. Each hypothesis k projects the samples onto a fixed (sin, cos) pair `S[k][j]`/`C[k][j]` giving `sum`, `A = Σ cos_j v_j`, `B = -Σ sin_j v_j`, then a 3-parameter model `(m0, m1, m2)` from a 9-coefficient row `C[k]` plus the centre sample; `out_m[3k..3k+2] = (m0,m1,m2)`, `out_res[k] = Σ_j (v_j - ((cos_j*m1 - sin_j*m0) + m2))²`. Model 0 uses inline constants, models 1..8 use the rows of the coefficient table at `0x1801450e8`; hypothesis k uses orientation group k of the sin/cos table at `0x18008ec40` (each group = 16 sin + 16 cos floats, first 10 of each used). All constants are exact hex-float literals transcribed from the vendor data sections; every float evaluation order (including the two-level `(a+b)+c` groupings) is reproduced verbatim. Passed the difftest on the first run. |
| `0x1800433b0` | `fpc_bio_bep_sw23_e6dfc8ce14` | `cr_vfir7_cols` | `void fn(int16_t *out, const int16_t *in, const int16_t *coef, int n, int sel)`. The **column-wise twin** of `cr_fir7_reflect`: a fixed 7-tap reflect-101 int16 FIR, but run *down* columns of stride `n` instead of along contiguous rows. `n` (`r9d`) is both the row stride and the column count; `sel` (5th stack arg) is the line length. For each column `c` (0..`n-1`): `out[c + j*n] = (int16)((Σ_{k=0}^{6} coef[k]*in[c + refl101(j-3+k, sel)*n] + 0x4000) >> 15)` for `j = 0..sel-1`. The vendor keeps a folded/rotating 7-short sliding window, emits two outputs per inner iteration plus a parity-dependent 3-or-4-row tail, and takes a separate branch when `sel <= 4` (`iVar35 < 1`). The tap→input-row map was recovered with an impulse-response probe (`difftest … probe_lf`, per-tap delta coefficients with an `in[r][c]=r+1` ramp), which showed the top/bottom reflection is exactly `refl101(i, sel)`. As with `cr_fir7_reflect`, a 7-tap window spans more than one reflect period for `sel < 4`, where the vendor's overlapping single-fold passes read the neighbouring column; the rewrite is the well-defined `refl101` and matches for all `sel >= 4`, the domain the difftest exercises. Passed the difftest on the first run. |

## Deferred (identified, not yet rewritten)

| vendor RVA | vendor symbol | why deferred |
|---|---|---|
| `0x180030340` | `fpc_bio_bep_sw23_8d79fe3601` | returns static table pointers — needs the table contents. |
| `0x180048d40` | `fpc_bio_init` | returns `*(void**)0x18016f4c8 + 8` — a global-context getter (pointer-valued, out-of-tree). |

These are pointer/table-valued, so bit-exact comparison needs a structural (not
address) check; they will be handled once the referenced tables are established.

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
