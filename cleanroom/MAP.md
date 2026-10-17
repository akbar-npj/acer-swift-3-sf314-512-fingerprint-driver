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
| `0x18000f6f0` | `fpc_bio_bep_sw23_06ea123a28` | `cr_masked_sharpness` | `int fn(int *out, const cr_image *src, void *const *mask)`: allocate a `src->w × src->h` u8 image, `cr_fir7_image_u8(&local, src, 0.5f)`; then over `n=w*h` accumulate `sumsq += (float)(d*d)` and `cnt += 1.0f` (both starting at 0/1) where `mask[i]==0xff`, `d=(int)(uint32_t)src[i]-(int)(uint32_t)blur[i]`; `*out = (int)((sumsq*1024.0f)/cnt)` — all **single precision**. |
| `0x180033f60` | `fpc_bio_bep_sw23_9d96566ff4` | `cr_masked_sharpness_f32` | `int fn(int *out, const float *const *src, int w, int h, void *const *mask)`: float-source twin of `cr_masked_sharpness`. Alloc two u8 images; if `w*h<1` just `cr_fir7_image_u8(blurred,bytes,0.5f)` and `*out=0`. Else round each `x=(*src)[i]` to `bytes[i]=(uint8_t)(int)(x+0.5f)`, returning **200** if `x>=255.5f || 0.0f > x+0.5f`; blur; masked `sumsq`/`cnt`; `*out=(int)((sumsq*1024.0f)/cnt)`. |

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
| `0x18003f060` | `fpc_bio_bep_sw23_d0814404fa` | `cr_bitmap_fill_extents` | `int fn(cr_image *dst, const cr_image *src)`: require both full (`a==w,b==h,offx==offy==0`) and same `w,h` else 0x69; `wpr=w>>5`. Phase 1 per word-column: `suffix[i]=OR_{j>=i}src[j]`, `prefix[i]=OR_{j<=i}src[j]`, `dst[i]=suffix[i]&prefix[i]` (via an `h`-word tmp). Phase 2 per row: `L,R` = leftmost/rightmost nonzero word; fill words `(L,R)` exclusive with `0xffffffff`, `word[L]=smear_right(word[L])`, `word[R]=smear_left(word[R])`, and when `L==R` `word[L]=smear_left&smear_right`. |

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
| `0x18002e6a0` | `fpc_bio_bep_sw23_85057ad42a` | `cr_sep11_row` | `void fn(int16_t *out, const uint8_t *in, const int16_t *coef, int w, int s)`. A **separable 11x11 int16 FIR** applied to one output row: `in` is a byte image (zero-extended), `s` is the row stride in bytes, `w` is the output width. The (w+10)-short intermediate is held in `out` in place. Pass 1 (vertical) produces `mid[j] = (Σ_{d=-5..5} K[j][d]*in[(j-5)+d*s]) >> 12` for `j = 0..w+9`; pass 2 (horizontal) produces `out[i] = (Σ_{k=0..10} coef[k]*mid[i+k]) >> 12` for `i = 0..w-1`. **Quirk:** pass 1's 4-wide-unrolled bulk (`j < (w+10)&~3`) uses the *symmetric* kernel `K[d] = coef[5-|d|]` — the vendor only reads `coef[0..5]` there — while the scalar tail reads all 11 taps `coef[0..10]` (`K[d] = coef[d+5]`); the two coincide for a symmetric kernel and the rewrite reproduces both. Neither pass has a rounding bias (just arithmetic `>>12`); pass 2 accumulates in wrapping 32-bit since `coef*mid` can exceed int32. Recovered from the pseudocode + assembly (`[rsp+0xb0]` = `s`, `[rsp+0xa8]` = `w`); passed the difftest on the first run with random `coef[0..10]`. |
| `0x180038ac0` | `fpc_bio_bep_sw23_b3a74c54eb` | `cr_corr_kbank` | `int fn(int32_t *out, const int16_t *in, const int16_t *kbank, const int16_t *selarr, long long unused, int ow, int oh, int iw, int ih, int K)`. A **per-pixel kernel-bank 2D correlation**: for each output pixel `(r,c)`, `sel = selarr[r*ow + c]` picks a `KxK` kernel from the bank and the `KxK` input window at top-left `(r,c)` is correlated with it — `out[r*ow + c] = Σ_{ky,kx} in[(r+ky)*iw + c+kx] * kbank[sel*K*K + ky*K + kx]` (int32 result). Guards: `iw < ow-1+K` or `ih < oh-1+K` → `1`; the K==15/K==7 paths add `iw <= ow+13`/`ih <= oh+13` (resp. +5) → `0x69` and K==17 adds `iw <= ow+15` → `1` (all four unreachable once the initial guards pass); `K < 1` writes all-zero outputs; returns `0`. **Two traps:** (a) the 5th argument is an unused **8-byte** slot — dropping it shifts every stack argument (the initial guards then silently disagree), so it must stay in the signature; (b) the K==17 body processes output columns in **groups of 4 aligned to `ow-4`**, so for `ow < 4` it writes before the output buffer (a vendor quirk) — the well-defined domain is `ow >= 4`, which is what the difftest exercises. The K=15/17/7 bodies are 4-wide-unrolled specialisations with identical integer accumulation; the rewrite is the closed form (wrapping 32-bit accumulate). Passed after fixing the 5th-arg layout and restricting `ow >= 4` for K==17. |

### Batch 47 — object-tree lifecycle helpers + image-data accessors

These are the first **non-leaf** functions rewritten after the leaf frontier was
exhausted: each calls only helpers already parity-verified (`cr_malloc`,
`cr_free`, `cr_sized_free`, `cr_buf_is_debug_class`, `cr_buf_is_pixels`,
`cr_meta_put_u32`).  Because they manipulate heap pointers, the observable
contract compared by the difftest is guard behaviour, NULL-ing, scalar writes,
and (where the input is shared) pointer identity — not raw pointer values.

| vendor RVA | vendor symbol | clean-room name | actual semantics |
|---|---|---|---|
| `0x18004b640` | `fpc_metadata_put_int16` | `cr_meta_put_i16` | `int fn(void *store, u32 key, u32 value, bool overwrite)`. Assembly is `MOVZX R9D,R9B; JMP 0x18004b670`: it zero-extends the overwrite flag and tail-calls the uint16 store, so it is semantically identical to `cr_meta_put_u32` (stores a `{key,size=4,value}` record). |
| `0x18000fc20` | `fpc_bio_bep_sw23_098428d710` | `cr_cleanup_ptr8_a` | `void fn(void *obj)`: `if (obj && *(void**)(obj+8)) cr_sized_free((void**)(obj+8));`. Frees the sized object held at `obj+8` (which `cr_sized_free` also NULLs). |
| `0x180011a50` | `fpc_bio_bep_sw23_1459ce6d3f` | `cr_cleanup_ptr8_b` | Byte-identical duplicate of `0x18000fc20`. |
| `0x180024760` | `fpc_bio_bep_sw23_5bc22e072c` | `cr_cleanup_ptr8_clear` | `void fn(void *obj)`: if `obj`, free `*(void**)(obj+8)` (if non-null) then **unconditionally** store NULL at `obj+8`. |
| `0x18001f9f0` | `fpc_bio_bep_sw23_42d43aea34` | `cr_obj_zero_free` | `void fn(void **obj)`: `p = *obj; if (p) { *(u64*)p = 0; *(u32*)((u8*)p+8) = 0; cr_sized_free(obj); }` — zero the first 12 bytes of the payload, then sized-free it and NULL the slot. |
| `0x180017170` | `fpc_bio_bep_sw23_2223670971.isra.3` | `cr_free_ptr_struct` | `void fn(void *obj)`: destroy an object owning eight sized pointers — six consecutive at `+0x00..+0x28`, then one at `+0x30` and one at `+0x70`. NULL is a no-op. (The vendor's `do/while` frees indices 0..4 in the loop and index 5 after; the rewrite frees 0..5 in one loop.) |
| `0x1800100c0` | `fpc_bio_bep_sw23_0bcc9b4ae6` | `cr_malloc_aligned16` | `int fn(void **out, size_t size)`: allocate `size + 0x10` via `cr_malloc`; on failure return `2`. Otherwise `n = 0x10 - ((uintptr_t)base & 0xf)` (in 1..16), store the size prefix `((u8*)base)[n-1] = n`, set `*out = base + n` (16-byte aligned) and return `0`. The prefix is never 0, so the block round-trips through `cr_sized_free`. A `size` of `-0x10` makes `size+0x10 == 0`, so `cr_malloc` returns 1 and the status is `2`. |
| `0x18004a890` | `fpc_image_data_get_dp_buffer` | `cr_image_get_dp` | `void *fn(const void *defs, u32 idx)`: if `defs && idx < 0x16`, fetch slot `idx` from the table at `defs+0x10` and return it only if `cr_buf_is_debug_class(p)`; else NULL. |
| `0x18004ab90` | `fpc_image_data_init_buffers` | `cr_image_buf_desc` | `void fn(const void *ctx, void *out)`: `p = ctx ? *(u8**)(ctx+0x18) : NULL`; if `p` is a pixels buffer (`cr_buf_is_pixels`), write `out+0x00 (i16) = (i16)*(u32*)(p+0x0c)`, `out+0x08 (ptr) = p+0x10`, `out+0x10 (i16) = (i16)(*(u32*)(p+0x04) >> 1)`, `out+0x14 (i32) = 1`; otherwise `out+0x00 = 0`, `out+0x08 = NULL`, `out+0x10 = 0`, `out+0x14 = 1`. |

### Batch 48 — object constructors / flag-driven destructors

The second wave of non-leaf functions.  These build or tear down the BEP object
tree on top of `cr_malloc_aligned16` / `cr_sized_free`.  Same difftest strategy
as batch 47: compare guard behaviour, NULL-ing, scalar fields, and allocator
side effects, never raw pointer values.

| vendor RVA | vendor symbol | clean-room name | actual semantics |
|---|---|---|---|
| `0x18000ee40` | `fpc_bio_bep_sw23_04faa0a17d` | `cr_free_obj_28_8` | `void fn(void *obj)`: always `cr_sized_free((void**)(obj+0x28))`; then, only if `*(u8*)(obj+0x50) & 1`, also `cr_sized_free((void**)(obj+8))`. No NULL guard (the free helper treats a NULL slot as a no-op). |
| `0x1800303d0` | `fpc_bio_bep_sw23_8dbe34c690` | `cr_meta_set_slot` | `uint8_t fn(const void *defs, u32 idx, int key, int value)`: `p = cr_image_get_dp(defs, idx)`; if `!p` return `0x6a`; else return `cr_meta_put_i16(p, key, value, true) != 0`. |
| `0x180046b80` | `fpc_bio_bep_sw23_f56cb91e79` | `cr_obj_init_58` | `uint64_t fn(void *obj)`: `cr_fill(obj, 0, 0x58)`, then redundantly zero the 8-byte slots at +8/+0x28/+0x48 and set `*(u32*)(obj+0x50) = -1`; returns 0. |
| `0x18002ad90` | `fpc_bio_bep_sw23_76795f570e` | `cr_alloc_handle` | `void fn(void **out)`: `if (cr_malloc_aligned16(out, 0x28)) return;` else `p = *out`; `*(u64*)p=0`, `*(u32*)(p+8)=0`, `*(u8*)(p+0xc)=0`, `*(u64*)(p+0x10)=~0`, `*(u64*)(p+0x18)=~0`, `*(u32*)(p+0x20)=~0`. (+0x0d..0x0f and +0x24..0x27 are left as the allocator returned them.) |
| `0x18003fb70` | `fpc_bio_bep_sw23_d52eeb3bb9` | `cr_alloc_400` | `int fn(void **out)`: `r = cr_malloc_aligned16(out, 0x38)`; if `r==0` zero the 0x38-byte payload, set `*(u32*)(p+4)=400` and `*(u64*)(p+8)=0`; return `r`. |
| `0x18001d820` | `fpc_bio_bep_sw23_3943c5f8d0.constprop.8` | `cr_image_alloc_u8` | `int fn(int *desc, int w, int h)`: NULL→1; `w<0||h<0`→`0x69`; write `desc[0]=desc[4]=w`, `desc[1]=desc[5]=h`, `desc[2]=desc[3]=desc[6]=desc[7]=0`; `w*h==0`→0; else `cr_malloc_aligned16((void**)(desc+2), (uint32_t)(w*h))` — a byte image. |
| `0x18003d790` | `fpc_bio_bep_sw23_c8dcdadf31` | `cr_image_alloc_s16` | The int16 twin: identical field writes, but the pixel allocation is `(long long)w * (long long)h * 2` (64-bit product). |
| `0x18000f570` | `fpc_bio_bep_sw23_05db73508b` | `cr_free_obj_flags` | `void fn(void *obj)`: flag-driven destructor. `f = *(u32*)(obj+0x74)`; `if (f&1) cr_cleanup_ptr8_a(obj+0x10)`; `if (f&2) cr_cleanup_ptr8_b(obj+0x50)`; `if (f&0x100) cr_sized_free((void**)(obj+0x88))`; `if (f&0x200) cr_cleanup_ptr8_clear(obj+0x30)`. The vendor reloads `f` after each free (reproduced verbatim). |
| `0x180029750` | `fpc_bio_bep_sw23_7346394a98` | `cr_bitmap_alloc` | `int fn(uint32_t *desc, u32 w, u32 h)`: NULL→1; `w<0||h<0`→`0x69`; write `desc[1]=desc[5]=h`, `desc[4]=w`, `desc[0]=(w+0x1f)&~0x1f` (row stride rounded to 32), `desc[2]=desc[3]=desc[6]=desc[7]=0`; `r=(int)(w+0x1f)>>5`; if `h*r==0`→0; else `cr_malloc_aligned16((void**)(desc+2), (long long)r*(long long)(int)h*4)` and zero all `(desc[0]*desc[1])>>5` dwords; on the (unreachable, since `desc[0]` is always 32-aligned) non-aligned branch it frees and returns `0x69`. |

### Batch 49 — higher-level destructors / accessors

| vendor RVA | vendor symbol | clean-room name | actual semantics |
|---|---|---|---|
| `0x180039390` | `fpc_bio_bep_sw23_b4a9504f57` | `cr_clz_or32` | `int fn(uint32_t x)`: `x ? cr_clz(x) : 0x20` (32). |
| `0x18003d430` | `fpc_bio_bep_sw23_c7c4fecba2` | `cr_free_8slot` | `void fn(void *obj)`: sized-free the eight owned pointers, in the vendor's order — `+0x00, +0x28, +0x38, +0x08, +0x18, +0x10, +0x48, +0x50`. No NULL guard (each free is a no-op on a NULL slot). |
| `0x180035740` | `fpc_bio_bep_sw23_a457bca0e1` | `cr_alloc_obj_58` | `int fn(void **out)`: NULL→1; `i = cr_malloc_aligned16(out, 0x58)`; if `i != 0` return `i`; else if `*out == NULL` set `i = 1`; else `i = cr_obj_init_58(*out)` and, if that returns 0, **return 0 without freeing**; otherwise `cr_sized_free(out)`; return `i`. (The 32-bit return was confirmed from the assembly — `MOV EAX, …` only.) |
| `0x18003a8d0` | `fpc_bio_bep_sw23_b664476fb3` | `cr_meta_get_slot` | `uint8_t fn(const void *defs, u32 idx, int key, u32 *out)`: `p = cr_image_get_dp(defs, idx)`; if `!p` return `0x6a`; else return `cr_meta_get_u32(p, key, out) != 0`. (Its callee `0x18004b3f0` is a thunk to `fpc_metadata_get_uint16`.) |
| `0x1800342d0` | `fpc_bio_bep_sw23_9eab7bca41` | `cr_subview_extend_s16` | `int fn(cr_image *img, int t, int b, int l, int r)`: `w2 = (img->w - l) - r`; `w2 < 0`→`0x69`; `h2 = (img->h - t) - b`; `h2 < 0`→`0x69`; `cr_image_subview(&local, img, l, t, w2, h2)`, then `cr_image_border_extend_s16(&local, t, b, l, r)`; return 0. Effectively "crop `(l,t)`-anchored `(w2,h2)` then pad the border back out". |
| `0x180037f10` | `fpc_bio_bep_sw23_aefaa44d78.isra.1` | `cr_subview_extend_u8` | The byte-image twin: identical crop + `cr_image_border_extend` (8-bit). |

### Batch 50 — nested destructor chain

| vendor RVA | vendor symbol | clean-room name | actual semantics |
|---|---|---|---|
| `0x18003fcd0` | `fpc_bio_bep_sw23_d6892b18e4` | `cr_free_8slot_wrap` | `void fn(void **slot)`: if `slot` is NULL return; if `*slot` non-NULL call `cr_free_8slot(*slot)`; then **unconditionally** `cr_sized_free(slot)` (which NULLs `*slot`; a no-op on a NULL `*slot`). |
| `0x18001c680` | `fpc_bio_bep_sw23_32f906bc87` | `cr_obj_destroy` | `void fn(void *obj)`: `cr_free_8slot_wrap((void**)(obj + 0x48))` then `cr_free_obj_28_8(obj)`. Frees only the owned sub-objects (and NULLs their slots); the object itself is released by the caller. |
| `0x180044ce0` | `fpc_bio_bep_sw23_ee965c1257.constprop.2` | `cr_wrap_destroy` | `void fn(void **slot)`: if `*slot` non-NULL, `cr_obj_destroy(*slot)` then `cr_sized_free(slot)` (frees the held object and NULLs `*slot`); if `*slot` is NULL, no-op. |
| `0x180043a10` | `fpc_bio_bep_sw23_e76dc431bf` | `cr_wrap_destroy2` | `void fn(void **slot)`: if `*slot` non-NULL, `cr_wrap_destroy((void**)((uint8_t*)*slot + 8))` then `cr_sized_free(slot)`; if `*slot` is NULL, no-op. |

### Batch 51 — small ready wrappers

| vendor RVA | vendor symbol | clean-room name | actual semantics |
|---|---|---|---|
| `0x180038720` | `fpc_bio_bep_sw23_b08a6243f0` | `cr_sized_free_if` | `void fn(void **slot)`: asm is `CMP qword [RCX],0 ; JZ ret ; JMP cr_sized_free` — `if (*slot) cr_sized_free(slot)`. No guard on the slot pointer itself. |
| `0x18001f640` | `fpc_bio_bep_sw23_406a45a1c8.isra.0.part.1` | `cr_free_pair8` | `void fn(void *obj)`: `cr_sized_free(obj); cr_sized_free(obj + 8)` (two consecutive slots, no guard). |
| `0x180033f40` | `fpc_bio_bep_sw23_9d5b96a246` | `cr_free_slot8` | `void fn(void *obj)`: `if (obj) cr_sized_free((void**)((uint8_t*)obj + 8))`. |
| `0x1800276a0` | `fpc_bio_bep_sw23_68cec20a19` | `cr_cleanup_ptr8_guard` | `void fn(void *obj)`: `if (obj) cr_cleanup_ptr8_a(obj)` — a NULL-guarded alias of `cr_cleanup_ptr8_a`. |
| `0x1800464b0` | `fpc_bio_bep_sw23_f2ad1c4415` | `cr_free_4slot` | `void fn(void *obj)`: sized-free four owned pointers, in the vendor's order — `+0x18, +0x00, +0x20, +0x28`. |
| `0x1800384c0` | `fpc_bio_bep_sw23_afa5254b16.part.5` | `cr_hi_bit_index` | `int fn(uint32_t x)`: `x ? 0x1f - cr_clz(x) : -1` — index of the highest set bit (floor log2), `-1` for zero. |
| `0x18004a910` | `fpc_image_data_get_payload_size_from_defs` | `cr_image_get_meta_dp` | `void *fn(const void *defs, u32 idx)`: `defs && idx<0x16` → `p = *(void**)(defs+0x10+idx*8)`; return `p` iff `cr_buf_is_metadata_class(p)`, else `NULL`. The **metadata-class** twin of `cr_image_get_dp` (debug class). |
| `0x18003b920` | `fpc_bio_bep_sw23_bc5ecf1262` | `cr_cleanup_ptr8_clear_b` | Byte-identical twin of `cr_cleanup_ptr8_clear`: `if (obj) { if (*(void**)(obj+8)) cr_sized_free(obj+8); *(void**)(obj+8) = NULL; }`. |
| `0x18000fd40` | `fpc_bio_bep_sw23_0a647d6e5c` | `cr_free_4args` | `void fn(void *p0, void *p1, void *p2, void *p3)`: copies each argument into a stack local and `cr_sized_free`s that local — i.e. frees exactly the four passed sized pointers. |

### Batch 52 — ready wrappers / allocators

| vendor RVA | vendor symbol | clean-room name | behaviour |
|---|---|---|---|
| `0x180046490` | `fpc_bio_bep_sw23_f24e438404.part.2` | `cr_free_4slot_guard` | `void fn(void *obj)`: `if (obj) cr_free_4slot(obj);` — NULL-guarded wrapper. |
| `0x180011890` | `fpc_bio_bep_sw23_126f4d9d64` | `cr_clear_6ptr` | Clears the sized slots at `obj + {0xa0,0x00,0x20,0x40,0x60,0x80}` via `cr_cleanup_ptr8_clear` (each frees and NULLs `slot+8`). |
| `0x18001f080` | `fpc_bio_bep_sw23_3dfa9d10cb` | `cr_bit_alloc` | `int fn(void **out, int n)`: `n<1` → `*out=NULL`, return 0. Else allocate `((n+7)&~7)>>3` bytes via `cr_malloc_aligned16`, then zero `(n+7)>>3` bytes. Returns the allocator's code. |
| `0x18001e8b0` | `fpc_bio_bep_sw23_3bec298cfe` | `cr_image_alloc_f32` | Descriptor init + 4-bytes-per-pixel buffer: `if(!img)1; if(w<0||h<0)0x69;` set `a=w,b=h,w=w,h=h,offx=offy=0,data=NULL`; `w*h==0` → 0; else `cr_malloc_aligned16(&data, (uint64_t)(uint32_t)(w*h) << 2)`. |
| `0x180026d00` | `fpc_bio_bep_sw23_64bb070921` | `cr_image_alloc_quarter` | Sets `d[8]=d[9]=0x40, d[10]=d[11]=2`, then `cr_image_alloc_u8(d, wi>>2, hi>>2)` with `wi=(w-4>-1)?w-4:w-1` (same for h). |
| `0x1800357a0` | `fpc_bio_bep_sw23_a549ff0d17` | `cr_copy_image_fields` | `if(b)`: copy `src1->w*src1->h*2` bytes from `*(src1+0x10)` to `b+0x58`; then, if `*(a+0x30)` non-NULL and `b+0x18` non-NULL, the same for the second descriptor. Returns 0. |
| `0x180038a50` | `fpc_bio_bep_sw23_b21591478d` | `cr_sqrt_q16` | Q16 integer sqrt: normalise `v = x << ((clz(x)-1)&0x1e)`, two Newton iterations from `(v>>16)+0x4000`, then `((v/g+g)>>1) << ((0x10-((clz-1)>>1))&0x1f)`. |
| `0x180032530` | `fpc_bio_bep_sw23_967c7ea01c` | `cr_u8_to_u16_guarded` | Guard both descriptors full-view (`a==w`, `offx==offy==0`), then `cr_u8_to_u16_shifted`; else 0x69. |
| `0x180024e60` | `fpc_bio_bep_sw23_5f6c1365bf` | `cr_copy_u16_shl_guarded` | Guard `dst->w==src->w && dst->h==src->h`, then `cr_image_copy_u16_shl`; else 0x69. |
| `0x1800280d0` | `fpc_bio_bep_sw23_6d0a2edcde` | `cr_fir_reflect_guarded` | Validate K/W/L (K==7 or 0xf fast paths with `W&7==0`, L≤256; else `0≤K<L≤256`), then `cr_fir_reflect`; else 0x69. |
| `0x18002d960` | `fpc_bio_bep_sw23_7fead33409` | `cr_fir_reflect_rows_guarded` | Row twin of the above; returns 1 (not 0x69) on validation failure; else `cr_fir_reflect_rows`. |
| `0x180010e60` | `fpc_bio_bep_sw23_0fbb842e61.part.2` | `cr_palette_remap` | If `flag[0x3d]!=0`: allocate `count*2` at `obj+0x18` (obj=`*(ctx+0x48)`, count=`*(obj+0x20)`), then for each `i` in `count` look up `lut[src[2i+1]*mult + src[2i]]` (`lut=lut_desc->data`, `mult=lut_desc->w`) into `dst[i]`. Returns the allocator code. |
| `0x1800388b0` | `fpc_bio_bep_sw23_b198c93f89` | `cr_bitmap_build_masked` | `int fn(cr_image *out, const cr_image *src, const void *cfg)`: `r = cr_image_alloc_u8(out, src->w, src->h)`; if `r==0` run `cr_mask_boxmax_fir_clear(out, src, 0xf, 1, 1, *(float*)(cfg+0x48))`; on failure free `out->data` via `cr_cleanup_ptr8_a` and return that error; else return `r`. |
| `0x18001f660` | `fpc_bio_bep_sw23_4142dcc8d3.part.1` | `cr_bitmap_unpack_boxmax_fir` | Unpack a packed bitmap into `out` (`idx=(offy+y)*a+(offx+x)`, bit `(word[idx>>5]>>(idx&31))&1`), then `k`-box-sum → `(==k*k)?0xff:0` threshold → `niter` × `cr_fir7_image_u8(out,out,sigma)`; `k` even → 0x69. Bitmap-source twin of `cr_mask_boxmax_fir_clear` (no bit-2 clear). |

### Batch 53 — ready wrappers (size 160–500)

| vendor RVA | vendor symbol | clean-room name | behaviour |
|---|---|---|---|
| `0x18000d310` | `fpc_bio_bep_sw23_00445c6288` | `cr_shuffle_indices` | `void fn(int *arr, int n, uint64_t seed)`: fill `arr[i]=i`, then `n*10` Fisher–Yates swaps using `cr_prng_range(&state,0,n)` twice per iteration (`state=(uint32_t)seed`). |
| `0x1800363b0` | `fpc_bio_bep_sw23_a87c7724d4` | `cr_softmax2` | Two-way softmax: `s = 2^-24 * (float)*(u32*)(ctx+0x20)`; `a=vals[0]*s*2^-14`, `b=vals[1]*s*2^-14`, `m=(b<=a)?a:b`; `*out = expf(a-m)/(expf(b-m)+expf(a-m))`. |
| `0x180038930` | `fpc_bio_bep_sw23_b19b9db308` | `cr_centroid_affine` | If `1.0f<=scale<2.0f`: `r=cr_bitmap_centroid(bm,win_h,win_w,&y,&x,margin)`; if `r==0` build the 2×3 affine (`q=0x40000000/(int)(scale*32768)`, off-diagonal 0, translation from centroid + window) into `out[0..5]`; else 0x69. |
| `0x180030ea0` | `fpc_bio_bep_sw23_91ac20e376` | `cr_running_avg` | Per-sample running average: for `src[i] < 250`, bump the saturating counter `cnt[i]` up to `*limit`, then `dst[i] = roundf((dst[i]*2^-6*(c-1) + s*k)/c*64)` clamped to 0x7fff. |
| `0x180012260` | `fpc_bio_bep_sw23_15363dfc49` | `cr_atan2_fixed` | Fixed-point atan2: octant reduction (iVar7 base `0x8000000`/`0xc8000000`/`+0x10000000`/`+0x20000000`), normalise `uVar6` by `clz-1`, `q=num/den`, then a Q15 polynomial `a4*-0x1ce + a2*-0xd46 + q*0x28bc + a3*0x657 + base`. Domain is 16-bit inputs (the vendor IDIV faults beyond). |
| `0x1800335e0` | `fpc_bio_bep_sw23_9b7f284e32` | `cr_box_mean_edge` | Moving-average box filter with edge replication: `w<2` → copy; `half=lroundf(w*0.5f)`; `out[0..half-1]=Σin[0..w-1]/w`; sliding `out[k]=(in[k]-in[k-w])*inv+out[k-1]` for `k=half..iVar3`; then replicate `out[iVar3]` to the tail. |

### Batch 54 — ready wrappers (size 192–512)

| vendor RVA | vendor symbol | clean-room name | behaviour |
|---|---|---|---|
| `0x18003ce10` | `fpc_bio_bep_sw23_c5b206e5b7` | `cr_atan2_image_u8` | Per-pixel orientation map: `dst[i] = (u8)((cr_atan2_fixed(b[i], a[i]) + 0x400000) >> 23)`; `dst` is u8, `a`/`b` int16, all packed with row stride `dst->w`. |
| `0x180037ac0` | `fpc_bio_bep_sw23_ad2e23e159` | `cr_gain_normalize_u8` | Ridge gain normalisation (guard `w&7`): phase 1 sums `(0xff-p)` per column mod 8; gain `= (Σacc[1..6] << sh) / ((3*(acc[7]+acc[0]) << sh) >> 15)`, `sh=min(clz-1)&31`, default 0x8000; phase 2 rewrites **only lanes 0 and 7** of each 8-column group: `v=((0xff-p)*gain)>>15; p=~v` (0 if `v>=0xff`). |
| `0x1800175b0` | `fpc_bio_bep_sw23_2464d11c20` | `cr_gain_normalize_s16` | int16 twin: base 0x3fc0, shift 12, default gain 0x1000, `u4 = Σacc[1..6]/3` (signed); phase 2 `v=((0x3fc0-p)*gain)>>12; p=(int16)(0x3fc0-v)` (0 if `v>=0x3fc0`). |
| `0x180044040` | `fpc_bio_bep_sw23_e8ff948c05.isra.1` | `cr_affine_sample_s16_nn` | Nearest-neighbour int16 affine resample: Q20 map `{x_col,x_row,x_org,y_col,y_row,y_org}`, accumulators start at `(int)(org*2^20)+0x80000`, out-of-bounds dst pixels take `fill`. |
| `0x180040ea0` | `fpc_bio_bep_sw23_dbf0b0038b` | `cr_weighted_running_avg` | `fs=src[i]/255; f5=state[i]*2^-4+fs; f4=min(limit,f5)`; if `f4>0`: `state[i]=roundf(f4*16)`, `dst[i]=roundf(((dst[i]*2^-6*(f4-fs))+fs*(img[i]*k))/f4*64)` clamped 0x7fff. |
| `0x18003b690` | `fpc_bio_bep_sw23_bb6f7bbe81` | `cr_pool_builder` | Build a descriptor pool: alloc `4n+0xf+Σ((sizes[i]+0x13)&~0xf)`, store the n u32 sizes at the front, then n 16-aligned sub-blocks each ending in a trailer `{u8 i, 0, 0x30, 0x27}`; `ptrs[i]` = block start; `hdr = {base, u8 n, u8 4}`. Returns the allocator status (0 ok, 2 on failure). |

### Batch 55 — pool users + ready wrappers

| vendor RVA | vendor symbol | clean-room name | behaviour |
|---|---|---|---|
| `0x180014110` | `fpc_bio_bep_sw23_1a1610649e` | `cr_affine_sample_u8_nn` | Byte twin of `cr_affine_sample_s16_nn`: same Q20 map/accumulators, in-bounds test folded to `0<=x<src->w && 0<=y<src->h`; OOB dst pixels take `fill`. |
| `0x18001a510` | `fpc_bio_bep_sw23_30be67b43f` | `cr_mirror_extend_fir` | `int fn(u8 *out, u8 *dst, const u8 *src, const i16 *coef, int n, int ncoef)`: `h=ncoef>>1`; place the n-byte row at `dst[h..h+n)`, mirror-fill `dst[j]=src[h-j]` and `dst[n+h+j]=src[n-2-j]`, then `cr_polyphase_fir4(out,dst,coef,n,ncoef)`. Vendor has 4-at-a-time fast paths for ncoef∈{9,15} & n%4==0 (byte-identical). |
| `0x180041140` | `fpc_bio_bep_sw23_dc3eb5f865` | `cr_inpaint_masked_box` | Masked inpaint: for each pixel with mask bit0/bit4 set, fill `img[idx]` with the mean of a 3×3 masked box (any positive count), else a 5×5 box (count>5), marking the mask byte 8 on success; then any mask bit3 becomes 2 and, when `apply`, mask bit0→`img=0.0f`, bit4→`img=255.0f`. |
| `0x180044230` | `fpc_bio_bep_sw23_e9b23176cd` | `cr_pool_alloc1` | `cr_pool_builder(hdr,ptrs,1,{s0})`; on success `*out0=ptrs[0]`; returns the status. |
| `0x180047e30` | `fpc_bio_bep_sw23_fbdfd5dc28` | `cr_pool_alloc2` | 2-block pool; on success writes both block pointers out. |
| `0x180010f40` | `fpc_bio_bep_sw23_10993dfb1a` | `cr_pool_alloc3` | 3-block pool; on success writes the three block pointers out. |
| `0x18001b9e0` | `fpc_bio_bep_sw23_316605bf10` | `cr_pool_alloc4` | 4-block pool; on success writes the four block pointers out. |
| `0x18001d480` | `fpc_bio_bep_sw23_361a5cb939.part.1` | `cr_pool_alloc5` | 5-block pool; on success writes the five block pointers out. |

### Batch 56 — streaming vertical FIR + correlation / splat

| vendor RVA | vendor symbol | clean-room name | behaviour |
|---|---|---|---|
| `0x18002eba0` | `fpc_bio_bep_sw23_85451455f9` | `cr_corr_coeff` | Pearson correlation of two int16 images over `[marginy,h-marginy) x [marginx,w-marginx)`, counting only pixels where **both** `< thresh`. Two passes (sums → means, then `varA=Σda²`, `varB=Σdb²`, `cov=Σdb*da`); `out_corr = cov/(cr_sqrtf(varA)*cr_sqrtf(varB))`, `out_valid = varA>0 && varB>0`. |
| `0x18003af20` | `fpc_bio_bep_sw23_b9b6032650` | `cr_inpaint_index_list` | Inpaint pixels from an index list: for each `idx` with mask bit2 (4) set, grow a box (3,5,7 wide; `maxwin=5+2*right`, `right = (w-2<=col)`, `maxwin=7,right=1` near a 2-pixel border) until `cr_masked_box_sum` returns `cnt>need` (`need=5` only for the win==5 & !right case); then `img[idx]=sum/cnt`, `mask[idx]=8`. |
| `0x180043120` | `fpc_bio_bep_sw23_e69abb2a5d` | `cr_splat_accum16` | Bilinear splat of 16 points: `base=(k+17)*17`, `p4sq=p4*p4`, `scale=1-p4sq`. First `cr_splat_bilinear(pts, bufA+base, bufB+base, alpha, |p3|, -sign(p3)*p4, scale)`, then a 16-iteration accumulation with `fx=p3*0.5, fy=p4*0.5` stepping by `p3/p4`, `neg=(p3<0)`, `ix=(int)fx-neg, iy=(int)fy`, `a=pts[i]*p4sq`, weights `w00=(1-fy)(1-fx)a`, `w01=(1-fx)fy a`, `w10=(1-fy)fx a`, `w11=fx fy a`; `bufB += w`, `bufA = w*beta + bufA`. |
| `0x18002af00` | `fpc_bio_bep_sw23_76ff29ef93` | `cr_row_fir_i16` | One output row of a streaming n-tap vertical FIR, int16 out. No-op (`return 1`) unless `ctx->row+1 == target`; advances `ctx->row`. `rr = old_row % n`. If `target>0`: `srcrow = target + n/2`; if `srcrow<h` widen+horizontally-FIR that image row into ring row `rr` via `cr_u8_expand_convolve` (coef = the shared i16 array), else mirror ring row `rem=(2h-srcrow-n/2-3)%n` into ring row `rr` (`rem` may be negative). Then `acc[col] = Σ_{k<n} coef[(n-1-rr)%n + k] * ring[k*w+col]`; `out[col]=(int16)((acc+0x4000)>>15)`, 4 columns per iteration, **no tail** (w must be a multiple of 4; `w<=3` returns 0). |
| `0x180010440` | `fpc_bio_bep_sw23_0dc5ae5cbd` | `cr_row_fir_i8` | Byte twin: identical fill/rotation, `out[col]=(u8)((acc+0x104000)>>21)`, plus a scalar tail loop for `col>=4+((w-4)>>2)*4` (so `w<=3` is handled entirely by the tail). |

### Batch 57 — destructor / constructor wrappers + misc

| vendor RVA | vendor symbol | clean-room name | behaviour |
|---|---|---|---|
| `0x18003f940` | `fpc_bio_bep_sw23_ea4d4b3c46` | `cr_free_4slot_clear1` | Destructor: clear-b the object, then `cr_cleanup_ptr8_a` on the pointers at `+0x20`, `+0x40`, `+0x60` (slot 0 at `+0x08` is only cleared). |
| `0x1800140d0` | `fpc_bio_bep_sw23_1a4e90d0f1` | `cr_free_3ptr_and8` | If `a` non-NULL, sized-free `a[0]`, `a[1]`, `a[5]` (`+0x00/+0x08/+0x28`); then `cr_cleanup_ptr8_a(b)` (frees `b+8`). |
| `0x180012f70` | `fpc_bio_bep_sw23_14713a91d5` | `cr_free_9slot_clear6` | Destructor: clear-b slots `obj+0x20*i` for `i<6` (i.e. `+0x08..+0xa8`), then `cr_cleanup_ptr8_a` on `+0xc0`, `+0xe0`, `+0x100`. |
| `0x180038820` | `fpc_bio_bep_sw23_9a4f7c2d10` | `cr_alloc_60_init` | `cr_malloc_aligned16(slot,0x60)`; on success `cr_fill(p,0,0x60)` then `p[0x30]=1`; returns the allocator status. |
| `0x180027730` | `fpc_bio_bep_sw23_6f3e9a2b8c` | `cr_round_dims_pow2` | `cr_desc_get_ptr_ints(tmp,&lo,&hi,cfg[4])`; if ok, clamp `w`/`h` up to `lo`/`hi` and round each **up** to the next power of two (`cr_hi_bit_index`); returns the status. |
| `0x180046c40` | `fpc_bio_bep_sw23_...` | `cr_norm_corr_score` | `nn=n*n`; `cr_mean_stddev(&mean,&std,*p2,nn)`; `acc=Σ coef[i]*data[nn-1-i]` (mode 1) or `coef[i]*data[i]`; **`if (!(std>0.1f)) std=0.1f;`** (NaN clamps — see note); `*out=cr_roundf_to_int((float)(int32_t)acc/std)`. |
| `0x180026b30` | `fpc_bio_bep_sw23_...` | `cr_sep_fir_pair` | Separable FIR pair with coef `{0x4000,0,0xc000,0x4000,0x4000,0x4000}`: row-FIR `src→A` (guard `(u32)(w-4)<0xfd`), then col-FIR `A→A` (guard `h`); row-FIR `src→B` (guard `w`), col-FIR `B→B` (guard `h`). Guards return 1 / 0x69. |
| `0x18003b110` | `fpc_bio_bep_sw23_...` | `cr_row_fir_vfir` | Streaming-FIR row twin of `cr_row_fir_i8` but the ring row is filled via `cr_mirror_extend_fir` and the vertical pass is `cr_vfir4_u8(out, ring, coef+((n-rr)-1)%n, w, n)`; mirror branch uses `lv=((2h-(srcrow+3+(n>>1)))%n)*w`. |

### Batch 58 — window generators + masked median + angle sampler

| vendor RVA | vendor symbol | clean-room name | behaviour |
|---|---|---|---|
| `0x18000e6f0` | `fpc_bio_bep_sw23_02e4655d23` | `cr_masked_median_f32` | Median of the float samples `!= skip`: `cr_malloc_aligned16(n*4)`, compact the non-skip samples, selection-sort, then `cnt` even → mean of the two middles, odd → middle. Returns the allocator status. |
| `0x1800345f0` | `fpc_bio_bep_sw23_a1cbee6c60` | `cr_gaussian_window_q15` | Q15 Gaussian: `q=-0.5/sigma²`, `c=(n-1)/2`; `sum=Σ expf((i-c)*q*(i-c))`; `out[k]=clamp(round(expf((k-c)*q*(k-c))*32768/sum), -32768, 32767)`. |
| `0x180018a10` | `fpc_bio_bep_sw23_2bf628d2b6` | `cr_gaussian_deriv_windows_q15` | Q15 Gaussian + 1st/2nd derivative windows. Pass 1 sums `(t*q)*t`; pass 2 uses `(q*u)*u`, `u2=(u+u)*q`, `d=e*u2`, emitting `g=e`, `dg=d`, `d2g=(u2*d + (q+q)*e)` (all `*32768/sum`, rounded). Grouping differs between passes. |
| `0x18003e7a0` | `fpc_bio_bep_sw23_cbae7209ea` | `cr_bilinear_angle_sample` | Orientation-field bilinear sampler: Q6 position `(px-ox, py-oy)`, corners clamped, each byte → `cr_sincos` (cos,sin), bilinear-interpolate both with Q6 weights (`>>12`), then `(cr_atan2_fixed(sin_i, cos_i)+0x400000)>>23`. Field descriptor = `cr_angle_field` (a `cr_image` + `ox@0x20, oy@0x24`). |

### Batch 59 — gaussian-blur wrappers + blit-to-subview wrappers

| vendor RVA | vendor symbol | clean-room name | behaviour |
|---|---|---|---|
| `0x180034740` | `fpc_bio_bep_sw23_a237dc497c` | `cr_gauss_blur7_pair` | Separable 7-tap Gaussian blur of two int16 images in place: `cr_gaussian_window_q15(coef,sigma,7)`, then for each image `cr_fir7_s16` (row) + `cr_fir7_s16_col` (col), short-circuited so a guard failure on the first image skips the second. |
| `0x180024fa0` | `fpc_bio_bep_sw23_601bc7e441` | `cr_blit_mirror_s16` | `cr_image_subview(&sub,dst,left,top,src->w,src->h)`; `cr_copy_u16_shl_guarded(&sub,src,0)`; then `cr_mirror_extend_s16(&sub,top,bottom,left,right)`. |
| `0x180046a80` | `fpc_bio_bep_sw23_f439d0d904` | `cr_blit_extend_s16` | Same prologue; border op is `cr_image_border_extend_s16` (edge-replicate). |
| `0x18003cf00` | `fpc_bio_bep_sw23_c61d1d8196` | `cr_blit_fillborder_s16` | Same prologue; border op is `cr_image_fill_border(&sub,top,bottom,left,right,fill)`. |

### Batch 60 — Gaussian-derivative blur pair + box-median filter

| vendor RVA | vendor symbol | clean-room name | behaviour |
|---|---|---|---|
| `0x18002b930` | `fpc_bio_bep_sw23_784ee12a49` | `cr_gauss_deriv_blur_pair` | Builds 15-tap g (Gaussian) + dg (derivative) windows via `cr_gaussian_deriv_windows_q15`, then writes two separable blurs of the source (dims from `src->w/src->h`): `o1 = rows(dg)+cols(g)`, `o2 = rows(g)+cols(dg)`. Both row passes read the same source data. Out-of-range dims → `0x69` (h) or `1` (w); guard failures short-circuit. |
| `0x1800256e0` | `fpc_bio_bep_sw23_62b3ad8b73` | `cr_box_median_u8` | n×n box median over an 8-bit image with clamped borders: gather the centred window into a scratch buffer (alloc'd by `cr_malloc_aligned16`), run `(n*n+1)>>1` forward bubble-sort passes, emit `scratch[(n*n-1)/2]`. Scratch freed by `cr_sized_free`. |

### Batch 61 — scaled real FFT front-end

| vendor RVA | vendor symbol | clean-room name | behaviour |
|---|---|---|---|
| `0x180029510` | `fpc_bio_bep_sw23_7270b9abae` | `cr_fft_real_fwd` | `int fn(float *a1, unsigned n, float *a3)`. `n > 512` → `0x69`. De-interleaves the `n` real samples of `a1` into `a3` (`a3[k]=a1[2k]`, `a3[n-1-k]=a1[2k+1]` for `k<n/2`), runs `cr_fft_real_n(a3, a1, n)`, then repacks into `a1` via `cr_fft_twiddle`: `a1[0]=a3[0]*0.70710677`, `a1[k]=a3[2k]*T[k*S]-a3[2k+1]*T[k*S+1]`, `a1[n/2+k]=a3[n-2k]*T[off+(k-1)*S]+a3[n-2k+1]*T[off+(k-1)*S+1]` with `S=1024/n`, `off=(n+2)*(512/n)`, and `a1[n/2]=T[512]*a3[1]`; finally scales every output by `scale_tab[cr_hi_bit_index(n)]` (`scale_tab = {sqrt2,1,1/sqrt2,1/2,...}`). Only `n` a power of two in `[16,512]` passes `cr_fft_real_n`, so `n/2` is exact throughout. **Trap:** the first-term twiddle index is `k*S` (the table pointer `R8` advances by `S` floats each iteration), not the constant `S` — using `S` matched only `k=1` and diverged for `k>=2`. |
| `0x180045490` | `fpc_bio_bep_sw23_f09a7f30b6` | `cr_fft_real_inv` | `int fn(float *p1, float *p2, unsigned n)`. Inverse twin: `(uint)(n-16) > 496` → `0x69`, `n` must be a power of two. Recombines the `n` spectra of `p1` into `p2` — for `j = 0..n/4-2`, with `a=p1[3+2j] b=p1[n-1-2j] c=p1[2+2j] d=p1[n-2-2j]`, `tw1=T[(j+1)S] tw2=T[(j+1)S+1]` (`S=4096/n`): `f12=(a+b)*-0.5 f16=(a-b)*0.5 f15=(c+d)*0.5 f13=(d-c)*-0.5 f14=tw1*f12+tw2*f13 f11=tw1*f13-f12*tw2`, writing `p2[2+2j]=f15+f14`, `p2[3+2j]=f16+f11`, `p2[n-1-2j]=f11-f16`, `p2[n-2-2j]=f15-f14` — then folds the four leftover bins (`p2[0]=(p1[1]+p1[0])*0.5`, `p2[1]=(p1[0]-p1[1])*0.5`, `p2[n/2]=p1[n/2]`, `p2[n/2+1]=p1[n/2+1]`) and tail-calls `cr_fft_inv(p1, p2, n/2)` (result lands in `p1`, `p2` is scratch). Passed the difftest on the first run. |

### Batch 62 — 5x5 filter-bank + 2x2 max-pool

| vendor RVA | vendor symbol | clean-room name | behaviour |
|---|---|---|---|
| `0x18002b100` | `fpc_bio_bep_sw23_7716e4a534` | `cr_filter_bank_max5x5` | `int fn(void *out, const void *in, int offset, int stride, int *desc)`. Descriptor `int[]`: `[0]=5` (else `0x69`), `[1]=H`, `[2]=W`, `[3]=nk` (kernels = planes), `[5]=nch` (output channels), `[6]=post-flag`, `*(short**)&desc[8]`=kernel table (`nch*nk` kernels of 25 shorts), `*(short**)&desc[10]`=bias table (`nch` shorts). `stride<=0` defaults to `W`. Output is `nch` planes of `((H-4)/2) x ((W-4)/2)` shorts (rows **and** cols downsampled by 2). For each output pixel `(r,c)` the 5x5 kernel is correlated against the 6x6 input window at base `offset + 2r*stride + 2c`, evaluated at the four 2x2 sub-offsets `(dr,dc) ∈ {0,1}²`; the per-plane results are summed over all `nk` kernel/plane pairs (each kernel uses its own plane at `p*H*W`), then the four sums are **max-pooled** (wrapping 32-bit), biased by `bias[ch]*0x4000` and arithmetic-shifted right by 15. `flag==1` clamps the whole output non-negative via `cr_s16_clamp_nonneg(out,out,orows*ocols*nch)`. The vendor splits the 25 taps into 4 running accumulators (block A = kernel row 0 / input row 0 → sums `(0,0)+(0,1)`; block B loops 4× over kernel rows 0-1,1-2,2-3,3-4 paired with input rows 1..4 → sums `(1,0)+(1,1)` then `(0,0)+(0,1)`; tail = kernel row 4 / input row 5 → `(1,0)+(1,1)`); the rewrite is the equivalent closed-form sum over the 6x6 window. Passed the difftest on the first run. |

### Batch 63 — scaled inverse real FFT

| vendor RVA | vendor symbol | clean-room name | behaviour |
|---|---|---|---|
| `0x18001d050` | `fpc_bio_bep_sw23_35b121b7ef` | `cr_fft_real_bwd` | `int fn(float *a1, unsigned n, float *a3)`. Twin of `cr_fft_real_fwd`: `n > 512` → `0x69`. Repacks the `n` spectra of `a1` into `a3` — `a3[0]=a1[0]*sqrt2`, and for `k = 0..n/2-2` with `i1=2*step*(k+1)`, `i2=2*step*(n-1-k)` (`step=512/n`): `a3[2+2k]=a1[1+k]*T[i1]+a1[n-1-k]*T[i2]`, `a3[3+2k]=a1[n-1-k]*T[i2+1]-a1[1+k]*T[i1+1]`; then `a3[1]=a1[n/2]*T[512]` — runs `cr_fft_real_inv(a3,a1,n)`, de-interleaves `a3` back into `a1` (`a1[2k]=a3[k]`, `a1[2k+1]=a3[n-1-k]` for `k<n/2`) and scales by `scale_tab[cr_hi_bit_index(n)]`. Passed the difftest on the first run. |

### Batch 64 — 3x3 float filter-bank + 2x2 max-pool

| vendor RVA | vendor symbol | clean-room name | behaviour |
|---|---|---|---|
| `0x180045a50` | `fpc_bio_bep_sw23_f21fb7f627` | `cr_filter_bank_max3x3_f32` | `int fn(void *out, const void *in, int *desc)`. Descriptor `int[]`: `[1]=H`, `[2]=W`, `[3]=nk` (kernels/planes), `[5]=nch`, `[6]=post-mode`, `*(float**)&desc[8]`=kernel table (`nch*nk` kernels of 9 floats), `*(float**)&desc[10]`=bias table. Output is `nch` planes of `((H-2)/2) x ((W-2)/2)` floats. For each output pixel the 3x3 kernel is correlated against the 4x4 input window at base `2r*W + 2c` at the four 2x2 sub-offsets; the per-plane sums over all `nk` kernel/plane pairs are max-pooled, then biased by `bias[ch]`; `mode != 0` runs `cr_copy_or_relu(out,out,orows*nch*ocols,mode)`. Returns 0. **Trap:** the four accumulators use *different* float association orders per row (e.g. `s00` row 0 is `(k1*v1 + k0*v0) + k2*v2` but rows 1-2 are `(v0*k0 + v1*k1) + v2*k2`; `s01`/`s11` use `k2*v3 + (k1*v2 + k0*v1)`), so the expression grouping was transcribed verbatim from the asm to stay bit-exact. Passed the difftest on the first run. |

### Batch 65 — 5x5 float filter-bank + 2x2 max-pool

| vendor RVA | vendor symbol | clean-room name | behaviour |
|---|---|---|---|
| `0x180044ee0` | `fpc_bio_bep_sw23_f02a43642e` | `cr_filter_bank_max5x5_f32` | `int fn(void *out, const void *in, int offset, int stride, int *desc)`. Float twin of Batch 62: descriptor `int[]` with `[0]==5` tag guard, `[1]=H`, `[2]=W`, `[3]=nk` (kernels/planes), `[5]=nch`, `[6]=post-mode`, `*(float**)&desc[8]`=kernel table (`nch*nk` kernels of 25 floats), `*(float**)&desc[10]`=bias table. `stride<=0` defaults to `W`; `offset` is an extra per-window base shift. Output is `nch` planes of `((H-4)/2) x ((W-4)/2)` floats. For each output pixel the 5x5 kernel is correlated against the 6x6 input window at the four 2x2 sub-offsets; the plane sum over all `nk` kernels/planes is max-pooled (`max(f140, max(f41, max(f42, f40)))`), then biased by `bias[ch]`; `post-mode != 0` runs `cr_copy_or_relu(out,out,ocols*orows*nch,mode)`. Returns 0, or `0x69` when `desc[0] != 5`. **Trap:** the four float accumulators use *different* association orders across the row-0 prologue, the rows-1..4 main loop and the row-5 tail (e.g. `f42` row 0 is left-associated `((((v1*k0+v2*k1)+v3*k2)+v4*k3)+v5*k4)` but rows 1-4 are right-associated `v5*k4+(v4*k3+(v3*k2+(v2*k1+v1*k0)))`; `f41` rows 1-4 are `(v3*k3+((v1*k1+v0*k0)+v2*k2))+v4*k4` while row 5 is left-associated), so every grouping was transcribed verbatim from the asm. Passed the difftest on the first run. |

### Batch 66 — float filter-chain runner

| vendor RVA | vendor symbol | clean-room name | behaviour |
|---|---|---|---|
| `0x180037d20` | `fpc_bio_bep_sw23_aecae12ae2` | `cr_filter_chain_run` | `int fn(void *buf, const int *chain, const int *in_desc, int off, int row)`. `chain`: `[0]=nstages`, `(void**)&chain[2]`=array of 48-byte stage descriptors (12 ints each, same layout as the two float filter descs). `in_desc`: `[0]`=stage-0 stride, `(void**)&in_desc[2]`=stage-0 input plane. Stage 0 runs `cr_filter_bank_max5x5_f32(buf, in_desc->plane, row*in_desc[0]+off, in_desc[0], stage0)` writing into `buf`; each later stage reads `buf` and writes to scratch at `buf + H*W*nk` floats, then copies `((H-tag+1)/2)*((W-tag+1)/2)*nch` floats back to the head of `buf`. Stage tag 5 -> 5x5 float filter, tag 3 -> 3x3 float filter, any other tag -> `0x69`. Returns 0, or the first failing stage's error code. Because each stage's input region `[0,H*W*nk)` and scratch region `[H*W*nk, ...)` are disjoint, the in-place chaining is deterministic. Passed the difftest on the first run. |

### Batch 67 — 3x3 int16 filter-bank + 2x2 max-pool

| vendor RVA | vendor symbol | clean-room name | behaviour |
|---|---|---|---|
| `0x180038080` | `fpc_bio_bep_sw23_afa5254b16` | `cr_filter_bank_max3x3_i16` | `int fn(void *out, const void *in, int *desc)`. Descriptor `int[]`: `[1]=H`, `[2]=W`, `[3]=nk` (kernels/planes), `[5]=nch`, `[6]=post-flag`, `*(short**)&desc[8]`=kernel table (`nch*nk` kernels of 9 shorts), `*(short**)&desc[10]`=bias table. Output is `nch` planes of `((H-2)/2) x ((W-2)/2)` shorts. For each output pixel the 3x3 kernel is correlated against the 4x4 input window at base `2r*W + 2c` at the four 2x2 sub-offsets; the plane sum over all `nk` kernel/plane pairs is max-pooled, biased by `bias[ch]*0x4000` and arithmetic-shifted right by 15. `flag==1` clamps the whole output non-negative via `cr_s16_clamp_nonneg`. **Trap:** all accumulation is *32-bit wrapping* (the vendor uses `IMUL/ADD r32`), so the four accumulators are held in `uint32_t` (products fit in `int`, the running sums wrap); using 64-bit would diverge once the sum exceeds 2^31. The inner loop is software-pipelined: rows 1-2 pair `a10/a11` with kernel row `j-1` and `a00/a01` with kernel row `j`, and the row-3 tail pairs `a10/a11` with kernel row 2. Passed the difftest on the first run. |

### Batch 67b — int16 filter-chain runner

| vendor RVA | vendor symbol | clean-room name | behaviour |
|---|---|---|---|
| `0x1800120c0` | `fpc_bio_bep_sw23_14eced02ef` | `cr_filter_chain_run_i16` | `int fn(void *buf, const int *chain, int start, int end)`. `chain`: `(void**)&chain[2]`=array of 48-byte stage descriptors (12 ints each). Every stage reads `buf` and writes its result to scratch at `buf + H*W*nk` shorts, then copies `((H-tag+1)/2)*((W-tag+1)/2)*nch` shorts back to the head of `buf`. Stage tag 5 -> `cr_filter_bank_max5x5`, tag 3 -> `cr_filter_bank_max3x3_i16`, any other tag -> `0x69`. `end < start` returns 0 immediately. Returns 0, or the first failing stage's error code. **Trap:** the copy-length halves are *signed* divisions by 2 (the asm emits the `(x + (x>>31)) >> 1` truncate-toward-zero sequence), not the arithmetic shifts used by the float twin `cr_filter_chain_run` — they only differ for negative operands. Passed the difftest on the first run. |

### Batch 67c — 2-D real inverse FFT

| vendor RVA | vendor symbol | clean-room name | behaviour |
|---|---|---|---|
| `0x180040930` | `fpc_bio_bep_sw23_d96d96a682.part.0` | `cr_fft2d_real_bwd` | `int fn(float *out, int orows, int ocols, float *in, uint nrows, uint ncols)`. Guards `(uint)(nrows-16) <= 0x1f0 && (uint)(ncols-16) <= 0x1f0` (i.e. both in `[16,512]`), else `0x69`. Allocates scratch `max(nrows,ncols)` floats + column buffer `nrows` floats via `cr_malloc_aligned16`. Row pass: `nrows` in-place length-`ncols` `cr_fft_real_bwd` over `in` (**return values ignored**). Column pass: for `ocols` columns starting at `in + iVar5` (`iVar5=(ncols-ocols)/2`), gather the `nrows` samples (stride `ncols`), run length-`nrows` `cr_fft_real_bwd`, then write `colbuf[iVar4 .. orows+iVar4)` (`iVar4=(nrows-orows)/2`) to `out` at row stride `ocols`. Returns 0, an allocator status, or the failing column FFT's error code. Both halves `(nrows-orows)/2`/`(ncols-ocols)/2` are *signed* divisions (truncate toward zero). Passed the difftest on the first run. |

### Batch 69 — morphological margin extract

| vendor RVA | vendor symbol | clean-room name | behaviour |
|---|---|---|---|
| `0x180044d10` | `fpc_bio_bep_sw23_eea97c0bb8` | `cr_bitmap_margin_extract` | `int fn(cr_image *dst, const cr_image *src)`. `iVar1=src->w`, `iVar2=src->h`. Scratch packed bitmap of width `w2` and height `iVar2+0xc`, where `w2 = ((iVar1+0x2b >= 0) ? iVar1+0x2b : iVar1+0x4a) & ~0x1f` (the signed `trunc((w+43)/32)*32` idiom, reused verbatim from `cr_thresh_open_mark`). Sequence: `cr_bitmap_alloc(temp,w2,h+12)` (early-return its status on failure, **without** cleanup); `cr_bitmap_copy_shift(temp,src,6,6)`; `cr_bitmap_dilate(temp,temp,5)`; `cr_bitmap_erode(temp,temp,5)`; `cr_bitmap_fill_extents(temp,temp)`; `cr_bitmap_border_set(temp,6,6,w2-(iVar1+6),6,1)`; `cr_bitmap_erode(temp,temp,10)`; then re-tag `temp->w=iVar1, temp->h=iVar2, temp->offx=temp->offy=6` and `cr_bitmap_extract_shift(dst,temp)`. Always `cr_cleanup_ptr8_b(temp)` at the end (except the alloc-failure early return). Returns 0 or the first failing callee's status. All 8 callees were already implemented. Passed the difftest on the first run. |

| `0x180010110` | `fpc_bio_bep_sw23_0cf963791a` | `cr_bitmap_filter_fir` | `int fn(cr_image *out, const cr_image *src, int n, float sigma, int flag)` (ms_abi slots: `rcx=out, rdx=src, r8d=n, xmm3=sigma, [stack]=flag`). Rasterise `src` into packed bitmap `b1` sized `src->a x src->b` via `cr_bitmap_alloc` + `cr_bitmap_set_from_image`. Then `m=n+1`, `w2 = round_up32(b1->w + 2m)`, `h2 = b1->h + 2m` (the signed `(A+0x1f>=0 ? A+0x1f : A+0x3e) & ~0x1f` idiom), `cr_bitmap_alloc(b2,w2,h2)`; `cr_bitmap_copy_shift(b2,b1,m,m)`; `cr_bitmap_erode(b2,b2,1)`; `cr_bitmap_dilate(b2,b2,n)`; `cr_bitmap_erode(b2,b2,n-1)`; if `flag` then `cr_bitmap_fill_extents(b2,b2)`; re-tag `b2->w=b1->w, b2->h=b1->h, b2->offx=b2->offy=m`; `cr_bitmap_extract_shift(b1,b2)`; `cr_cleanup_ptr8_b(b2)`; `cr_bitmap_unpack(out,b1)`; `cr_cleanup_ptr8_b(b1)`; return `cr_fir7_image_u8(out,out,sigma)`. **Vendor quirk:** the two error paths after `b1` exists (`b2`-alloc failure, `copy_shift` failure) call `cr_sized_free` on the `b1` *descriptor* (frees `b1[0]`, i.e. `round32(src->a)`) rather than `b1+8`; unreachable for valid inputs, replicated as-is. |

| `0x18003f360` | `fpc_bio_bep_sw23_d18ad9722a` | `cr_bitmap_filter_apply_s16` | `int fn(void *dst, const cr_image *src, const void *cfg)`. `dst` is a cr_image-like descriptor: `+0x08` int16 pixel buffer, `+0x10` w, `+0x14` h. Allocates a u8 image `t = cr_image_alloc_u8(w,h)` (early-return its status), runs `cr_bitmap_filter_fir(&t, src, 5, 4.0f, *(char*)(cfg+8))`, and — on success, when `w*h > 0` — rewrites each pixel `pix[i] = (int16_t)((pix[i]*m + (0xff-m)*0x3fc0) / 0xff)` where `m = t.data[i]` (signed `/255`, magic `0x80808081`). Always `cr_cleanup_ptr8_a(&t)`. Returns the pipeline status. The sigma constant is the float at `0x18008c4e0` = `4.0f`. |

| `0x180032af0` | `fpc_bio_bep_sw23_98562b2e92.constprop.5` | `cr_fft_weighted_apply_32af0` | `int fn(int *desc, const float *weights, const void *cfg)`. `desc` is a cr_image holding an int16 buffer (`desc[4]`/`desc[5]` = w/h, `+0x08` = pixels); `weights` is a float array of `W*H`. `W,H = cr_round_dims_pow2(&W,&H, desc[5], desc[4], cfg)` (note the swapped order; early-return its status). Allocates two `W*H`-float scratch buffers `p70`,`p68` (free `p70` if the 2nd alloc fails), then `cr_image_alloc_f32(&img, desc[4], desc[5])`, `cr_i16_to_f32_scaled(&img, desc, 6)`, `cr_fft2d_prep_1e920(p70, W, H, img.data, desc[5], desc[4])`, element-wise `p68[i*H+j] = p70[i*H+j] * weights[i*H+j]` over `W` rows x `H` cols, free `p70`, `cr_fft2d_real_bwd(img.data, desc[5], desc[4], p68, W, H)`, then `cr_f32_to_i16_scaled(desc, &img, 6)`. `img` is torn down with `cr_cleanup_ptr8_clear_b` and every error path frees the live scratch. Returns 0 or the first failing callee's status. **Test caveat:** the vendor's `cr_fft2d_prep_1e920` reads `img.data` past its `desc[4]*desc[5]`-float buffer when the padded width `W > 3*desc[5]`, so the difftest keeps `desc[5] >= 6` (where `W <= 3*desc[5]`). |

| `0x180013340` | `fpc_bio_bep_sw23_184c694a1a` | `cr_obj_init_13340` | `uint32_t fn(const void *defs, void *out, int flag)`. Builds the 128-byte (16-qword) image-set descriptor at `out` from the definition table `defs`. NULL `out` → `0x69`. Zeroes all 16 qwords, then for `s = 0xc,0xe,0x10,0x12,0x14` (step 2 while `!= 0x16`): if `!cr_image_slot_empty(defs,s)`, `cr_malloc_aligned16(&out[i],0x38)` (return its status on failure), `cr_image_data_dump(defs,s,out[i])` (failure → `0x6a`), then `out[i+7] = cr_image_get_dp(defs,s+1)`; `i++`. If `flag && out[0]`, then for slots 8 and 10 (each when `cr_image_slot_defined && cr_image_slot_empty`) run `cr_pixel_buf_setup(defs,slot,(i16)out[0][0],(i16)out[0][2])` and return a non-zero status. Then if slot 8 is non-empty, `cr_malloc_aligned16(&out[5],0x38)` + `cr_image_data_dump(defs,8,out[5])` + `out[0xc]=cr_image_get_dp(defs,9)`; if slot 10 is non-empty, the same into `out[6]`/`out[0xd]=cr_image_get_dp(defs,0xb)`. Always `out[0xf]=cr_image_get_dp(defs,0)`; if slot 1 is non-empty, `cr_malloc_aligned16(&out[0xe],0x18)` + `cr_image_buf_desc(defs,out[0xe])`. Returns `0x69` when `out[0]` ended up NULL, else 0. **Test note:** the difftest snapshots/restores the shared metadata table around each side so both see identical input, and keeps rows/cols <= 2 (the `cr_pixel_buf_setup` memmove writes `rows*2*cols` bytes at `meta+0x24`). Passed on the first run (309 ok). |

| `0x18000f000` | `fpc_bio_bep_sw23_050be4b9be` | `cr_harris_local_minmax_grid` | `int fn(cr_grid *grid, const cr_image *src, const cr_image *mask, const cr_harris_max_cfg *cfg)`. The min/max twin of `cr_harris_local_max_grid` (`0x180023e70`): identical prologue (`cr_image_alloc_u8` A, `cr_image_alloc_f32` B, `cr_image_copy_u8(&A,src)`, `cr_harris_response(&B,&A,cfg->coef,cfg->sigma)`) and identical interior scan (`c=cfg->border`, `x∈[c,B.w-c)`, `y∈[c,B.h-c)`, base `= B.data + B.offy*B.a + B.offx`). For each pixel, with `cur = B[y][x]`: if `cur` is **strictly greater** than all 8 neighbours (`ucomiss cur,nbr; jbe skip`), OR **strictly less** than all 8 neighbours, AND the `mask` bit `bit=(mask.offy+y)*mask.a+(mask.offx+x)` is set (`word=mask.data[bit>>5]`, test bit `bit&31`), call `cr_grid_insert(grid,(u8)x,(u8)y,val,(cr_grid_cfg*)cfg)`. `val = cur` when `0.0 <= cur`, else `cur` with the sign bit XORed away (`^0x80000000`, the float at `0x18008c510`); i.e. `|cur|` except that `-0.0` is kept as `-0.0`. After a successful max insert the code re-runs the min check (harmless — a strict max is never a strict min); a min insert advances directly. The mask is read only after a neighbour test passes. Any stage failure short-circuits through the shared cleanup (`cr_cleanup_ptr8_a(&A)`, `cr_cleanup_ptr8_clear_b(&B)`) and returns that status. **Test note:** same `border >= 1` constraint as the max variant (c == 0 over-reads one pixel past every edge). Passed on the first run (310 ok). |

### Batch 70 — grid-bucketed keypoint sampler

| vendor RVA | vendor symbol | clean-room name | behaviour |
|---|---|---|---|
| `0x1800466f0` | `fpc_bio_bep_sw23_f3cb2fe615` | `cr_keypoint_grid_sample` | `int fn(cr_pt8 *pts, int *out_count, int npts, int maxout, const int *dims, uint32_t seed, const uint8_t *cfg)`. An 8-byte keypoint record is `{int32 f0; int16 f4; int16 f6}` (the union `cr_pt8` exposes the two 4-byte words). `cols=cfg[0x25]`, `rows=cfg[0x26]`, `W=dims[4]`, `H=dims[5]`. Allocates `nexts` (`(int16)cfg[0x10]` ints), then `heads`/`order` (`rows*cols` ints each) via `cr_malloc_aligned16`; each failure frees the earlier buffers and returns the status. Fills `heads` with -1. For `kp = npts-1 .. 0`: `c = (f4*cols)/W`, `r = (f6*rows)/H` (both signed, clamped: negatives to 0, then to the grid edge), writes the record's own 4-byte word 0 over word 1 (`w[1]=w[0]`, *after* both coords are read), then pushes `kp` onto `heads[c + r*cols]` with `nexts[kp]` as the chain link (so the list head is the lowest index). Shuffles the `rows*cols` cell ids with `cr_shuffle_indices(order, ncells, (uint64)seed)`. Finally walks the shuffled cell order (wrapping: `idx = (cur >= ncells-1) ? 0 : cur+1`) and, for every non-empty cell, copies the head's word 1 into `pts[outn].w[0]`, advances `*head = nexts[*head]`, and increments `outn`, until `outn == maxout` (requires `maxout <= npts`, else the vendor spins). Stores `outn` in `*out_count`, frees all three buffers, returns 0. Passed the difftest on the first run (290 ok). |

### Batch 71 — normalized int16 FIR down each column

| vendor RVA | vendor symbol | clean-room name | behaviour |
|---|---|---|---|
| `0x180011a70` | `fpc_bio_bep_sw23_1468a9d011` | `cr_fir_norm_s16` | `int fn(int16_t *out, const int16_t *in, const int16_t *kern, int klen, int stride, int count)`. The vertical pass of a separable blur (the horizontal twin is `0x18001e400`); the caller passes `stride = w`, `count = h` and often `out == in`. Allocates a `count`-short gather buffer and a `(klen>>1)+1`-int denominator buffer via `cr_malloc_aligned16` (freeing the first on the second's failure). `denom[0] = kern[h]`; `denom[k] = denom[k-1] + 2*kern[h-k]` (`h = klen>>1`); `full = denom[h]`. For each of the `stride` columns: gather `in[j*stride]` (j=0..count-1) into scratch, then left region `i in [0,h)`: `sum_{t=h-i..h+i} kern[t]*gather[(i-h)+t] / denom[i]`; middle region `i in [0,count-2h)`: `sum_{k=0..klen-1} kern[k]*gather[i+k] / full`; right region `i in [1,h]`: `sum_{t=i..2h-i} kern[t]*gather[(count-2h-1+i)+t] / denom[h-i]`. Each accumulator gets `+0x4000` before the signed `IDIV`, and the quotient truncates to int16. `stride <= 0` allocates/frees but processes nothing. Returns 0 or an allocator status. **Trap:** accumulation is 32-bit wrapping (`IMUL`+`ADD r32`) — accumulate in `uint32_t`, reinterpret as int32 only for the signed division. **Note:** the Ghidra pseudocode for this RVA carries a bogus struct signature (`param_3` shown as a struct with kernel at `+0x20`); the *assembly* is authoritative — `param_3` is the kernel `int16_t*`. Passed the difftest on the first run (291 ok). |
| `0x18001e400` | `fpc_bio_bep_sw23_3b02921c6d` | `cr_fir_norm_rows_s16` | `int fn(int16_t *out, const int16_t *in, const int16_t *kern, int klen, int W, int H)`. The horizontal twin of `cr_fir_norm_s16` (called first by `0x1800278f0`; `cr_fir_norm_s16` is the in-place second pass). Identical denominator construction and left/middle/right regions, but each of the `H` rows gathers `W` **contiguous** samples (`gather[j] = in[row*W + j]`) and writes the results back along the same row (`out[row*W + i]`, `out[row*W + h + i]`, `out[row*W + W-h+i-1]`). Same dead `0x4000` branches and 32-bit-wrapping accumulation. Returns 0 or an allocator status. Passed the difftest on the first run (292 ok). |
| `0x1800278f0` | `fpc_bio_bep_sw23_6b13e2f5bb` | `cr_sep_gauss_blur_s16` | `int fn(cr_image *dst, const cr_image *src, float sigma, unsigned klen)`. Guard (else 0x69): both descriptors full-view (8-byte `(a,b)` pair == `(w,h)` pair and `(offx,offy)==0`) and `klen` odd. Allocates `klen` shorts, fills via `cr_gaussian_window_q15(kern,sigma,klen)`, then `cr_fir_norm_rows_s16(dst->data, src->data, kern, klen, src->w, src->h)` (horizontal) and, only if that returns 0, `cr_fir_norm_s16(dst->data, dst->data, kern, klen, src->w, src->h)` (in-place vertical). Frees the kernel; returns 0x69 / allocator status / first FIR status. Passed the difftest on the first run (293 ok). |
| `0x180013a30` | `fpc_bio_bep_sw23_193665ba13` | `cr_sep_gauss_blur_s16_reflect` | `int fn(cr_image *dst, const cr_image *src, float sigma, unsigned klen)`. Same guard/klen/odd and `cr_gaussian_window_q15` kernel build as `cr_sep_gauss_blur_s16` (0x1800278f0), but uses **reflect-101 borders** instead of zero: horizontal pass `cr_fir_norm_rows_reflect_s16(d, s, kern, klen, w, h)` then (if 0) vertical in-place `cr_fir_norm_reflect_s16(d, d, kern, klen, w, h)`. Index reflection: for `i = j - k`, `j<0 ⇒ 2-(1-j)`, `j>=w ⇒ 2*(w-1)-(j+1)`; with periodic fallback `(((i % w) + w) % w)` when the reflected index is still out of range, plus a `j==0 ? 1 : 0` adjustment. Returns 0x69 / allocator / first FIR status. Passed on the first run (311 ok). |

### Batch 72 — filter chain → stacked linear layers → 2-way softmax

| vendor RVA | vendor symbol | clean-room name | behaviour |
|---|---|---|---|
| `0x18002ee10` | `fpc_bio_bep_sw23_85eeef99fe` | `cr_linear_softmax2` | `int fn(float *out, const int *desc, const int *in_desc, int off, int row)`. `desc` is the float filter chain consumed by `cr_filter_chain_run`, extended with a head of linear sub-descriptors: `desc[4]` = layer count, `*(void**)((char*)desc + 0x18)` = array of 0x20-byte layer records, `desc[8]` = scratch size in floats. A record is `[0]=in_len`, `[1]=nrows`, `[2]=post`, `+0x10` = weight (`nrows*in_len` floats), `+0x18` = bias (`nrows` floats). Allocates `desc[8]` floats, runs `cr_filter_chain_run` into it (a nonzero status is returned after the free), then for each layer computes `buf[in_len + r] = bias[r] + Σ_{j<in_len} weight[r*in_len + j] * buf[j]` for `r in [0,nrows)` (the empty sum when `in_len <= 0`). When `post != 0` it then runs `cr_copy_or_relu(dst, dst, nrows, post)` (`dst = buf + in_len`); a nonzero result is returned after the free. Finally the `nrows` results are compacted to the head of `buf` (`buf[t] = buf[in_len + t]`), except that a layer with `nrows < 1 && post == 0` skips both the warp and the compaction. After all layers it writes the 2-class softmax of `buf[0], buf[1]`: `m = (buf[1] > buf[0]) ? buf[1] : buf[0]` (MAXSS: NaN → `buf[0]`); `*out = expf(buf[0]-m) / (expf(buf[1]-m) + expf(buf[0]-m))`. Returns 0, an allocator/chain status, or `cr_copy_or_relu`'s error. Passed the difftest on the first run (294 ok). |
| `0x180016bd0` | `fpc_bio_bep_sw23_20317dd11c` | `cr_chain_classify_i16` | `int fn(float *out, const int *chain, const void *src_desc, int off, int row)`. Image geometry comes from the first chain stage: `H = stages[1]`, `W = stages[2]` (`stages = *(void**)((char*)chain + 0x8)`). Allocates a `W x H` float image (`cr_image_alloc_f32(&img, W, H)`), fills `img[row*W + c] = (float)(((int)src[idx + c] + 0x20) >> 6) / 255.0f` where `src = *(int16_t**)((char*)src_desc + 0x8)`, `stride = *(int*)((char*)src_desc + 0x10)`, `idx = row_arg*stride + off` (advancing by `stride` per image row; the `>>` is an arithmetic shift of the 32-bit sign-extended sample, `255.0f = 0x437f0000`). Then runs `cr_linear_softmax2(out, chain, &img, 0, 0)`, frees the image (`cr_cleanup_ptr8_clear_b`) and returns that status; an allocator failure returns before the classifier. Passed the difftest on the first run (295 ok). |
| `0x18002d550` | `fpc_bio_bep_sw23_7cab493289` | `cr_gauss_deriv_triple_coef` | `uint64_t fn(const void *d1, const void *d2, const void *d3, const void *dc, float sigma)`. All four descriptors must be full-view images (`(a,b) == (w,h)` and `(offx,offy) == 0`), else returns 0x69. `dc` supplies the coefficient plane at `+8` and `W = dc->w`, `H = dc->h`; the low bit-triple of `W` picks the pipeline and both only run when `sigma >= 0.72f` (`0x3f3851ec`): `W & 7 == 0` → p1 = rows(d2g)→cols(g), p3 = rows(g)→cols(d2g), p2 = rows(dg)→cols(dg) via the `*_guarded` reflect-101 FIRs, short-circuiting on the first nonzero status; `W & 7 != 0` → p1 = fir7(d2g)→vfir7(g), p3 = fir7(g)→vfir7(d2g), p2 = fir7(dg)→vfir7(dg) via the plain reflect-101 FIRs, returning 0. `{g,dg,d2g} = cr_gaussian_deriv_windows_q15(.,.,.,sigma,7)` (that callee always returns 0, so its status is not observable here). Passed the difftest on the first run (296 ok). **Test note:** `cr_chain_classify_i16`'s difftest must keep the chain's stage-0 `nk == 1` — the classifier feeds a single `W x H` plane, and `cr_filter_bank_max5x5_f32` strides planes by `H*W`, so `nk > 1` reads past the image. |
| `0x180029870` | `fpc_bio_bep_sw23_7360af0a7b` | `cr_structure_tensor_score` | `uint64_t fn(int16_t *out, const int *mask_desc, const cr_image *geo, const char *obj)`. `*out = 0xffff`; `W = geo->w`, `H = geo->h`; three `cr_image_set(&i1/&i2/&i3, NULL, W, H)` then a single `cr_pool_alloc3` of three `W*H*2`-byte blocks into `i1/i3/i2.data`. `cr_gauss_deriv_triple_coef(&i1,&i2,&i3, geo, 1.0f)` (0x69 short-circuits); then for `i in [0, geo->a*H)` a structure-tensor eigen step on `{b0=i1[i], b1=i3[i], b2=i2[i]}` (Gxx=b0, Gyy=b1, Gxy=b2): if `b2² < 1e-12` → `e1=b0, e2=b1, (p,q) = (sel?1:0, sel?0:1)` with `sel=(e2<=e1)`; else `m=(b0+b1)/2`, `rt=sqrtf(m²-(b0·b1-b2²))`, `e1=|m+rt|`, `e2=|m-rt|`, `(p,q)=(sel?k2:k1, b2)` where `k1=(m+rt)-b0, k2=(m-rt)-b0`; `coh=((e1-e2)²/(e1²+e2²))·255.0`, `den=q²+p²`, `rq=q·p/den`, store `o0[i]=(q²-p²)/den·coh` (→i1) and `o1[i]=2·rq·coh` (→i3). Smooth in place with `cr_gaussian_fir_2pass(&i1,&i1, sigma=*(float*)(obj+8))` then `cr_gaussian_fir_2pass(&i3,&i3, sigma)` (each returns status 1 if `W ∉ [16,256]`, 0x69 if the other dimension `∉ [16,256]` on the unaligned path; nonzero short-circuits). Finally over the mask bits (`stride=mask_desc[0]`, `bits=*(void**)(mask_desc+8)`, `xoff=mask_desc[6]`, `yoff=mask_desc[7]`): for each set bit at `idx=(yoff+y)*stride+xoff+x`, `sum += ((int)(sqrtf(i1[i]²+i3[i]²)·0.4f) & 0xff)`, `count++` (`i=x+y*W`); `*out = (short)(sum / (count+1))`. The pool is freed once allocated; the last status is returned. Passed the difftest on the first run (297 ok). |
| `0x1800231a0` | `fpc_bio_bep_sw23_51e3fa6e58` | `cr_block_conv_231a0` | `uint64_t fn(int16_t *out, const intptr_t *ptrs, const void *desc)`. Fixed-point 2D convolution block with max/min reductions. `desc` (int-indexed at 4-byte strides, with `void*` fields at +0x20/+0x28): `desc[2]=line` (per-row pitch in shorts of each `ptrs[j]` buffer), `desc[3]=K` (kernel rows), `desc[4]=Wout`, `desc[5]=R` (slice count), `desc[6]=clamp flag`, `*(void**)(desc+0x20)=kernel` (K*9 int16: K rows of 3 used as 3x3 tiles), `*(void**)(desc+0x28)=bias` (R int16, each scaled by 0x4000 into `iVar6`). For each slice `r` and output column pair the two accumulation phases (A over `ptrs[0..2]`, B over `ptrs[1..3]`) compute a K-deep correlation whose four sub-sums are reduced with `max`/`min` into two results shifted down by 15 and biased by `iVar6`; a tail handles the odd trailing column. If `desc[6]==1` the `R*Wout` outputs are clamped non-negative (`cr_s16_clamp_nonneg`). Returns 0. Passed the difftest on the first run (298 ok). |
| `0x180044270` | `fpc_bio_bep_sw23_e9d9c1b039` | `cr_structure_tensor_score_img` | `uint64_t fn(int16_t *out, int *geo, const cr_image *src, uint64_t param_4)`. Thin pipeline wrapper: `W=src->w`, `H=src->h`; `cr_image_set(&local_60, NULL, W, H)`; if OK `cr_pool_alloc1(hdr, &local_58, W*H*2)` and attach the allocated buffer as `local_60.data`; `cr_u8_to_u16_guarded(&local_60, src, 6)` (u8→i16 shift ×2^6, returns 0x69 on the dimension/offset guard); if OK `cr_structure_tensor_score(out, geo, &local_60, (const char*)param_4)`; finally `cr_sized_free_if(hdr)` and return the last status (0, 0x69, or the tensor score status). Note the decompiler drops the `local_60.data = local_58[0]` assignment — the `W*H*2` pool block is exactly the i16 pixel store. Passed the difftest bit-for-bit (299 ok). |
| `0x180035150` | `fpc_bio_bep_sw23_*` | `cr_template_ncc_35150` | `int fn(int16_t *out, const int16_t *data, const int16_t *ref, uint32_t radius, int w, int rows)`. Column-major template / normalised cross-correlation. Clamps `radius` to `[0, rows-1]`; `half = radius>>1`; allocates two `half`-int16 scratch rows via `cr_malloc_aligned16` (both must succeed or it returns 2 without work) and frees with `cr_sized_free`. Computes reference averages `local_250[i]=(sum<<10)/cnt` and `local_248[i]`. For each of `w` columns it copies the column into `local_240[256]`, then writes three vertical bands — `[0,half)` and `[rows-half,rows)` use `ref`-vs-column-window correlation rounded `(x+0x200)>>10` then `(x*s + 0x4000)>>15`; the middle `[half,rows-half)` band uses `(x*2+0x8000)>>16`. Returns 0 on success. Passed the difftest bit-for-bit (300 ok). NOTE Ghidra renders `x + 0x4000 >> 0xf` as `(x+0x4000)>>15` (rounding shift). |
| `0x1800283d0` | `fpc_bio_bep_sw23_*` | `cr_template_ncc_283d0` | Column-major twin of `cr_template_ncc_35150` (0x180035150). Same per-column NCC algorithm, but the ABI last two args are swapped to `(rows, w)` and `data`/`out` are stored **column-major** (`element (r,c) = base[r + c*rows]`), so the outer loop stride is `rows` instead of `w`. The two internal `goto invalidInstructionException` branches are unreachable (`radius >= half`) and omitted. Otherwise bit-identical band logic. Passed the difftest bit-for-bit (301 ok). |
| `0x18001e920` | `fpc_bio_bep_sw23_*` | `cr_fft2d_prep_1e920` | 2D real-FFT preparation. `int fn(float *out, uint ncols, uint nrows, const float *src, int w, int h)`. Entry guard: `ncols`/`nrows` must be in `[0x10,0x200]` else `0x69`. Centres/pads a `(w×h)` source into a `(ncols×nrows)` working buffer (three left/middle/right copy bands with `param_6` row-stride), FFTs each **column** (`cr_fft_real_fwd`, 0x180029510) and places it into `out`, then FFTs each **row** after periodic top/bottom boundary extension. Pure float copies (no float arithmetic) + two FFT calls. Tested with symmetric centred inputs `w=ncols-2e, h=nrows-2e` (e∈{0,1,2}) to cover no-crop and padded paths. Passed the difftest bit-for-bit (302 ok). |
| `0x18000f8b0` | `fpc_bio_bep_sw23_*` | `cr_ncc_apply_f8b0` | Thin template-NCC apply. `int fn(const uint64_t *img_out, const uint64_t *img_in, uint16_t radius)`. Validates the two 4×uint64 image descriptors (`[0]==[2]` and `[3]==0` else 0x69; `[1]`=int16 data ptr, `[2]`=w\|h<<32), allocates a radius-length int16 ref buffer filled with `(short)(32768.0/radius)`, then runs `cr_template_ncc_283d0(out, in, ref, radius, w, h)` and `cr_template_ncc_35150(out, out, ref, radius, w, h)` in place; returns the status (0 / 0x69 / 1). Passed the difftest bit-for-bit (304 ok). |
| `0x180034390` | `fpc_bio_bep_sw23_*` | `cr_ncc_apply_34390` | Same as `cr_ncc_apply_f8b0` but the ref buffer (n int16) is filled by `cr_gaussian_window_q15(ref, sigma, n)` instead of a constant; the 4th arg is `n` (also used as the NCC radius). Passed the difftest bit-for-bit (304 ok). |

### Batch 73 — blur/kernel-apply dispatcher

| vendor RVA | vendor symbol | clean-room name | behaviour |
|---|---|---|---|
| `0x18001c6a0` | `fpc_bio_bep_sw23_32f906bc87.part.2` | `cr_blur_dispatch_1c6a0` | `int fn(void *a, void *b, float sigma, int count, int sel)`. Leaf tail-jump: reads `sel` from `[rsp+0x28]` (argument 5, on the stack), zero-extends `count` (`movzx r9d,r9w`), overwrites `r8` with the jump-table base `0x18008c4b0` and jumps through the 5-entry table on the **low byte** of `sel` (`cmp r8b,4 ; ja default`). The table order is *not* the natural one — dumped from the DLL: `sel 0 → cr_gauss_fir_apply (0x180046610)`, `sel 1 → cr_sep_gauss_blur_s16_reflect (0x180013a30)`, `sel 2 → cr_correlate_34930 (0x180034930)`, `sel 3 → cr_ncc_apply_34390 (0x180034390)`, `sel 4 → cr_sep_gauss_blur_s16 (0x1800278f0)`, `sel > 4 → 0x69`. Every target reads `sigma` from **xmm2** and `count` from `r9`, so the dispatcher just forwards them (`r8` is clobbered and ignored). **ABI trap:** the signature is `(ptr, ptr, float, int, int)` — under the Microsoft x64 convention the position-3 float lands in `xmm2`, the position-4 int in `r9`, and the position-5 int on the stack, which is exactly what the vendor reads. Modelling it as `(ptr, ptr, int, int, int, float, float, float)` (a plausible but wrong guess) sends the floats to the stack and leaves `xmm2` stale, so the sigma-dependent targets (sel 0/1) mismatch. Passed the difftest (312 ok). |

### Batch 74 — blurred-pair difference normaliser

| vendor RVA | vendor symbol | clean-room name | behaviour |
|---|---|---|---|
| `0x18001ee30` | `fpc_bio_bep_sw23_3d3372550f` | `cr_blur_diff_norm` | `int fn(cr_image *src, const void *obj)` (two pointers → rcx/rdx, no float argument positions). `W=src->w`, `H=src->h`, `N=W*H`. Allocates two `N*2`-byte int16 blocks with `cr_pool_alloc2` and wraps them as `cr_image ia/ib` via `cr_image_set`. Runs `cr_blur_dispatch_1c6a0` twice on the same source — `sigma0 = obj[0]`, `sigma1 = obj[1]`, `count = 0xf`, selector byte `obj+12` — then writes in place into `src->data`: `dst[i] = (int16_t)(A[i] - B[i])`, tracking `m = max |dst[i]|`. Frees the pool, sets `scale = m ? (int)(0x7f0000/m) : 0x400`, and maps every pixel through `t = (dst[i]*scale >> 10) + 0x2000`, clamped to `[0, 0x3fc0]` (`t < 1 → 0`, `t >= 0x3fc0 → 0x3fc0`). Returns 0 on success, else the first failing status; the pool is freed on every post-allocation path. The caller (`0x180018c60`) passes `obj = RBX+0xe4`, so the selector is a config byte at `obj+12`. Passed the difftest (313 ok). |

### Batch 75 — u8 blurred-pair difference normaliser (float source)

| vendor RVA | vendor symbol | clean-room name | behaviour |
|---|---|---|---|
| `0x1800148c0` | `fpc_bio_bep_sw23_1c8303fae6` | `cr_blur_diff_norm_u8` | `int fn(cr_image *dst, const cr_image *src, const void *obj)` (three pointers → rcx/rdx/r8). `W=src->w`, `H=src->h`, `N=W*H`. Allocates three `N*2`-byte int16 blocks with `cr_pool_alloc3` (`ia/ib/ic`); `ia` becomes the float source scaled by 64 and rounded (`cr_f32_to_i16_scaled(&ia, src, 6)`). Blurs `ia` twice — `sigma0 = obj[0]`, `sigma1 = obj[1]`, `count = 0xf`, selector byte `obj+12` — then `ia[i] = (int16_t)(ib[i] - ic[i])`, `m = max |ia[i]|`, `scale = m ? (int)(0x7f0000/m) : 0x400` (32-bit signed division), and writes `dst->data[i] = clamp(((ia[i]*scale + 0x8000) >> 16) + 0x80, 0, 0xff)` (`t > 0xfe → 0xff`, `t <= 0 → 0`). Returns 0 on success, else the first failing status; the pool is freed on every post-allocation path. u8-output sibling of `cr_blur_diff_norm`. Passed the difftest (314 ok). |

### Batch 76 — local-contrast normaliser

| vendor RVA | vendor symbol | clean-room name | behaviour |
|---|---|---|---|
| `0x180013720` | `fpc_bio_bep_sw23_1901aeeef9` | `cr_blur_divnorm_stretch` | `int fn(cr_image *img, const void *cfg)` (two pointers → rcx/rdx). `cfg`: float +4 (blur sigma), float +8 (denominator factor), byte +0xc (selector; only 3 or 4 valid, else `0x69`). `W=img->w`, `H=img->h`, `N=W*H`. Allocates `A,B` (int16) and `C` (float) of W×H via `cr_image_alloc_s16` / `cr_image_alloc_f32`. For N > 0: `mean = (Σ sign-extended img pixels)/N` (`IDIV`); then `p = (uint16_t)img[i] - mean` (**unsigned** load), `img[i] = (int16_t)p`, `A[i] = (int16_t)((int16_t)p < 0 ? -p : p)`; `B = cr_blur_dispatch_1c6a0(&B, &A, sigma, (uint16_t)(int)(sigma*8+1), sel)`; `maxB = max(0, max_i B[i])`; `C[i] = (float)img[i] / max(cfg[2]*maxB, (float)B[i])` tracking `mx`/`mn`; `scale = (1.0f > mx-mn) ? 16320.0f : 16320.0f/(mx-mn)`; `img[i] = (int16_t)(int32_t)((C[i]-mn)*scale)`. For N <= 0 it only runs the blur once. `A/B/C` freed on every post-allocation path. Passed the difftest (315 ok). |

### Batch 77 — oriented matched filter

| vendor RVA | vendor symbol | clean-room name | behaviour |
|---|---|---|---|
| `0x180045eb0` | `fpc_bio_bep_sw23_f24e438404` | `cr_matched_filter_45eb0` | `int fn(int16_t *out, const uint8_t *const *rows, const void *cfg)` (three pointers → rcx/rdx/r8, no float argument positions). `cfg`: int +0xc (kernel-bank stride multiplier `kmul`), int +0x10 (`W`), int +0x14 (`H`), int +0x18 (`flag`), ptr +0x20 (`kbase`, int16 bank, 25 shorts/kernel), ptr +0x28 (`mbase`, int16 per-row bias). For each output row `r` in `0..H-1` with `bias = (int)mbase[r] << 14` and kernel block `kptr = kbase + r*kmul*25`: a chunk pass over byte offsets `off = 0,4,…,4u` (`u = (W-2)>>1`) computes two 5×5 convolutions — `A` over `rows[0..4]`, `B` over `rows[1..5]` — at 4 horizontal offsets each, and stores `out[2k] = scale(max(A0,A1,B0,B1))`, `out[2k+1] = scale(max(A2,A3,B2,B3))`; a tail pass over columns `j = 2u+2 .. W-1` (2 offsets each) stores `out[j] = scale(max(A0,A1,B0,B1))`. `scale(v) = (int16_t)(((uint32_t)v << 6) + bias) >> 15` (32-bit wrapping, `SAR 0xf`). For `W < 2` only the tail pass runs (from `j = 0`). If `flag == 1` the whole `W*H` output is clamped non-negative (`cr_s16_clamp_nonneg`, `0x180012060`) at the end. Always returns 0. Passed the difftest (316 ok). |

### Batch 78 — frame quality gate

| vendor RVA | vendor symbol | clean-room name | behaviour |
|---|---|---|---|
| `0x180035cf0` | `fpc_bio_bep_sw23_a6e520d415` | `cr_quality_gate_35cf0` | `int fn(cr_image *img, float *out_q, uint8_t *out_flag, void *state, void *src, void *handle, const void *cfg)`. rcx/rdx/r8/r9 = img/out_q/out_flag/state; src/handle/cfg are the 5th/6th/7th args (on the stack). `handle` is a TLV metadata store read via `cr_meta_get_u32` for keys `0xda`/`0xdd`/`0xd2`/`0xd6`. `state`: +0x00 ptr to a ≥0x14-byte history, +0x10 previous int16 image, +0x40 frame count, +0x44 frame counter (incremented, saturating at `0x7fffffff`), +0x48 running quality average, +0x4c running score average. `cfg`: +0x08 max level, +0x0c min quality, +0x10 margin x, +0x14 margin y, +0x18 diff flag (signed), +0x1c ratio, +0x20 flag threshold, +0x2c mode (0 → level 200/sigma 10; 2 → level `0xff-…`, sigma `t/1024`; 3 → sigma `t/1024`; else sigma 10), +0x30 scale. Computes `q = scale * 1/((float)level * a/1024 * b/1024 * sigma)`, stores it, gates on `q > 2.0078433f` and on the running average vs `ratio`, then `cr_downsample_mean(img, src, 4)`; if `cfg[0x18] > 0` it allocates an int16 image, runs `cr_ncc_apply_f8b0(desc, img, 5)` and subtracts the result from `img` where the pixel is `<= 0xf9` (unsigned 16-bit load). Finally `cr_corr_coeff` on `img` vs `state[2]`, shifts a 19-byte history (`hist[i+1]=hist[i]`, summing), copies `img` into `state[2]` when the correlation passes `cfg[0x0c]`, and updates the running score `(sum/div1 + div1*avg_s)/div2` (`div1 = min(counter,20)`, `div2 = div1+1`). Sets `*out_flag = 1` when the score beats `cfg[0x20]`. Returns 0 / `0x3eb` (metadata) / `0x3ec` (input) or the first failing status. Passed the difftest (317 ok). |

### Batch 79 — scale-space Laplacian blob detector

| vendor RVA | vendor symbol | clean-room name | behaviour |
|---|---|---|---|
| `0x18001bbf0` | `fpc_bio_bep_sw23_31febb3ff4` | `cr_blob_detect_1bbf0` | `int fn(cr_grid *grid, const cr_image *desc, const int32_t *maskcfg, const void *cfg)` (four pointers → rcx/rdx/r8/r9). `desc` is a scaled-image descriptor: `+0x00` row pitch, `+0x04` image rows, `+0x08` pixel pointer, `+0x10`/`+0x14` scaled width/height, `+0x18`/`+0x1c` x/y margins. `cfg` byte `+8` = margin `mode` (signed), float `+0x1c` = sigma; the same buffer also carries the `cr_grid_cfg` fields `cr_grid_insert` reads (`+0x10` cap2, `+0x24` mode). Bounds checks (else return `0x69`): `desc[6]+mode > 6`, `desc->w+7+(desc[6]-mode) <= desc->a`, `desc[7]+mode > 6`, `desc->h+7+(desc[7]-mode) <= desc->b`. Then `Wn = desc->w-2*mode`, `W2 = Wn+2`, `W4 = Wn+4`, stride `S = Wn+14`; allocates an aligned-16 int16 scratch of `(Wn+0xc+W4)*3*2` bytes. Builds an 11-tap Q15 Gaussian window (`cr_gaussian_window_q15(coef,sigma,11)`), then four `cr_sep11_row` calls (rows `2S, S, 0, 2S`) and two `cr_laplacian_3x3` calls (`out = 3S+W2` from `(2S,S,0)`, then `out = 3S` from `(S,0,2S)`), all over source rows starting at `pix + (desc[7]+mode-2)*pitch + desc[6]+mode-2` and advancing by one row each call. The main loop runs `y` from `mode` to `desc->h-mode-1`: each iteration advances the source row, smooths into a rotating ring slot, takes the Laplacian of three consecutive smoothed rows, and for every column `col` in `[0,Wn)` whose centre `psVar21[col+1]` strictly exceeds all eight 3×3 neighbours, bit-tests the mask word at bit index `(maskcfg[7]+y)*maskcfg[0] + (mode+col+maskcfg[6])` (`maskcfg[2..3]` = word pointer) and, if set, calls `cr_grid_insert(grid, (uint8_t)(mode+col), (uint8_t)y, (float)centre, cfg)`. Frees the scratch and returns 0 (or the allocation status). Passed the difftest (318 ok). |

### Batch 80 — Gaussian-derivative structure-tensor orientation

| vendor RVA | vendor symbol | clean-room name | behaviour |
|---|---|---|---|
| `0x18000d3b0` | `fpc_bio_bep_sw23_...` | `cr_structure_orient_d3b0` | `int fn(void *dst, const cr_image *src, const void *mask, uint8_t and_mask, const void *cfg)` (rcx/rdx/r8/r9/[rsp] = cfg). Reads `W=src->w`, `H=src->h`, `cfg` int16 `+0x0c` = `count`, uint8 `+0x0f` = `flag`, float `+0x04` = `sigma1`, float `+0x08` = `sigma2`. Allocates two `W×H` int16 images `A,B` via `cr_image_set` + `cr_pool_alloc2`, then `cr_gauss_deriv_3img(&A,&B,src,sigma1)`. Per pixel computes the 2×2 structure-tensor eigen-decomposition of `(aa,ab,bb)=(A²,A·B,B²)`: `half=(aa+bb)/2`, `s=√(half²-(aa·bb-ab²))`, `l1=half+s`, `l2=half-s`; dominant eigenvector encoded as `(cross,diff)=(ab, |l1|≥|l2| ? l2-aa : l1-aa)`; coherence `coh = ((|l1|-|l2|)² / (|l1|²+|l2|²+1e-7)) * 16383`; edge case `ab² ≤ 1e-12` → `(cross,diff)=(|aa|≥|bb| ? 0:1, |aa|≥|bb| ? 1:0)`. `A[i]=(cross²-diff²)/norm * coh`, `B[i]=2·cross·diff/norm * coh`; when `flag==1` and `(mask[i] & and_mask)==0`, `coh=0`. Then blurred: `count==1` → single `cr_blur_dispatch_1c6a0` pass on each of `A,B` (radius `(min(W,H)-1)|1` capped at `0x51`), `count>0` → `count` passes of `cr_gaussian_fir_2pass`, else none. Finally `cr_cordic_atan_q15(dst->data, B, A, W*H, 2)` and free. Returns 0 / first failing status. Passed the difftest (319 ok). |

### Batch 81 — Gaussian-derivative structure-tensor orientation (3-image twin)

| vendor RVA | vendor symbol | clean-room name | behaviour |
|---|---|---|---|
| `0x18003b960` | `fpc_bio_bep_sw23_...` | `cr_structure_orient_3b960` | Same signature/flow as `cr_structure_orient_d3b0` but the three tensor planes arrive precomputed from `cr_gauss_deriv_triple_guarded(&I1,&I2,&I3,src,sigma1)` (outputs `o1,o2,o3`). The assembly fixes the per-pixel roles: the 2×2 tensor is `[[o1, o2],[o2, o3]]`, i.e. `fVar15=o3` (other diagonal), `fVar19=o2` (off-diagonal / small-test / `cross`), `fVar18=o1` (baseline diagonal). The eigen-decomposition, `(cross,diff)` selection (`uVar7 = (|l2|≤|l1|)`), coherence, `flag`/mask zeroing, and int16 rounding are identical to `d3b0`. `output1` is stored back into **I1** and `output2` into **I3** (I2 is never rewritten); `I1` and `I3` are then blurred (`count==1` → `cr_blur_dispatch_1c6a0` radius `(min(W,H)-1)|1` capped `0x51`; `count>0` → `count` × `cr_gaussian_fir_2pass`) and finally `cr_cordic_atan_q15(dst->data, I3, I1, W*H, 2)`. Returns 0 / first failing status. Passed the difftest (320 ok). |

### Batch 82 — mask-weighted spatial bin selection

| vendor RVA | vendor symbol | clean-room name | behaviour |
|---|---|---|---|
| `0x180014320` | `fpc_bio_bep_sw23_...` | `cr_bin_select_14320` | `int fn(void *pts, int *out_count, int npts, int maxout, const void *mask, uint32_t seed, const void *cfg)` (rcx/rdx/r8d/r9d/[rsp+0x20]/+0x28/+0x30). `pts` = `npts` records of 8 B `{int32 key(+0); int16 x(+4); int16 y(+6)}`; `mask` = `{int stride(+0); uint32 *words(+8); int w(+0x10); int h(+0x14); int x0(+0x18); int y0(+0x1c)}`; `cfg` = `{int8 margin(+8); int16 maxpts(+0x10); int weight(+0x14); uint8 NX(+0x25); uint8 NY(+0x26)}`. Allocates `bin_count`, `next_ptr` (`maxpts`), `bin_head`, `order` (all `cr_malloc_aligned16`, `nb=NX*NY` entries of 4 B), zeroing `bin_head=-1`, `bin_count=0`. `bw=ceil((w-2m)/NX)`, `bh=ceil((h-2m)/NY)`. Bins every point in **reverse** index order: `bx=clamp((x-m)/bw,0,NX-1)`, `by=clamp((y-m)/bh,0,NY-1)`, copies the key `+0→+4`, increments `bin_count[by*NX+bx]` and pushes the index onto that bin's linked list (`bin_head`/`next_ptr`). Then for each bin sums the mask bits over its clipped pixel window `[m+col, min(m+bw+w…, w-m)) × [m+row, min(…, h-m))` reading `words[lin>>5] >> ((lin-rowbase)&0x1f)` (`lin=(y0+r)*stride+x0+col`), sets `bin_count = min(bin_count, cr_lroundf(bits*weight/(bw*bh*nb)))`. Counts empty bins, `cr_shuffle_indices(order,nb,seed)`, then round-robins the shuffled bins popping one point at a time (`out[i]=in[head].+4`, `bin_head=next_ptr[head]`, decrement `bin_count`) until `maxout` points or all bins empty. Sets `*out_count`, frees, returns 0 / first failing status. Passed the difftest (321 ok). |

### Batch 83 — orientation / grid dispatchers and the feature-extraction step

| vendor RVA | vendor symbol | clean-room name | behaviour |
|---|---|---|---|
| `0x18002cfd0` | `fpc_bio_bep_sw23_7bed5f5baa` | `cr_structure_orient_dispatch_2cfd0` | `int fn(void *dst, const void *src, const void *mask, uint8_t and_mask, const void *cfg)`. Tail-jumps on `cfg[0x10]`: `0` → `cr_structure_orient_d3b0`, `1` → `cr_structure_orient_3b960`, else returns `0x69`. Every argument is forwarded unchanged. Passed the difftest (322 ok). |
| `0x180038020` | `fpc_bio_bep_sw23_af79bb854b` | `cr_grid_populate_dispatch_38020` | `int fn(cr_grid *grid, const cr_image *src, const void *mask, const void *cfg)`. Stores `grid->count = 0` (`[rcx+0x40]`), then tail-jumps on `cfg[1]`: `4` → `cr_blob_detect_1bbf0(grid, src, mask, cfg)`, `5` → `cr_harris_local_minmax_grid(grid, src, mask, cfg)`, `1` → `cr_harris_local_max_grid(grid, src, mask, cfg)`, else returns `0x69`. `mask` is the blob `maskcfg` for selector 4 and the mask image for selectors 5/1. Passed the difftest (323 ok). |
| `0x180026dc0` | `fpc_bio_bep_sw23_66a478b71e` | `cr_feature_extract_step_26dc0` | `int fn(void *state, const cr_image *img, void *handle, const cr_image *packed, const void *cfg)`. Guard: `mode = *(int16*)(cfg+0x24)`, `(uint16)(mode-1) >= 0x7ff` → `0x69`. Allocates a `(W/4)×(H/4)` int16 image `q16` (`W=img->w`, `H=img->h`), runs `cr_quality_gate_35cf0(&q16, &q, &flag, state, img, handle, cfg)`, frees `q16` with `cr_cleanup_ptr8_clear`; a non-zero gate status is returned, and `flag != 1` returns 0. Then allocates a `W×H` u8 image; if `state->count (+0x40) == 0` it is filled with `0xff` via `cr_fill`, otherwise `cr_bitmap_unpack_boxmax_fir(&u8img, packed, 1, 1, 1.5f)` (error → free and return). The image is folded in with `cr_weighted_running_avg(*(state+0x18), state+0x58, img, &u8img.data, q, cfg+0x24)`, freed with `cr_cleanup_ptr8_a`, `state->count` is incremented when `< mode`, and finally `*(int8*)(state+0x08) < 1` runs `cr_feature_qualify(state, cfg, q)`. Returns the qualifier's status or 0. Passed the difftest (324 ok). |

### Batch 84 — float-source feature-extraction step

| vendor RVA | vendor symbol | clean-room name | behaviour |
|---|---|---|---|
| `0x18002db20` | `fpc_bio_bep_sw23_78d706f81a` | `cr_feature_extract_step_2db20` | `int fn(void *state, const cr_image *fimg, void *handle, const cr_image *packed, const void *cfg)`. The float-source twin of `0x180026dc0`: same guard, gate and qualifier plumbing, but the *source* image `fimg` holds **float** pixels. A `W×H` u8 working image is allocated and filled inline with `clamp((int)(fimg[i] + 0.5f), 0, 255)`, then a `(W/4)×(H/4)` int16 scratch is allocated and fed to `cr_quality_gate_35cf0(scratch, &q, &flag, state, u8, handle, cfg)`. On gate failure the u8 image is freed and the status returned; `flag != 1` frees and returns 0. The packed image is expanded into a second `W×H` u8 image with `cr_mask_boxmax_fir_clear(&u8b, packed, 0xf, 1, 1, 1.5f)` (first frame: `cr_fill(0xff)` instead), folded via `cr_weighted_running_avg(*(state+0x18), state+0x58, u8, &u8b.data, q, cfg+0x24)`, `state->count` bumped when `< mode`, and `*(int8*)(state+0x08) < 1` runs `cr_feature_qualify`. Every error path frees the u8 working image (`cr_cleanup_ptr8_a`). Passed the difftest (325 ok). |

### Batch 85 — directional 5x5 matched-filter bank

| vendor RVA | vendor symbol | clean-room name | behaviour |
|---|---|---|---|
| `0x18003de60` | `fpc_bio_bep_sw23_cb074cb39c` | `cr_dirbank_3de60` | `int fn(int16_t *out, const int16_t *const *rows, const void *cfg)`. Fixed-point (Q15) directional matched-filter bank. `cfg`: `+0x08` stride, `+0x0c` ncoef, `+0x10` w, `+0x14` h, `+0x18` normalise, `+0x20` coefA (`h*ncoef*25` shorts), `+0x28` coefB (`h` shorts). `rows` is an array of ≥6 int16 row pointers. Per output row `r` the bias `coefB[r]*0x4000` is added; a 5×5 correlation is slid over `ncoef` orientation blocks (each block a distinct 25-short kernel) and **two shifted responses are max-pooled** into two int16 channels (`>>15`, arithmetic). A trailing partial column (`(w-2)>>1` full pairs then the remainder) uses a reduced 5-tap edge kernel. If `cfg+0x18 == 1` the whole `w*h` plane is then clamped non-negative (`cr_s16_clamp_nonneg`). Returns 0. Passed the difftest (326 ok). |

### Batch 86 — three-level matched-filter pyramid

| vendor RVA | vendor symbol | clean-room name | behaviour |
|---|---|---|---|
| `0x1800364c0` | `fpc_bio_bep_sw23_a9419e00dd` | `cr_pyramid_364c0` | `int fn(int16_t *out, const void *obj, const cr_image *img, const cr_sampler *s)`. `obj+0x08` → a descriptor of three 0x30-byte levels; the guard requires the plane counts `5/3/5` (`L0[0]==5 && L1[0]==3 && L2[0]==5`). Phase 1 partitions the caller-owned `out` into three row-pointer arrays: level *k* holds (planes+1) pointers spaced `stride_k` shorts apart, with `stride_0=(L0[3]*L0[2]+1)/2` and `stride_{1,2}=L{1,2}[3]*L{1,2}[2]` (the multiplier starts at 1, becomes 2). Phase 2 streams `(L2[1]-4)>>1` output blocks: bilinearly resamples new level-0 rows (`cr_bilinear_sample_u8`, `n=L0[2]` samples at an increasing global idx), runs `cr_matched_filter_45eb0` into a level-1 plane, `cr_block_conv_231a0` into a level-2 plane, and `cr_dirbank_3de60` into the next block of the tail region; each level's pointer ring is rotated by 2 (`cr_array_rotate`) and its fill index backed off by 2 when consumed. Phase 3 interleaves the block planes into the front of `out` (`out[b*nblocks+r] = block[r] row[b]`). Returns 0, `0x69` on a guard mismatch, else the first nonzero callee status. Passed the difftest (327 ok). |
| `0x180025960` | `fpc_bio_bep_sw23_62b3ad8b73.part.2` | `cr_template_remove_25960` | `int fn(cr_image *img, const cr_image *mask, int sel)`. Fixed-pattern (ridge template) removal on a float image. Guard: `img == NULL` -> `0x69`; odd `h` **and** odd `w` -> `0x69`; `sel` must be 1 (h = 80, table `0x180117240`) or 2 (h = 176, table `0x180159760`) — `sel == 0` returns 0, anything else `0x3ee` — and then `h` must match the table and `w == 64`, else `0x3ee`. A scratch `h*64` float plane is seeded with the separable ridge template (row `o < h/2` = `tab[o]`, row `h-1-o` = `tab[h/2-1]`, each plus the 32-entry ramp `tab[0..32)` mirrored about the row centre), blended toward the centre sample `buf[n/2+32]` by `src/255`, fitted with `gain = 0.9*sum((buf*cnt - sum)*src) / (cnt*sumsq - sum^2)` over the `mask == 0xff` samples (clamped at 0; left at 1.0 when the variance is exactly 0), then `src -= (buf - mean(buf))*gain` and finally each pixel is blended back toward `max(src)` by the mask byte and clamped to [0,255]. The centre sample is re-read from the scratch plane on every pixel, so the scan feeds the blended value back after passing that index. The scratch plane is released and 0 returned. Passed the difftest (328 ok). |
| `0x180037460` | `fpc_bio_bep_sw23_acac607cac` | `cr_grid_pick_37460` | `int fn(void *pts, int *out_n, int npts, int want, const cr_image *bits, uint32_t seed, const void *cfg)`. Buckets `npts` 8-byte records `{int32 v; int16 x; int16 y;}` into a `cfg[0x25]` x `cfg[0x26]` grid. Phase 1 walks the records in reverse, moves each record's 4-byte value word over its x/y halves, maps `(x*gw)/imgw` / `(y*gh)/imgh` (clamped into range) and prepends the index to the cell's list. Phase 2 slides a `gw` x `gh` window over the 1-bit-per-pixel `bits` bitmap, counts set bits, and stores `min(round(cnt*want / ((xhi-xlo)*N*(y2-col))), cell count)`. Phase 3 walks the cells in a seeded shuffle order emitting one point per visit until `*out_n == want`; cells whose quota has run out are only used when every cell is empty. Frees the four scratch arrays and returns 0. Passed the difftest (329 ok). |
| `0x180025050` | `fpc_bio_bep_sw23_604499eb5a` | `cr_mask_pipeline_25050` | `int fn(cr_image *img, const cr_index_list *list, const uint8_t *cfg, cr_image *mask)`. Mask-driven inpaint / classify pipeline dispatched on `cfg[0]`: 1 = box inpaint (and 2, apply 1) + list inpaint + classify + box inpaint (and 0x13, apply 0); 2/3 = the same without the trailing box call (apply 1 / 0); 4 = list inpaint then up to `cfg+2` rounds of `{pick every listed pixel with mask bit 2, 5x5 masked box mean with and-mask 0x1b, accept when count > 5, set mask 0x20}` followed by `0x20 -> 8`; 5 = plain list inpaint; 7 = two-pass row/column gap interpolation (rows whose horizontal neighbour differences are all below the `cfg+4` threshold bracket a vertical lerp of the strictly positive samples, then the transposed pass; run lengths capped by the signed bytes at `cfg[0xc]`/`cfg[0xd]`). `cfg[1]` enables the u16 limit at `cfg+2` (list count above it -> `0x3e9`), and the post-check returns `0x3e9` when any listed pixel still has mask bit 2. Passed the difftest (331 ok). |
| `0x18002bd60` | `fpc_bio_bep_sw23_78d706f81a.isra.2.part.3` | `cr_norm_2bd60` | `int fn(cr_image *img, const cr_image *mask, const uint8_t *cfg)` on an int16 image. `cfg[0x0a] == 1` first runs a row-mean correction: every row mean is cached, the mean of rows `[row0, row0+nrows)` is added back and the row's own mean subtracted for the top `row0` rows, then the same for the bottom `row0` rows using the block `[h-row0-nrows, h-row0)`. `cfg[9]` then selects 0 (no-op), 1 (per-column gain so each column mean matches the `[x0, x0+cfg[0x10])` window mean), 2 (per-column offset) or 3 (per-column `(v-mean)*tab[c] + window_mean` with one of six fixed tables selected by `cfg[0xb]`, requiring `w == 32/35/36`). Modes 1/2 need `h > 30`; every other guard failure returns `0x69`. Samples are selected by mask bits `0xe`; the mask's `w` field is used as its row stride. Output is clamped at 16320 (mode 2 also at 0). Passed the difftest (331 ok). |
| `0x180016b90` | `fpc_bio_bep_sw23_2013a4f2e9` | `cr_pick_dispatch_16b90` | `int fn(void *pts, int *out_n, int npts, int want, const void *src, uint32_t seed, const void *cfg)`. Pure dispatch on `cfg[0x24]`: 0 -> `cr_keypoint_grid_sample` (`src` is the int dims array), 1 -> `cr_grid_pick_37460` (`src` is the bitmap image), 2 -> `cr_bin_select_14320` (`src` is the mask image); any other selector returns 0 without touching the outputs. Passed the difftest (332 ok). |
| `0x18002f2e0` | `fpc_bio_bep_sw23_86c3ffb0b2` | `cr_pick_points_2f2e0` | `int fn(uint8_t *out_xy, float *out_val, int *out_n, const uint8_t *xy_tab, const float *val_tab, int npts, int want, const void *src, uint32_t seed, const void *cfg)`. `npts == 0` -> 0. Allocates `(int16)cfg[0x10]` 8-byte records, fills them with `{int32 i; float val_tab[i]}`, sorts by value descending (`cr_sort_records(rec, npts, 1, 1)`), then overwrites the value word with `{int16 x; int16 y}` from `xy_tab[i*2]`. Calls `cr_pick_dispatch_16b90(rec, out_n, npts, min(npts,want), src, seed, cfg)`; on success copies the selected records back to `out_xy` (2 bytes) and `out_val` (original float). Frees the scratch array and returns the dispatch status. A negative `npts` skips the record fill. Passed the difftest (334 ok). |
| `0x1800317a0` | `fpc_bio_bep_sw23_94f134be25` | `cr_mask_inpaint_317a0` | `int fn(uint8_t *flag, const cr_image *img, const cr_index_list *list, const uint8_t *cfg)`. `*flag = 0` up front. `cfg[0] == 5`: guard `cfg[1] && *(u16*)(cfg+2) < list->count` -> `0x3e9` (NULL/empty list -> 0), allocate and zero a `count`-byte flag array, then sweep the whole list with `cr_box_sum_excl` at windows 3 and 5 (`win==5` needs count > 5, else count > 0), storing `(int)(sum/cnt + 0.5f)` and `flags[i] = 100/win`; after that only border pixels (row/col outside `[2, n-3]`) are retried, at window 5 then window 7, with `flags[i] = floor((1/win)*100)`, and when an unfilled border pixel survives window 9 the loop jumps straight to the flag check (with `cfg[1]` any remaining zero flag -> `0x3e9`). `cfg[0] == 7`: row pass scans adjacent horizontal pairs for a squared difference `>= *(int*)(cfg+4)` and, between two successive detections separated by `run` rows, lerps every strictly positive column down the run with `step = (0x400/(run+1))*(b-a)` and `((acc+0x200)>>10)+a`; the transposed column pass does the same across columns and sets `*flag = 1` when `run` exceeds the signed byte cap at `cfg[0xd]` (row cap `cfg[0xc]`). Any other mode -> `0x410`. Passed the difftest (333 ok). |

### Batch 87 — feature packing / descriptor assembly

| vendor RVA | vendor symbol | clean-room name | behaviour |
|---|---|---|---|
| `0x18000e850` | `fpc_bio_bep_sw23_0330ba9356` | `cr_feat_pack_0e850` | `int fn(cr_image *src, cr_feat_obj *obj, const uint8_t *cfg)`. Builds the packed feature object. `cfg[0xb]` -> `cr_desc_get_tag_byte_ptr` (M=25, N=16, selector byte), `cfg[0xe]` -> `cr_desc_get_triple` (a=16, b=32, coef/thr tables); a non-zero `cfg[0xe]` requires `ws.n == td.a`, and `cfg[0xb] > 0xc` -> `0x69`. Stores `obj+0x30 = cfg[0xc]`, `obj+0x31 = ws.b8`, `obj+0x34 = td.b` and, when `td.b > 0`, allocates `(td.b+1)` u16 bins at `obj+0x38`. Allocates an `N*N` byte warp scratch plus `count` 8-byte `{index, score}` records; per keypoint it warps into the scratch (`cr_warp_rotate_u8`), sign-packs into `obj->rows + b8*i` (`cr_signpack_dot`), optionally orientation-picks (`cr_orient_pick`, skipped when `cfg[0xc] != 0`) and scores (`cr_norm_corr_score`). Then sorts the records ascending and permutes the four parallel arrays (`cr_permute_rows`), and fills the `(nbins+1)`-entry u16 table with the first sorted index whose score exceeds each threshold. Returns the first failing callee status. Passed the difftest (335 ok). |
| `0x180021000` | `FUN_180021000` (no export) | `cr_maxpool_stream_21000` | `int fn(uint8_t *buf, const int *chain, const cr_image *img, const cr_sampler *s)`. Row-streaming 5x5 max-pool stage runner. `chain[2]` is the stage-descriptor array; the guard requires `desc[3] == 1 && desc[0] == 5`, otherwise the *caller's* `buf` is released with `cr_sized_free` and `0x69` returned. `buf` holds six rows of `W = desc[2]` bytes followed by the int16 output. Four rows are pre-rolled through `cr_bilinear_sample_u8` (indices 0..3); each of the `((H-4)>>1)` output rows shifts the window up two rows, samples the next two, then runs `desc[5]` kernels. Per pixel the four 5x5 correlations over the 6x6 window at the four 2x2 sub-offsets are max-reduced (signed), `(max << 6) + bias*0x4000` is arithmetic-shifted right by 15 and truncated to int16; plane stride is `ow*oh`, column step is 2. `desc[6] == 1` clamps the whole plane non-negative. The output is then copied to the head of `buf` and stages `1..chain[0]-1` run through `cr_filter_chain_run_i16`; a failure there also frees `buf` before returning the status. Passed the difftest (336 ok). |
| `0x18002b680` | `fpc_bio_bep_sw23_777e3255f8` | `cr_pick_points_dispatch_2b680` | `int fn(void *a, const void *src, const uint8_t *cfg)`. `cfg[0x24] != 2` -> 0 without touching anything. Otherwise forwards to `cr_pick_points_2f2e0` with the seven fields held in `a`: `out_xy` (+0x08), `out_val` (+0x10), `out_n` (+0x40), `xy_tab` (+0x20), `val_tab` (+0x28), `npts` (+0x44), `seed` (+0x4c), plus the caller's `src` and `want = *(int*)(cfg+0x14)`. Passed the difftest (337 ok). |
| `0x1800273a0` | `fpc_bio_bep_sw23_6896a40de5` | `cr_stage_run_273a0` | `int fn(float *out, const int *chain, const cr_image *img, const cr_sampler *s)`. `chain[2]` -> stage descriptors. When `chain[0] == 3` and the descriptors form a three-level pyramid (`d[0]==5`, `d[0xc]==3`, `d[0x18]==5`) the buffer is sized `sum over the three 0x30-byte levels of (tag+1)*L[0]*L[1]*(1,2,2)` plus `2*first_block[0]` when `chain[4] > 0`, and the stage runs through `cr_pyramid_364c0`; otherwise the size is `2*trunc((H-tag+1)/2) * ((W-tag+1)/2) * nk + (tag+1)*H`, raised to `2*chain[9]`, and the stage runs through `cr_maxpool_stream_21000`. Then each of the `chain[4]` 0x20-byte block descriptors `{p0, p1, flag, -, coef*, bias*}` projects the first `p0` int16 of the buffer onto `p1` outputs with `(sum_j coef[r*p0+j]*buf[j] + bias[r]*0x4000) >> 15` (32-bit wrapping), `flag == 1` clamping the block non-negative; the `p1` results are copied back over the head of the buffer. `cr_softmax2` then writes the single float result from `buf[0]`, `buf[1]` and the buffer is released. Stage failure frees the buffer and returns the status unchanged. Passed the difftest (338 ok). |

## Deferred (identified, not yet rewritten)

| vendor RVA | vendor symbol | why deferred |
|---|---|---|
| `0x180030340` | `fpc_bio_bep_sw23_8d79fe3601` | returns static table pointers — needs the table contents. |
| `0x18004a680` | `fpc_bio_bep_sw23_...` | 176 B `fpc_image_data_dump`: calls `cr_buf_is_metadata_class` (`0x180049120`) *before* its NULL check — needs the metadata-class predicate first. |
| `0x180048d40` | `fpc_bio_init` | returns `*(void**)0x18016f4c8 + 8` — a global-context getter (pointer-valued, out-of-tree). |
| `0x18002ba80` | `fpc_bio_bep_sw23_7861b9e0de` | 624 B CORDIC/rotation: uses the u16 coefficient table at `0x180117120` (12 B/entry) and the `cr_clz` helper (`0x1800393b0`). |
| `0x18001fd10` | `fpc_bio_bep_sw23_444798a52f` | 672 B fixed-point Q15 bilinear warp with `cr_ldexpf`-scaled step increments. |
| `0x180043040` | `fpc_bio_bep_sw23_e6767afcb6` | 224 B entry point: guards on a byte selector (`>0xd` → 0x69; `sel==0` → 0; mask `0x3540` allows only {6,8,10,12,13}), then `cr_desc_get_ptr2(&chain, sel)` and, on success, `cr_bitmap_centroid`, `cr_chain_classify_i16` and a `(short)(p*1000.0)` store at ctx+0x7e. For `sel ∈ {12,13}` the vendor's `cr_desc_get_ptr2` hands back real chain descriptors (`&DAT_180122980` / `DAT_1801598e0`) that the clean-room returns as NULL, so this path dereferences a null pointer — deferred until the chain tables are reconstructed. |
| `0x180026a70` | `fpc_bio_bep_sw23_63b79ffea2` | 192 B wrapper: `cr_desc_get_ptr1(&p, 4)` (always sel 4 → the static trained-model chain `DAT_180159ea0`), then `cr_centroid_affine` and `cr_stage_run_273a0` over that chain, storing `(short)(100.0f * result)`. The chain's convolution-kernel tables are part of the trained model, so the clean-room (which returns NULL for sel 4) cannot dereference it — deferred until the chain tables are reconstructed. |

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
