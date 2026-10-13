# Reachable BEP tree — inventory

Functions reachable from `FpcBioEnrolAdd` (the enrol-add entry that produces
the reconstructed ridge image), computed by parsing the Ghidra decompilation
of `fpc_enclave.dll` into a call graph (`fpwork/callgraph.py`).

| metric | value |
|---|---|
| root | `0x1800013d0` `FpcBioEnrolAdd` |
| reachable functions | 355 |
| total `.text` size | 169488 bytes (165.5 KiB) |
| leaf functions (no in-tree callees) | 118 |
| max call depth from root | 11 |
| **rewritten + parity-verified** | **59** (16.6% of funcs, 6832 B = 4.03% of bytes) |

> The embedded symbol names are adversarial and must not be trusted: the
> function named `FpcSin` is `sqrtf`, `FpcCos` is `expf`, `FpcMalloc` is
> `roundf`, `FpcExp` is `floorf`, `FpcFloor` is a free-wrapper and `FpcFree`
> is a malloc-wrapper. Semantics are established from the body/disassembly.

## Rewrite status

| # | clean-room name | vendor RVA | vendor symbol | size | status |
|---|---|---|---|---|---|
| 1 | `cr_fill` | `0x180011000` | `fpc_bio_bep_sw23_110d16790e` | 32 | **done** |
| 2 | `cr_status_from_ctx` | `0x1800216d0` | `fpc_bio_bep_sw23_4d4be3ba3b` | 32 | **done** |
| 3 | `cr_meta_get_u32` | `0x18004b4e0` | `fpc_metadata_get_uint16` | 112 | **done** |
| 4 | `cr_image_set` | `0x18003b250` | `fpc_bio_bep_sw23_b9f68de6cb` | 64 | **done** |
| 5 | `cr_image_slot_empty` | `0x18004a250` | `fpc_image_create` | 64 | **done** |
| 6 | `cr_image_slot_defined` | `0x18004aa70` | `fpc_image_data_get_size_from_defs` | 32 | **done** |
| 7 | `cr_buf_is_debug_class` | `0x1800490f0` | `fpc_buffer_is_debug` | 48 | **done** |
| 8 | `cr_meta_put_u32` | `0x18004b670` | `fpc_metadata_put_uint16` | 144 | **done** |
| 9 | `cr_buf_is_metadata_class` | `0x180049120` | `fpc_buffer_is_meta` | 32 | **done** |
| 10 | `cr_buf_is_pixels` | `0x1800490d0` | `fpc_buffer_get_pixels_buffer` | 16 | **done** |
| 11 | `cr_status_from_flag` | `0x180016720` | `fpc_bio_bep_sw23_1dbe7da717` | 16 | **done** |
| 12 | `cr_image_set (dup of 3b250)` | `0x18003fbc0` | `fpc_bio_bep_sw23_d5d1681a28` | 64 | **done** |
| 13 | `cr_image_subview` | `0x180010ef0` | `fpc_bio_bep_sw23_0fdf5f04f4` | 64 | **done** |
| 14 | `cr_image_subview (dup of 10ef0)` | `0x180017a80` | `fpc_bio_bep_sw23_265153bede` | 64 | **done** |
| 15 | `cr_bitmask_range` | `0x18003c540` | `fpc_bio_bep_sw23_c31521ad32` | 64 | **done** |
| 16 | `cr_copy` | `0x180040de0` | `fpc_bio_bep_sw23_db3e766540` | 64 | **done** |
| 17 | `cr_image_fill_const2` | `0x180023a60` | `fpc_bio_bep_sw23_53297280e7` | 48 | **done** |
| 18 | `cr_image_mark_indices` | `0x1800305b0` | `fpc_bio_bep_sw23_900aab35d7` | 64 | **done** |
| 19 | `cr_image_threshold_mark` | `0x180033ae0` | `fpc_bio_bep_sw23_9c60738574` | 64 | **done** |
| 20 | `cr_sqrtf` | `0x180003080` | `FpcSin` | 144 | **done** |
| 21 | `cr_roundf_to_int` | `0x180003020` | `FpcMalloc` | 48 | **done** |
| 22 | `cr_bitmap_get` | `0x180027380` | `fpc_bio_bep_sw23_688cc93710` | 32 | **done** |
| 23 | `cr_expf` | `0x180002dd0` | `FpcCos` | 416 | **done** |
| 24 | `cr_floorf_to_int` | `0x180002f70` | `FpcExp` | 64 | **done** |
| 25 | `cr_modff` | `0x180040e20` | `fpc_bio_bep_sw23_db476a7e1b` | 32 | **done** |
| 26 | `cr_ldexpf` | `0x1800413a0` | `fpc_bio_bep_sw23_dc5cdd7edc` | 64 | **done** |
| 27 | `cr_lroundf` | `0x180002d60` | `FpcBioTemplateSave` | 64 | **done** |
| 28 | `cr_s16_clamp_nonneg` | `0x180012060` | `fpc_bio_bep_sw23_14aab7a29c` | 64 | **done** |
| 29 | `cr_prng_range` | `0x18002fd00` | `fpc_bio_bep_sw23_8bbb505c96` | 64 | **done** |
| 30 | `cr_clz` | `0x1800393b0` | `fpc_bio_bep_sw23_b54df0b0f5` | 64 | **done** |
| 31 | `cr_sincos` | `0x18001b990` | `fpc_bio_bep_sw23_3123fca792` | 80 | **done** |
| 32 | `cr_dot_f32` | `0x18003b800` | `fpc_bio_bep_sw23_bbdc68c33d` | 80 | **done** |
| 33 | `cr_image_mark_nonpos` | `0x1800182b0` | `fpc_bio_bep_sw23_27c8bbdf12` | 80 | **done** |
| 34 | `cr_image_set_pitch` | `0x180034490` | `fpc_bio_bep_sw23_a0bbe17d94` | 80 | **done** |
| 35 | `cr_image_set (dup of 3b250)` | `0x180036460` | `fpc_bio_bep_sw23_a8929aa58a` | 64 | **done** |
| 36 | `cr_rect_fill_u8` | `0x1800465a0` | `fpc_bio_bep_sw23_f2c350625f.part.1` | 112 | **done** |
| 37 | `cr_rect_fill_u16` | `0x18001d700` | `fpc_bio_bep_sw23_38215f32ef` | 128 | **done** |
| 38 | `cr_rect_fill_f32` | `0x18001edb0` | `fpc_bio_bep_sw23_3d13ea8103` | 128 | **done** |
| 39 | `cr_bitmap_clear_rect` | `0x180037fb0` | `fpc_bio_bep_sw23_af53e5058d` | 112 | **done** |
| 40 | `cr_bitmap_set_from_image` | `0x180023bb0` | `fpc_bio_bep_sw23_5637713915` | 128 | **done** |
| 41 | `cr_bitmap_unpack` | `0x180041cc0` | `fpc_bio_bep_sw23_e285f0085a` | 128 | **done** |
| 42 | `cr_classify_mark` | `0x180041bb0` | `fpc_bio_bep_sw23_e218884414` | 112 | **done** |
| 43 | `cr_copy_or_relu` | `0x180030270` | `fpc_bio_bep_sw23_8ca6f25abc` | 128 | **done** |
| 44 | `cr_array_rotate` | `0x18001d7b0` | `fpc_bio_bep_sw23_38df1c2726` | 112 | **done** |
| 45 | `cr_type_desc_getter` | `0x18003d8f0` | `fpc_bio_bep_sw23_c9c1caf0a0.constprop.2` | 112 | **done** |
| 46 | `cr_buffer_pixels_setup` | `0x1800491e0` | `fpc_buffer_pixels_check_size` | 144 | **done** |
| 47 | `cr_image_copy_u8` | `0x1800308d0` | `fpc_bio_bep_sw23_901c599831.isra.1` | 208 | **done** |
| 48 | `cr_image_copy_u32` | `0x18000f600` | `fpc_bio_bep_sw23_06c5524131` | 208 | **done** |
| 49 | `cr_image_copy_u16_shl` | `0x18002ade0` | `fpc_bio_bep_sw23_768fe83277` | 208 | **done** |
| 50 | `cr_masked_variance` | `0x180037e70` | `fpc_bio_bep_sw23_aed252bf13` | 160 | **done** |
| 51 | `cr_read_quad` | `0x1800469e0` | `fpc_bio_bep_sw23_f3d41f1091` | 160 | **done** |
| 52 | `cr_affine_transform` | `0x180014b30` | `fpc_bio_bep_sw23_1cbe178998` | 160 | **done** |
| 53 | `cr_vfir4_u8` | `0x18000fb20` | `fpc_bio_bep_sw23_097e23479a` | 256 | **done** |
| 54 | `cr_masked_minmax` | `0x180020130` | `fpc_bio_bep_sw23_45d26c97de` | 256 | **done** |
| 55 | `cr_orient_pick` | `0x1800309a0` | `fpc_bio_bep_sw23_90875da224` | 256 | **done** |
| 56 | `cr_atan2_deg` | `0x1800391b0` | `fpc_bio_bep_sw23_b4118e23cd` | 256 | **done** |
| 57 | `cr_matmul_nt` | `0x18003e9f0` | `fpc_bio_bep_sw23_cbfed5bc7c` | 272 | **done** |
| 58 | `cr_mean_stddev` | `0x18003f460` | `fpc_bio_bep_sw23_d1adcab3af` | 272 | **done** |
| 59 | `cr_masked_minmax_s16` | `0x1800277e0` | `fpc_bio_bep_sw23_69f82fab13` | 272 | **done** |
| … | 296 more | | | | pending |

## Rewrite frontier — 118 leaf functions

Leaves have no in-tree callees, so each can be rewritten and differentially
tested in isolation. Sorted by size (smallest first).

| RVA | vendor symbol | size | in-tree callers | status |
|---|---|---|---|---|
| `0x180016720` | `fpc_bio_bep_sw23_1dbe7da717` | 16 | 1 | **done** |
| `0x1800490d0` | `fpc_buffer_get_pixels_buffer` | 16 | 1 | **done** |
| `0x180011000` | `fpc_bio_bep_sw23_110d16790e` | 32 | 12 | **done** |
| `0x1800216d0` | `fpc_bio_bep_sw23_4d4be3ba3b` | 32 | 1 | **done** |
| `0x180027380` | `fpc_bio_bep_sw23_688cc93710` | 32 | 1 | **done** |
| `0x18002aeb0` | `fpc_bio_bep_sw23_769acc1eef` | 32 | 1 |  |
| `0x180040e20` | `fpc_bio_bep_sw23_db476a7e1b` | 32 | 1 | **done** |
| `0x180048d40` | `fpc_bio_init` | 32 | 1 |  |
| `0x180049120` | `fpc_buffer_is_meta` | 32 | 2 | **done** |
| `0x18004aa70` | `fpc_image_data_get_size_from_defs` | 32 | 2 | **done** |
| `0x180002fb0` | `FpcFloor` | 48 | 1 |  |
| `0x180003020` | `FpcMalloc` | 48 | 5 | **done** |
| `0x180023a60` | `fpc_bio_bep_sw23_53297280e7` | 48 | 1 | **done** |
| `0x1800490f0` | `fpc_buffer_is_debug` | 48 | 1 | **done** |
| `0x180002d60` | `FpcBioTemplateSave` | 64 | 5 |  **done** |
| `0x180002f70` | `FpcExp` | 64 | 1 | **done** |
| `0x180002fe0` | `FpcFree` | 64 | 1 |  |
| `0x180010ef0` | `fpc_bio_bep_sw23_0fdf5f04f4` | 64 | 5 | **done** |
| `0x180012060` | `fpc_bio_bep_sw23_14aab7a29c` | 64 | 7 |  **done** |
| `0x180012f30` | `fpc_bio_bep_sw23_16c9802c18` | 64 | 1 |  |
| `0x180017a80` | `fpc_bio_bep_sw23_265153bede` | 64 | 1 | **done** |
| `0x180020860` | `fpc_bio_bep_sw23_46f04b866a` | 64 | 1 |  |
| `0x18002dab0` | `fpc_bio_bep_sw23_81499c2105` | 64 | 1 |  |
| `0x18002fd00` | `fpc_bio_bep_sw23_8bbb505c96` | 64 | 1 |  **done** |
| `0x1800305b0` | `fpc_bio_bep_sw23_900aab35d7` | 64 | 1 | **done** |
| `0x180033ae0` | `fpc_bio_bep_sw23_9c60738574` | 64 | 1 | **done** |
| `0x180036460` | `fpc_bio_bep_sw23_a8929aa58a` | 64 | 2 |  **done** |
| `0x1800393b0` | `fpc_bio_bep_sw23_b54df0b0f5` | 64 | 5 |  **done** |
| `0x18003b250` | `fpc_bio_bep_sw23_b9f68de6cb` | 64 | 6 | **done** |
| `0x18003c540` | `fpc_bio_bep_sw23_c31521ad32` | 64 | 1 | **done** |
| `0x18003fbc0` | `fpc_bio_bep_sw23_d5d1681a28` | 64 | 11 | **done** |
| `0x180040de0` | `fpc_bio_bep_sw23_db3e766540` | 64 | 2 | **done** |
| `0x1800413a0` | `fpc_bio_bep_sw23_dc5cdd7edc` | 64 | 3 |  **done** |
| `0x1800448f0` | `fpc_bio_bep_sw23_eb7a7b573f` | 64 | 1 |  |
| `0x18004a250` | `fpc_image_create` | 64 | 1 | **done** |
| `0x1800182b0` | `fpc_bio_bep_sw23_27c8bbdf12` | 80 | 1 |  **done** |
| `0x180018e50` | `fpc_bio_bep_sw23_2db989eca6` | 80 | 1 |  |
| `0x18001b990` | `fpc_bio_bep_sw23_3123fca792` | 80 | 2 |  **done** |
| `0x180034490` | `fpc_bio_bep_sw23_a0bbe17d94` | 80 | 1 |  **done** |
| `0x18003b800` | `fpc_bio_bep_sw23_bbdc68c33d` | 80 | 1 |  **done** |
| `0x180017960` | `fpc_bio_bep_sw23_25c6d755fa` | 96 | 1 |  |
| `0x1800356e0` | `fpc_bio_bep_sw23_a45214d052.part.7` | 96 | 1 |  |
| `0x18001d7b0` | `fpc_bio_bep_sw23_38df1c2726` | 112 | 1 |  **done** |
| `0x180028de0` | `fpc_bio_bep_sw23_702329d57c` | 112 | 1 |  |
| `0x18002d4e0` | `fpc_bio_bep_sw23_7c99980763` | 112 | 1 |  |
| `0x180037fb0` | `fpc_bio_bep_sw23_af53e5058d` | 112 | 2 |  **done** |
| `0x18003d8f0` | `fpc_bio_bep_sw23_c9c1caf0a0.constprop.2` | 112 | 1 |  **done** |
| `0x180041bb0` | `fpc_bio_bep_sw23_e218884414` | 112 | 1 |  **done** |
| `0x1800465a0` | `fpc_bio_bep_sw23_f2c350625f.part.1` | 112 | 4 |  **done** |
| `0x18004b4e0` | `fpc_metadata_get_uint16` | 112 | 3 | **done** |
| `0x18001d700` | `fpc_bio_bep_sw23_38215f32ef` | 128 | 1 |  **done** |
| `0x18001edb0` | `fpc_bio_bep_sw23_3d13ea8103` | 128 | 3 |  **done** |
| `0x180023bb0` | `fpc_bio_bep_sw23_5637713915` | 128 | 2 |  **done** |
| `0x180030270` | `fpc_bio_bep_sw23_8ca6f25abc` | 128 | 3 |  **done** |
| `0x180041cc0` | `fpc_bio_bep_sw23_e285f0085a` | 128 | 1 |  **done** |
| `0x180003080` | `FpcSin` | 144 | 7 | **done** |
| `0x180030340` | `fpc_bio_bep_sw23_8d79fe3601` | 144 | 1 | deferred (returns static table pointers) |
| `0x1800491e0` | `fpc_buffer_pixels_check_size` | 144 | 1 | **done** |
| `0x18004b670` | `fpc_metadata_put_uint16` | 144 | 1 | **done** |
| `0x180014b30` | `fpc_bio_bep_sw23_1cbe178998` | 160 | 1 | **done** |
| `0x180037e70` | `fpc_bio_bep_sw23_aed252bf13` | 160 | 1 | **done** |
| `0x1800469e0` | `fpc_bio_bep_sw23_f3d41f1091` | 160 | 1 | **done** |
| `0x18000f600` | `fpc_bio_bep_sw23_06c5524131` | 208 | 1 | **done** |
| `0x18002ade0` | `fpc_bio_bep_sw23_768fe83277` | 208 | 1 | **done** |
| `0x1800308d0` | `fpc_bio_bep_sw23_901c599831.isra.1` | 208 | 4 | **done** |
| `0x18000fb20` | `fpc_bio_bep_sw23_097e23479a` | 256 | 1 | **done** |
| `0x180020130` | `fpc_bio_bep_sw23_45d26c97de` | 256 | 2 | **done** |
| `0x1800309a0` | `fpc_bio_bep_sw23_90875da224` | 256 | 1 | **done** |
| `0x1800391b0` | `fpc_bio_bep_sw23_b4118e23cd` | 256 | 1 | **done** |
| `0x1800277e0` | `fpc_bio_bep_sw23_69f82fab13` | 272 | 2 | **done** |
| `0x18003e9f0` | `fpc_bio_bep_sw23_cbfed5bc7c` | 272 | 1 | **done** |
| `0x18003f460` | `fpc_bio_bep_sw23_d1adcab3af` | 272 | 1 | **done** |
| `0x180017840` | `fpc_bio_bep_sw23_253a6224d6` | 288 | 2 |  |
| `0x1800334c0` | `fpc_bio_bep_sw23_9a9c3581cf` | 288 | 3 |  |
| `0x18001f790` | `fpc_bio_bep_sw23_4172e0ed57` | 304 | 2 |  |
| `0x18002cc00` | `fpc_bio_bep_sw23_7b12c18a30` | 304 | 1 |  |
| `0x180037330` | `fpc_bio_bep_sw23_ab8df24280` | 304 | 3 |  |
| `0x18000f9d0` | `fpc_bio_bep_sw23_08800726c8` | 320 | 4 |  |
| `0x180019490` | `fpc_bio_bep_sw23_30229e9ac0` | 320 | 2 |  |
| `0x180034190` | `fpc_bio_bep_sw23_9e452a5621.isra.7.constprop.13` | 320 | 2 |  |
| `0x180026fb0` | `fpc_bio_bep_sw23_66bb0714da` | 336 | 1 |  |
| `0x18000eca0` | `fpc_bio_bep_sw23_045ad05bbf` | 384 | 2 |  |
| `0x18001c4e0` | `fpc_bio_bep_sw23_3281879ff9` | 384 | 1 |  |
| `0x18000ee70` | `fpc_bio_bep_sw23_04faa0a17d.part.1` | 400 | 1 |  |
| `0x18001fb80` | `fpc_bio_bep_sw23_442776bb33` | 400 | 1 |  |
| `0x180002dd0` | `FpcCos` | 416 | 5 | **done** |
| `0x180016df0` | `fpc_bio_bep_sw23_214aef3596` | 416 | 2 |  |
| `0x180024cb0` | `fpc_bio_bep_sw23_5f21879897` | 432 | 3 |  |
| `0x18000d040` | `fpc_bep_template_serialize` | 464 | 1 |  |
| `0x1800220e0` | `fpc_bio_bep_sw23_5029eb7cfe` | 464 | 3 |  |
| `0x18002ca30` | `fpc_bio_bep_sw23_79a4530e21.part.4` | 464 | 1 |  |
| `0x180044b10` | `fpc_bio_bep_sw23_ed385570f8` | 464 | 1 |  |
| `0x1800169b0` | `fpc_bio_bep_sw23_1fe4634733` | 480 | 1 |  |
| `0x180017ac0` | `fpc_bio_bep_sw23_267120cd30` | 480 | 1 |  |
| `0x180024200` | `fpc_bio_bep_sw23_598b2d29a0` | 496 | 1 |  |
| `0x18000fd90` | `fpc_bio_bep_sw23_0a86d32299` | 528 | 2 |  |
| `0x180020d80` | `fpc_bio_bep_sw23_49a7dfde4e` | 528 | 1 |  |
| `0x18003e590` | `fpc_bio_bep_sw23_cb8639ce35` | 528 | 3 |  |
| `0x180043db0` | `fpc_bio_bep_sw23_e809dd007c` | 560 | 1 |  |
| `0x18000d8e0` | `fpc_bio_bep_sw23_02a79f65fe` | 576 | 1 |  |
| `0x18001c280` | `fpc_bio_bep_sw23_326e82e939` | 608 | 1 |  |
| `0x18002f070` | `fpc_bio_bep_sw23_861d4887f0` | 624 | 3 |  |
| `0x18001aaa0` | `fpc_bio_bep_sw23_311b05823c` | 656 | 1 |  |
| `0x180028930` | `fpc_bio_bep_sw23_6f845fb02c` | 656 | 1 |  |
| `0x18002ddd0` | `fpc_bio_bep_sw23_82f9a9e315.part.9` | 656 | 2 |  |
| `0x180032830` | `fpc_bio_bep_sw23_97ae28484f` | 704 | 1 |  |
| `0x18003ecc0` | `fpc_bio_bep_sw23_cd9632fb7f` | 752 | 3 |  |
| `0x1800337e0` | `fpc_bio_bep_sw23_9bbd6b7a97` | 768 | 1 |  |
| `0x180043a50` | `fpc_bio_bep_sw23_e789d2446e` | 832 | 1 |  |
| `0x180030fc0` | `fpc_bio_bep_sw23_91ea5ea28d.isra.6` | 928 | 5 |  |
| `0x180040560` | `fpc_bio_bep_sw23_d8d4223a88` | 976 | 5 |  |
| `0x180033b40` | `fpc_bio_bep_sw23_9d0de274f8` | 1024 | 2 |  |
| `0x18002c600` | `fpc_bio_bep_sw23_79a4530e21` | 1072 | 1 |  |
| `0x18003bf90` | `fpc_bio_bep_sw23_beb4df26c0` | 1152 | 2 |  |
| `0x180020230` | `fpc_bio_bep_sw23_45dc1beabd` | 1184 | 1 |  |
| `0x1800433b0` | `fpc_bio_bep_sw23_e6dfc8ce14` | 1200 | 2 |  |
| `0x18002e6a0` | `fpc_bio_bep_sw23_85057ad42a` | 1280 | 1 |  |
| `0x180038ac0` | `fpc_bio_bep_sw23_b3a74c54eb` | 1776 | 1 |  |
