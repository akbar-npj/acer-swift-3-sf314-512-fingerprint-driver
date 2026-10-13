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
| **rewritten + parity-verified** | **206** (58.0% of funcs, 52480 B = 30.87% of bytes) |

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
| 60 | `cr_masked_minmax_f32` | `0x180017840` | `fpc_bio_bep_sw23_253a6224d6` | 288 | **done** |
| 61 | `cr_i16_to_f32_scaled` | `0x1800334c0` | `fpc_bio_bep_sw23_9a9c3581cf` | 288 | **done** |
| 62 | `cr_bilinear_sample_u8` | `0x18001f790` | `fpc_bio_bep_sw23_4172e0ed57` | 304 | **done** |
| 63 | `cr_box_blur_h_f32` | `0x18002cc00` | `fpc_bio_bep_sw23_7b12c18a30` | 304 | **done** |
| 64 | `cr_masked_box_sum` | `0x180037330` | `fpc_bio_bep_sw23_ab8df24280` | 304 | **done** |
| 65 | `cr_f32_to_i16_scaled` | `0x18000f9d0` | `fpc_bio_bep_sw23_08800726c8` | 320 | **done** |
| 66 | `cr_block_extreme_bitmap` | `0x180019490` | `fpc_bio_bep_sw23_30229e9ac0` | 320 | **done** |
| 67 | `cr_bitmap_popcount` | `0x180034190` | `fpc_bio_bep_sw23_9e452a5621.isra.7.constprop.13` | 320 | **done** |
| 68 | `cr_downsample_mean` | `0x180026fb0` | `fpc_bio_bep_sw23_66bb0714da` | 336 | **done** |
| 69 | `cr_sincos_f32` | `0x18000eca0` | `fpc_bio_bep_sw23_*` (sin/cos pair) | 384 | **done** |
| 70 | `cr_image_fill_border` | `0x18001c4e0` | `fpc_bio_bep_sw23_3281879ff9` | 384 | **done** |
| 71 | `cr_image_border_extend` | `0x18001fb80` | `fpc_bio_bep_sw23_442776bb33` | 400 | **done** |
| 72 | `cr_saturation_score` | `0x1800356e0` | `fpc_bio_bep_sw23_a45214d052.part.7` | 96 | **done** |
| 73 | `cr_image_border_extend_s16` | `0x180016df0` | `fpc_bio_bep_sw23_214aef3596` | 416 | **done** |
| 74 | `cr_malloc` | `0x180002fe0` | `FpcFree` (malloc wrapper) | 64 | **done** |
| 75 | `cr_free` | `0x180002fb0` | `FpcFloor` (free wrapper) | 48 | **done** |
| 76 | `cr_sized_free` | `0x18003bf40` | `fpc_bio_bep_sw23_bdbfe0d964` | 80 | **done** |
| 77 | `cr_bitmap_dilate` | `0x180024cb0` | `fpc_bio_bep_sw23_5f21879897` | 432 | **done** |
| 78 | `cr_bitmap_erode` | `0x1800220e0` | `fpc_bio_bep_sw23_5029eb7cfe` | 464 | **done** |
| 79 | `cr_polyphase_fir4` | `0x18000ee70` | `fpc_bio_bep_sw23_04faa0a17d.part.1` | 400 | **done** |
| 80 | `cr_affine_sample_u8` | `0x18002ca30` | `fpc_bio_bep_sw23_79a4530e21.part.4` | 464 | **done** |
| 81 | `cr_splat_bilinear` | `0x180044b10` | `fpc_bio_bep_sw23_ed385570f8` | 464 | **done** |
| 82 | `cr_bitmap_border_set` | `0x180017ac0` | `fpc_bio_bep_sw23_267120cd30` | 480 | **done** |
| 83 | `cr_laplacian_3x3` | `0x1800169b0` | `fpc_bio_bep_sw23_1fe4634733` | 480 | **done** |
| 84 | `cr_fir7_s16` | `0x180020d80` | `fpc_bio_bep_sw23_49a7dfde4e` | 528 | **done** |
| 85 | `cr_permute_rows` | `0x180024200` | `fpc_bio_bep_sw23_598b2d29a0` | 496 | **done** |
| 86 | `cr_bitmap_copy_shift` | `0x18000fd90` | `fpc_bio_bep_sw23_0a86d32299` | 528 | **done** |
| 87 | `cr_bitmap_extract_shift` | `0x18003e590` | `fpc_bio_bep_sw23_cb8639ce35` | 528 | **done** |
| 88 | `cr_fir7_s16_col` | `0x18001c280` | `fpc_bio_bep_sw23_326e82e939` | 608 | **done** |
| 89 | `cr_bitmap_mean_correct` | `0x18000d8e0` | `fpc_bio_bep_sw23_02a79f65fe` | 576 | **done** |
| 90 | `cr_signpack_dot` | `0x180043db0` | `fpc_bio_bep_sw23_e809dd007c` | 560 | **done** |
| 91 | `cr_u8_to_u16_shifted` | `0x1800337e0` | `fpc_bio_bep_sw23_9bbd6b7a97` | 768 | **done** |
| 92 | `cr_mirror_extend_s16` | `0x180028930` | `fpc_bio_bep_sw23_6f845fb02c` | 656 | **done** |
| 93 | `cr_box_sum_excl` | `0x18000d040` | `fpc_bep_template_serialize` | 464 | **done** |
| 94 | `cr_boxsum15_s16` | `0x180032830` | `fpc_bio_bep_sw23_97ae28484f` | 704 | **done** |
| 95 | `cr_boxsum15_u8` | `0x18001aaa0` | `fpc_bio_bep_sw23_311b05823c` | 656 | **done** |
| 96 | `cr_u8_expand_convolve` | `0x18003ecc0` | `fpc_bio_bep_sw23_cd9632fb7f` | 752 | **done** |
| 97 | `cr_grid_insert` | `0x18002f070` | `fpc_bio_bep_sw23_861d4887f0` | 624 | **done** |
| 98 | `cr_bitmap_centroid` | `0x18002ddd0` | `fpc_bio_bep_sw23_82f9a9e315.part.9` | 656 | **done** |
| 99–106 | `cr_desc_get_*` (9 getters) | various | various | 688 | **done** |
| 107 | `cr_tri9_filter` | `0x180043a50` | `fpc_bio_bep_sw23_e789d2446e` | 832 | **done** |
| 108 | `cr_fir_reflect` | `0x180030fc0` | `fpc_bio_bep_sw23_91ea5ea28d.isra.6` | 928 | **done** |
| 109 | `cr_fir_reflect_rows` | `0x180040560` | `fpc_bio_bep_sw23_d8d4223a88` | 976 | **done** |
| 110 | `cr_fir7_reflect` | `0x180033b40` | `fpc_bio_bep_sw23_9d0de274f8` | 1024 | **done** |
| 111 | `cr_box_mean_f32` | `0x18002c600` | `fpc_bio_bep_sw23_79a4530e21` | 1072 | **done** |
| 112 | `cr_sort_records` | `0x18003bf90` | `fpc_bio_bep_sw23_beb4df26c0` | 1152 | **done** |
| 113 | `cr_line_orient_fit` | `0x180020230` | `fpc_bio_bep_sw23_45dc1beabd` | 1184 | **done** |
| 114 | `cr_vfir7_cols` | `0x1800433b0` | `fpc_bio_bep_sw23_e6dfc8ce14` | 1200 | **done** |
| 115 | `cr_sep11_row` | `0x18002e6a0` | `fpc_bio_bep_sw23_85057ad42a` | 1280 | **done** |
| 116 | `cr_corr_kbank` | `0x180038ac0` | `fpc_bio_bep_sw23_b3a74c54eb` | 1776 | **done** |
| 117 | `cr_meta_put_i16` | `0x18004b640` | `fpc_metadata_put_int16` | 16 | **done** |
| 118 | `cr_cleanup_ptr8_a` | `0x18000fc20` | `fpc_bio_bep_sw23_098428d710` | 32 | **done** |
| 119 | `cr_cleanup_ptr8_b` | `0x180011a50` | `fpc_bio_bep_sw23_1459ce6d3f` | 32 | **done** |
| 120 | `cr_cleanup_ptr8_clear` | `0x180024760` | `fpc_bio_bep_sw23_5bc22e072c` | 64 | **done** |
| 121 | `cr_obj_zero_free` | `0x18001f9f0` | `fpc_bio_bep_sw23_42d43aea34` | 48 | **done** |
| 122 | `cr_free_ptr_struct` | `0x180017170` | `fpc_bio_bep_sw23_2223670971.isra.3` | 96 | **done** |
| 123 | `cr_malloc_aligned16` | `0x1800100c0` | `fpc_bio_bep_sw23_0bcc9b4ae6` | 80 | **done** |
| 124 | `cr_image_get_dp` | `0x18004a890` | `fpc_image_data_get_dp_buffer` | 64 | **done** |
| 125 | `cr_image_buf_desc` | `0x18004ab90` | `fpc_image_data_init_buffers` | 112 | **done** |
| 126 | `cr_free_obj_28_8` | `0x18000ee40` | `fpc_bio_bep_sw23_04faa0a17d` | 48 | **done** |
| 127 | `cr_meta_set_slot` | `0x1800303d0` | `fpc_bio_bep_sw23_8dbe34c690` | 64 | **done** |
| 128 | `cr_obj_init_58` | `0x180046b80` | `fpc_bio_bep_sw23_f56cb91e79` | 64 | **done** |
| 129 | `cr_alloc_handle` | `0x18002ad90` | `fpc_bio_bep_sw23_76795f570e` | 80 | **done** |
| 130 | `cr_alloc_400` | `0x18003fb70` | `fpc_bio_bep_sw23_d52eeb3bb9` | 80 | **done** |
| 131 | `cr_image_alloc_u8` | `0x18001d820` | `fpc_bio_bep_sw23_3943c5f8d0.constprop.8` | 112 | **done** |
| 132 | `cr_image_alloc_s16` | `0x18003d790` | `fpc_bio_bep_sw23_c8dcdadf31` | 128 | **done** |
| 133 | `cr_free_obj_flags` | `0x18000f570` | `fpc_bio_bep_sw23_05db73508b` | 144 | **done** |
| 134 | `cr_bitmap_alloc` | `0x180029750` | `fpc_bio_bep_sw23_7346394a98` | 224 | **done** |
| 135 | `cr_clz_or32` | `0x180039390` | `fpc_bio_bep_sw23_b4a9504f57` | 32 | **done** |
| 136 | `cr_free_8slot` | `0x18003d430` | `fpc_bio_bep_sw23_c7c4fecba2` | 96 | **done** |
| 137 | `cr_alloc_obj_58` | `0x180035740` | `fpc_bio_bep_sw23_a457bca0e1` | 96 | **done** |
| 138 | `cr_meta_get_slot` | `0x18003a8d0` | `fpc_bio_bep_sw23_b664476fb3` | 64 | **done** |
| 139 | `cr_subview_extend_s16` | `0x1800342d0` | `fpc_bio_bep_sw23_9eab7bca41` | 160 | **done** |
| 140 | `cr_subview_extend_u8` | `0x180037f10` | `fpc_bio_bep_sw23_aefaa44d78.isra.1` | 160 | **done** |
| 141 | `cr_free_8slot_wrap` | `0x18003fcd0` | `fpc_bio_bep_sw23_d6892b18e4` | 64 | **done** |
| 142 | `cr_obj_destroy` | `0x18001c680` | `fpc_bio_bep_sw23_32f906bc87` | 32 | **done** |
| 143 | `cr_wrap_destroy` | `0x180044ce0` | `fpc_bio_bep_sw23_ee965c1257.constprop.2` | 48 | **done** |
| 144 | `cr_wrap_destroy2` | `0x180043a10` | `fpc_bio_bep_sw23_e76dc431bf` | 64 | **done** |
| 145 | `cr_sized_free_if` | `0x180038720` | `fpc_bio_bep_sw23_b08a6243f0` | 32 | **done** |
| 146 | `cr_free_pair8` | `0x18001f640` | `fpc_bio_bep_sw23_406a45a1c8.isra.0.part.1` | 32 | **done** |
| 147 | `cr_free_slot8` | `0x180033f40` | `fpc_bio_bep_sw23_9d5b96a246` | 32 | **done** |
| 148 | `cr_cleanup_ptr8_guard` | `0x1800276a0` | `fpc_bio_bep_sw23_68cec20a19` | 32 | **done** |
| 149 | `cr_free_4slot` | `0x1800464b0` | `fpc_bio_bep_sw23_f2ad1c4415` | 48 | **done** |
| 150 | `cr_hi_bit_index` | `0x1800384c0` | `fpc_bio_bep_sw23_afa5254b16.part.5` | 48 | **done** |
| 151 | `cr_image_get_meta_dp` | `0x18004a910` | `fpc_image_data_get_payload_size_from_defs` | 64 | **done** |
| 152 | `cr_cleanup_ptr8_clear_b` | `0x18003b920` | `fpc_bio_bep_sw23_bc5ecf1262` | 64 | **done** |
| 153 | `cr_free_4args` | `0x18000fd40` | `fpc_bio_bep_sw23_0a647d6e5c` | 80 | **done** |
| 154 | `cr_free_4slot_guard` | `0x180046490` | `fpc_bio_bep_sw23_f24e438404.part.2` | 32 | **done** |
| 155 | `cr_clear_6ptr` | `0x180011890` | `fpc_bio_bep_sw23_126f4d9d64` | 80 | **done** |
| 156 | `cr_bit_alloc` | `0x18001f080` | `fpc_bio_bep_sw23_3dfa9d10cb` | 96 | **done** |
| 157 | `cr_image_alloc_f32` | `0x18001e8b0` | `fpc_bio_bep_sw23_3bec298cfe` | 112 | **done** |
| 158 | `cr_image_alloc_quarter` | `0x180026d00` | `fpc_bio_bep_sw23_64bb070921` | 80 | **done** |
| 159 | `cr_copy_image_fields` | `0x1800357a0` | `fpc_bio_bep_sw23_a549ff0d17` | 128 | **done** |
| 160 | `cr_sqrt_q16` | `0x180038a50` | `fpc_bio_bep_sw23_b21591478d` | 112 | **done** |
| 161 | `cr_u8_to_u16_guarded` | `0x180032530` | `fpc_bio_bep_sw23_967c7ea01c` | 80 | **done** |
| 162 | `cr_copy_u16_shl_guarded` | `0x180024e60` | `fpc_bio_bep_sw23_5f6c1365bf` | 96 | **done** |
| 163 | `cr_fir_reflect_guarded` | `0x1800280d0` | `fpc_bio_bep_sw23_6d0a2edcde` | 128 | **done** |
| 164 | `cr_fir_reflect_rows_guarded` | `0x18002d960` | `fpc_bio_bep_sw23_7fead33409` | 128 | **done** |
| 165 | `cr_palette_remap` | `0x180010e60` | `fpc_bio_bep_sw23_0fbb842e61.part.2` | 144 | **done** |
| 166 | `cr_shuffle_indices` | `0x18000d310` | `fpc_bio_bep_sw23_00445c6288` | 160 | **done** |
| 167 | `cr_softmax2` | `0x1800363b0` | `fpc_bio_bep_sw23_a87c7724d4` | 176 | **done** |
| 168 | `cr_centroid_affine` | `0x180038930` | `fpc_bio_bep_sw23_b19b9db308` | 240 | **done** |
| 169 | `cr_running_avg` | `0x180030ea0` | `fpc_bio_bep_sw23_91ac20e376` | 288 | **done** |
| 170 | `cr_atan2_fixed` | `0x180012260` | `fpc_bio_bep_sw23_15363dfc49` | 320 | **done** |
| 171 | `cr_box_mean_edge` | `0x1800335e0` | `fpc_bio_bep_sw23_9b7f284e32` | 368 | **done** |
| 172 | `cr_atan2_image_u8` | `0x18003ce10` | `fpc_bio_bep_sw23_c5b206e5b7` | 192 | **done** |
| 173 | `cr_gain_normalize_u8` | `0x180037ac0` | `fpc_bio_bep_sw23_ad2e23e159` | 464 | **done** |
| 174 | `cr_gain_normalize_s16` | `0x1800175b0` | `fpc_bio_bep_sw23_2464d11c20` | 512 | **done** |
| 175 | `cr_affine_sample_s16_nn` | `0x180044040` | `fpc_bio_bep_sw23_e8ff948c05.isra.1` | 496 | **done** |
| 176 | `cr_weighted_running_avg` | `0x180040ea0` | `fpc_bio_bep_sw23_dbf0b0038b` | 464 | **done** |
| 177 | `cr_pool_builder` | `0x18003b690` | `fpc_bio_bep_sw23_bb6f7bbe81` | 368 | **done** |
| 178 | `cr_affine_sample_u8_nn` | `0x180014110` | `fpc_bio_bep_sw23_1a1610649e` | 528 | **done** |
| 179 | `cr_pool_alloc1` | `0x180044230` | `fpc_bio_bep_sw23_e9b23176cd` | 64 | **done** |
| 180 | `cr_pool_alloc2` | `0x180047e30` | `fpc_bio_bep_sw23_fbdfd5dc28` | 96 | **done** |
| 181 | `cr_pool_alloc3` | `0x180010f40` | `fpc_bio_bep_sw23_10993dfb1a` | 112 | **done** |
| 182 | `cr_inpaint_masked_box` | `0x180041140` | `fpc_bio_bep_sw23_dc3eb5f865` | 608 | **done** |
| 183 | `cr_mirror_extend_fir` | `0x18001a510` | `fpc_bio_bep_sw23_30be67b43f` | 528 | **done** |
| 184 | `cr_pool_alloc4` | `0x18001b9e0` | `fpc_bio_bep_sw23_316605bf10` | 128 | **done** |
| 185 | `cr_pool_alloc5` | `0x18001d480` | `fpc_bio_bep_sw23_361a5cb939.part.1` | 144 | **done** |
| 186 | `cr_row_fir_i16` | `0x18002af00` | `fpc_bio_bep_sw23_76ff29ef93` | 512 | **done** |
| 187 | `cr_row_fir_i8` | `0x180010440` | `fpc_bio_bep_sw23_0dc5ae5cbd` | 672 | **done** |
| 188 | `cr_corr_coeff` | `0x18002eba0` | `fpc_bio_bep_sw23_85451455f9` | 624 | **done** |
| 189 | `cr_inpaint_index_list` | `0x18003af20` | `fpc_bio_bep_sw23_b9b6032650` | 496 | **done** |
| 190 | `cr_splat_accum16` | `0x180043120` | `fpc_bio_bep_sw23_e69abb2a5d` | 608 | **done** |
| 191 | `cr_free_4slot_clear1` | `0x18003f940` | `fpc_bio_bep_sw23_d45db0ac34` | 48 | **done** |
| 192 | `cr_free_3ptr_and8` | `0x1800140d0` | `fpc_bio_bep_sw23_19f77335db` | 64 | **done** |
| 193 | `cr_free_9slot_clear6` | `0x180012f70` | `fpc_bio_bep_sw23_172c5ff058` | 112 | **done** |
| 194 | `cr_alloc_60_init` | `0x180038820` | `fpc_bio_bep_sw23_b18007b597` | 144 | **done** |
| 195 | `cr_round_dims_pow2` | `0x180027730` | `fpc_bio_bep_sw23_69dd666845` | 176 | **done** |
| 196 | `cr_norm_corr_score` | `0x180046c40` | `fpc_bio_bep_sw23_f63d7ce299` | 256 | **done** |
| 197 | `cr_sep_fir_pair` | `0x180026b30` | `fpc_bio_bep_sw23_645d50eeb9` | 320 | **done** |
| 198 | `cr_row_fir_vfir` | `0x18003b110` | `fpc_bio_bep_sw23_b9f3573bad.isra.3` | 320 | **done** |
| 199 | `cr_masked_median_f32` | `0x18000e6f0` | `fpc_bio_bep_sw23_02e4655d23` | 336 | **done** |
| 200 | `cr_gaussian_window_q15` | `0x1800345f0` | `fpc_bio_bep_sw23_a1cbee6c60` | 336 | **done** |
| 201 | `cr_gaussian_deriv_windows_q15` | `0x180018a10` | `fpc_bio_bep_sw23_2bf628d2b6` | 400 | **done** |
| 202 | `cr_bilinear_angle_sample` | `0x18003e7a0` | `fpc_bio_bep_sw23_cbae7209ea` | 400 | **done** |
| 203 | `cr_gauss_blur7_pair` | `0x180034740` | `fpc_bio_bep_sw23_a237dc497c` | 112 | **done** |
| 204 | `cr_blit_mirror_s16` | `0x180024fa0` | `fpc_bio_bep_sw23_601bc7e441` | 144 | **done** |
| 205 | `cr_blit_extend_s16` | `0x180046a80` | `fpc_bio_bep_sw23_f439d0d904` | 144 | **done** |
| 206 | `cr_blit_fillborder_s16` | `0x18003cf00` | `fpc_bio_bep_sw23_c61d1d8196` | 160 | **done** |
| … | 149 more | | | | pending |

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
| `0x18002aeb0` | `fpc_bio_bep_sw23_769acc1eef` | 32 | 1 | **done** |
| `0x180040e20` | `fpc_bio_bep_sw23_db476a7e1b` | 32 | 1 | **done** |
| `0x180048d40` | `fpc_bio_init` | 32 | 1 |  |
| `0x180049120` | `fpc_buffer_is_meta` | 32 | 2 | **done** |
| `0x18004aa70` | `fpc_image_data_get_size_from_defs` | 32 | 2 | **done** |
| `0x180002fb0` | `FpcFloor` | 48 | 1 |  **done** |
| `0x180003020` | `FpcMalloc` | 48 | 5 | **done** |
| `0x180023a60` | `fpc_bio_bep_sw23_53297280e7` | 48 | 1 | **done** |
| `0x1800490f0` | `fpc_buffer_is_debug` | 48 | 1 | **done** |
| `0x180002d60` | `FpcBioTemplateSave` | 64 | 5 |  **done** |
| `0x180002f70` | `FpcExp` | 64 | 1 | **done** |
| `0x180002fe0` | `FpcFree` | 64 | 1 |  **done** |
| `0x180010ef0` | `fpc_bio_bep_sw23_0fdf5f04f4` | 64 | 5 | **done** |
| `0x180012060` | `fpc_bio_bep_sw23_14aab7a29c` | 64 | 7 |  **done** |
| `0x180012f30` | `fpc_bio_bep_sw23_16c9802c18` | 64 | 1 | **done** |
| `0x180017a80` | `fpc_bio_bep_sw23_265153bede` | 64 | 1 | **done** |
| `0x180020860` | `fpc_bio_bep_sw23_46f04b866a` | 64 | 1 | **done** |
| `0x18002dab0` | `fpc_bio_bep_sw23_81499c2105` | 64 | 1 | **done** |
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
| `0x1800448f0` | `fpc_bio_bep_sw23_eb7a7b573f` | 64 | 1 | **done** |
| `0x18004a250` | `fpc_image_create` | 64 | 1 | **done** |
| `0x1800182b0` | `fpc_bio_bep_sw23_27c8bbdf12` | 80 | 1 |  **done** |
| `0x180018e50` | `fpc_bio_bep_sw23_2db989eca6` | 80 | 1 | **done** |
| `0x18001b990` | `fpc_bio_bep_sw23_3123fca792` | 80 | 2 |  **done** |
| `0x180034490` | `fpc_bio_bep_sw23_a0bbe17d94` | 80 | 1 |  **done** |
| `0x18003b800` | `fpc_bio_bep_sw23_bbdc68c33d` | 80 | 1 |  **done** |
| `0x180017960` | `fpc_bio_bep_sw23_25c6d755fa` | 96 | 1 | **done** |
| `0x1800356e0` | `fpc_bio_bep_sw23_a45214d052.part.7` | 96 | 1 |  **done** |
| `0x18001d7b0` | `fpc_bio_bep_sw23_38df1c2726` | 112 | 1 |  **done** |
| `0x180028de0` | `fpc_bio_bep_sw23_702329d57c` | 112 | 1 | **done** |
| `0x18002d4e0` | `fpc_bio_bep_sw23_7c99980763` | 112 | 1 | **done** |
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
| `0x180017840` | `fpc_bio_bep_sw23_253a6224d6` | 288 | 2 | **done** |
| `0x1800334c0` | `fpc_bio_bep_sw23_9a9c3581cf` | 288 | 3 | **done** |
| `0x18001f790` | `fpc_bio_bep_sw23_4172e0ed57` | 304 | 2 | **done** |
| `0x18002cc00` | `fpc_bio_bep_sw23_7b12c18a30` | 304 | 1 | **done** |
| `0x180037330` | `fpc_bio_bep_sw23_ab8df24280` | 304 | 3 | **done** |
| `0x18000f9d0` | `fpc_bio_bep_sw23_08800726c8` | 320 | 4 | **done** |
| `0x180019490` | `fpc_bio_bep_sw23_30229e9ac0` | 320 | 2 | **done** |
| `0x180034190` | `fpc_bio_bep_sw23_9e452a5621.isra.7.constprop.13` | 320 | 2 | **done** |
| `0x180026fb0` | `fpc_bio_bep_sw23_66bb0714da` | 336 | 1 | **done** |
| `0x18000eca0` | `fpc_bio_bep_sw23_045ad05bbf` | 384 | 2 | **done** |
| `0x18001c4e0` | `fpc_bio_bep_sw23_3281879ff9` | 384 | 1 | **done** |
| `0x18000ee70` | `fpc_bio_bep_sw23_04faa0a17d.part.1` | 400 | 1 | **done** |
| `0x18001fb80` | `fpc_bio_bep_sw23_442776bb33` | 400 | 1 |  **done** |
| `0x180002dd0` | `FpcCos` | 416 | 5 | **done** |
| `0x180016df0` | `fpc_bio_bep_sw23_214aef3596` | 416 | 2 | **done** |
| `0x180024cb0` | `fpc_bio_bep_sw23_5f21879897` | 432 | 3 | **done** |
| `0x18000d040` | `fpc_bep_template_serialize` | 464 | 1 | **done** |
| `0x1800220e0` | `fpc_bio_bep_sw23_5029eb7cfe` | 464 | 3 | **done** |
| `0x18002ca30` | `fpc_bio_bep_sw23_79a4530e21.part.4` | 464 | 1 | **done** |
| `0x180044b10` | `fpc_bio_bep_sw23_ed385570f8` | 464 | 1 | **done** |
| `0x1800169b0` | `fpc_bio_bep_sw23_1fe4634733` | 480 | 1 | **done** |
| `0x180017ac0` | `fpc_bio_bep_sw23_267120cd30` | 480 | 1 | **done** |
| `0x180024200` | `fpc_bio_bep_sw23_598b2d29a0` | 496 | 1 | **done** |
| `0x18000fd90` | `fpc_bio_bep_sw23_0a86d32299` | 528 | 2 | **done** |
| `0x180020d80` | `fpc_bio_bep_sw23_49a7dfde4e` | 528 | 1 | **done** |
| `0x18003e590` | `fpc_bio_bep_sw23_cb8639ce35` | 528 | 3 | **done** |
| `0x180043db0` | `fpc_bio_bep_sw23_e809dd007c` | 560 | 1 | **done** |
| `0x18000d8e0` | `fpc_bio_bep_sw23_02a79f65fe` | 576 | 1 | **done** |
| `0x18001c280` | `fpc_bio_bep_sw23_326e82e939` | 608 | 1 | **done** |
| `0x18002f070` | `fpc_bio_bep_sw23_861d4887f0` | 624 | 3 | **done** |
| `0x18001aaa0` | `fpc_bio_bep_sw23_311b05823c` | 656 | 1 | **done** |
| `0x180028930` | `fpc_bio_bep_sw23_6f845fb02c` | 656 | 1 | **done** |
| `0x18002ddd0` | `fpc_bio_bep_sw23_82f9a9e315.part.9` | 656 | 2 | **done** |
| `0x180032830` | `fpc_bio_bep_sw23_97ae28484f` | 704 | 1 | **done** |
| `0x18003ecc0` | `fpc_bio_bep_sw23_cd9632fb7f` | 752 | 3 | **done** |
| `0x1800337e0` | `fpc_bio_bep_sw23_9bbd6b7a97` | 768 | 1 | **done** |
| `0x180043a50` | `fpc_bio_bep_sw23_e789d2446e` | 832 | 1 | **done** |
| `0x180030fc0` | `fpc_bio_bep_sw23_91ea5ea28d.isra.6` | 928 | 5 | **done** |
| `0x180040560` | `fpc_bio_bep_sw23_d8d4223a88` | 976 | 5 | **done** |
| `0x180033b40` | `fpc_bio_bep_sw23_9d0de274f8` | 1024 | 2 | **done** |
| `0x18002c600` | `fpc_bio_bep_sw23_79a4530e21` | 1072 | 1 | **done** |
| `0x18003bf90` | `fpc_bio_bep_sw23_beb4df26c0` | 1152 | 2 | **done** |
| `0x180020230` | `fpc_bio_bep_sw23_45dc1beabd` | 1184 | 1 | **done** |
| `0x1800433b0` | `fpc_bio_bep_sw23_e6dfc8ce14` | 1200 | 2 | **done** |
| `0x18002e6a0` | `fpc_bio_bep_sw23_85057ad42a` | 1280 | 1 | **done** |
| `0x180038ac0` | `fpc_bio_bep_sw23_b3a74c54eb` | 1776 | 1 | **done** |
