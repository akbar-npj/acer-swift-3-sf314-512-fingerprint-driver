/*
 * fpc_bep_template.h — captured BEP input graph (structures only).
 *
 * The graph is the pointer set handed to cr_bep_process_1c810 by the vendor
 * front end.  It is almost entirely static configuration; the only per-frame
 * inputs are the pixel buffer and seven header-derived metadata words.
 */
#ifndef FPC_BEP_TEMPLATE_H
#define FPC_BEP_TEMPLATE_H

#include <stdint.h>

typedef struct {
    uint16_t off;
    uint8_t  tgt;
} cr_bep_ptr;

typedef struct {
    uint32_t        size;
    const uint8_t  *data;   /* NULL = allocate zeroed, not part of template */
    uint16_t        nptr;
    const cr_bep_ptr *ptr;
} cr_bep_blk;

typedef struct {
    uint32_t       rva;
    uint32_t       size;
    const uint8_t *data;
} cr_bep_region;

extern const cr_bep_blk cr_bep_template[];
extern const cr_bep_region cr_bep_static[];
extern const int cr_bep_static_count;
extern const uint32_t cr_bep_image_size;
extern const int cr_bep_template_count;
extern const int cr_bep_template_a1;
extern const int cr_bep_template_a2;
extern const int cr_bep_template_a3;
extern const int cr_bep_template_a4;
extern const int cr_bep_template_a5;
extern const int cr_bep_template_a6;
extern const int cr_bep_template_frame;
extern const int cr_bep_template_meta;

/*
 * Run the clean-room BEP on one frame.
 *
 *   hdr22 : 22-byte image header from the sensor (may be NULL -> zeroes)
 *   pix   : 128x88 raw frame, 11264 bytes
 *   out   : 64x176 ridge image, 11264 bytes
 *
 * Returns 0 on success.
 */
int cr_bep_run_frame(const uint8_t *hdr22, const uint8_t *pix, uint8_t *out);

#endif /* FPC_BEP_TEMPLATE_H */
