/*
 * fpc_comp.c — clean-room reimplementation of two Gaussian-windowed FIR
 * orchestration functions (0x180046610, 0x180044a20).
 *
 * Both validate a pair of image descriptors (field[0] == field[0x10] and
 * field[0x18] == 0), then build a Q15 Gaussian window and run it through the
 * reflect-101 FIR helpers.  Transcribed from disassembly, including the exact
 * validation/guard ordering and return codes (0x69 invalid, else guard status).
 *
 * The descriptor is read through raw offsets (matching the vendor's memory
 * accesses): +0x08 data pointer, +0x10 (qword, equals +0x00; low 32 = W),
 * +0x14 int (L), +0x18 (qword == 0).
 */
#include "fpc_bep.h"

static inline void *desc_data(const void *d) {
    const unsigned char *p = (const unsigned char *)d;
    void *v;
    __builtin_memcpy(&v, p + 0x08, sizeof v);
    return v;
}
static inline int desc_w(const void *d) {
    const unsigned char *p = (const unsigned char *)d;
    int v; __builtin_memcpy(&v, p + 0x10, sizeof v);
    return v;
}
static inline int desc_l(const void *d) {
    const unsigned char *p = (const unsigned char *)d;
    int v; __builtin_memcpy(&v, p + 0x14, sizeof v);
    return v;
}
static inline int desc_valid(const void *d) {
    const unsigned char *p = (const unsigned char *)d;
    uint64_t a, b, c;
    __builtin_memcpy(&a, p + 0x00, sizeof a);
    __builtin_memcpy(&b, p + 0x10, sizeof b);
    __builtin_memcpy(&c, p + 0x18, sizeof c);
    return (a == b) && (c == 0);
}

/* 0x180046610 — general (count-tap) Gaussian-FIR apply. */
int cr_gauss_fir_apply(void *a, void *b, int r8, uint16_t count,
                       float unk0, float unk1, float sigma)
{
    (void)r8; (void)unk0; (void)unk1;
    if (!desc_valid(a) || !desc_valid(b)) return 0x69;
    void *buf = NULL;
    if (cr_malloc_aligned16(&buf, 2u * count) != 0) return 0x69;
    int16_t *coef = (int16_t *)buf;
    void *a_data = desc_data(a);
    void *b_data = desc_data(b);
    int W = desc_w(b);
    int L = desc_l(b);
    cr_gaussian_window_q15(coef, sigma, count);
    int status = cr_fir_reflect_rows_guarded(a_data, b_data, coef, count, W, L);
    if (status == 0)
        status = cr_fir_reflect_guarded(a_data, a_data, coef, count, W, L);
    cr_sized_free(&buf);
    return status;
}

/* 0x180044a20 — fixed 7-tap twin.  When W is 8-aligned it uses the guarded
 * row/reflect FIRs (returning the guard status); otherwise the fixed fir7_reflect
 * + vfir7_cols pair (always returning 0). */
int cr_gauss_fir7_apply(void *a, void *b, float unk0, float unk1, float sigma)
{
    (void)unk0; (void)unk1;
    if (!desc_valid(a) || !desc_valid(b)) return 0x69;
    int16_t coef[7];
    void *a_data = desc_data(a);
    void *b_data = desc_data(b);
    int W = desc_w(b);
    int L = desc_l(b);
    cr_gaussian_window_q15(coef, sigma, 7);
    if ((W & 7) == 0) {
        int status = cr_fir_reflect_rows_guarded(a_data, b_data, coef, 7, W, L);
        if (status == 0)
            status = cr_fir_reflect_guarded(a_data, a_data, coef, 7, W, L);
        return status;
    }
    cr_fir7_reflect(a_data, b_data, coef, W, L);
    cr_vfir7_cols(a_data, a_data, coef, W, L);
    return 0;
}
