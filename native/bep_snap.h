/*
 * bep_snap.h — snapshot the live BEP input graph for standalone replay.
 *
 * The vendor enclave builds a pointer graph (image descriptors, mask bank,
 * slot table) before calling the BEP.  That graph is constant per sensor;
 * only the pixel buffer changes between captures.  Dumping it once lets the
 * clean-room BEP run without the vendor DLL.
 */
#ifndef BEP_SNAP_H
#define BEP_SNAP_H

#include <stdint.h>

/* Dump the graph rooted at the BEP arguments plus the mapped image data.
 * Returns 0 on success. */
int bep_snap_dump(const char *path,
                  void *a1, void *a2, void *a3, void **a4, void *a5, int a6,
                  uintptr_t image_base);

#endif /* BEP_SNAP_H */
