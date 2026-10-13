#ifndef FPC_WIN32_SHIMS_H
#define FPC_WIN32_SHIMS_H

#include <stdint.h>

#include "pe_loader.h"   /* u8/u16/u32/u64 typedefs */

/* Set the loaded image base so GetModuleHandle / GetProcAddress can answer. */
void win32_shims_set_image_base(void *base);

/* Resolve one import name to a native shim (NULL if unknown). Matches the
 * pe_resolve_fn signature in pe_loader.h. */
void *shim_lookup(const char *dll, const char *name);

#endif /* FPC_WIN32_SHIMS_H */
