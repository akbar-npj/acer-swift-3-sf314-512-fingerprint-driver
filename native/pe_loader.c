/* Minimal PE32+ loader (see pe_loader.h). */
#include "pe_loader.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

static const char *rva_str(void *base, u32 rva) {
    return (const char *)((u8 *)base + rva);
}

static void *read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return NULL; }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n <= 0) { fclose(f); fprintf(stderr, "%s: empty\n", path); return NULL; }
    void *buf = malloc((size_t)n);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) {
        fclose(f); free(buf); fprintf(stderr, "%s: short read\n", path); return NULL;
    }
    fclose(f);
    *out_len = (size_t)n;
    return buf;
}

static void apply_relocations(u8 *base, u8 *raw, pe_optional_header64 *opt,
                              pe_section_header *sec, u16 nsec, s64 delta) {
    if (opt->NumberOfRvaAndSizes <= PE_DIR_BASERELOC) return;
    pe_data_dir *dir = &opt->DataDirectory[PE_DIR_BASERELOC];
    if (!dir->VirtualAddress || !dir->Size) return;

    u32 rva = dir->VirtualAddress;
    u32 end = rva + dir->Size;
    while (rva < end) {
        pe_base_relocation *blk = (pe_base_relocation *)(base + rva);
        if (blk->SizeOfBlock == 0) break;
        u32 count = (blk->SizeOfBlock - sizeof(*blk)) / 2;
        u16 *entries = (u16 *)(blk + 1);
        for (u32 i = 0; i < count; i++) {
            u16 e = entries[i];
            u32 type = e >> 12, off = e & 0xFFF;
            if (type == 0) continue;               /* ABSOLUTE padding */
            if (type == 10 /* DIR64 */) {
                u64 *slot = (u64 *)(base + blk->VirtualAddress + off);
                *slot += (u64)delta;
            } else {
                fprintf(stderr, "[pe] unsupported reloc type %u\n", type);
            }
        }
        rva += blk->SizeOfBlock;
    }
    (void)raw; (void)sec; (void)nsec;
}

static int resolve_imports(u8 *base, pe_optional_header64 *opt, pe_resolve_fn resolve) {
    if (opt->NumberOfRvaAndSizes <= PE_DIR_IMPORT) return 0;
    pe_data_dir *dir = &opt->DataDirectory[PE_DIR_IMPORT];
    if (!dir->VirtualAddress) return 0;

    pe_import_descriptor *imp = (pe_import_descriptor *)(base + dir->VirtualAddress);
    int unresolved = 0;
    for (; imp->Name; imp++) {
        const char *dll = rva_str(base, imp->Name);
        u64 *thunk = (u64 *)(base + (imp->OriginalFirstThunk ? imp->OriginalFirstThunk
                                                              : imp->FirstThunk));
        u64 *iat = (u64 *)(base + imp->FirstThunk);
        for (; *thunk; thunk++, iat++) {
            if (*thunk & (1ULL << 63)) {          /* import by ordinal */
                *iat = (u64)resolve(dll, NULL);
                continue;
            }
            pe_import_by_name *ibn = (pe_import_by_name *)(base + (u32)*thunk);
            void *fn = resolve(dll, ibn->Name);
            if (!fn) {
                fprintf(stderr, "[pe] unresolved import %s!%s\n", dll, ibn->Name);
                unresolved++;
            }
            *iat = (u64)fn;
        }
    }
    return unresolved;
}

void *pe_load(const char *path, pe_resolve_fn resolve) {
    size_t raw_len = 0;
    u8 *raw = read_file(path, &raw_len);
    if (!raw) return NULL;

    pe_dos_header *dos = (pe_dos_header *)raw;
    if (dos->e_magic != PE_DOS_SIGNATURE) {
        fprintf(stderr, "[pe] %s: not a PE (bad DOS magic)\n", path);
        free(raw); return NULL;
    }
    u8 *nt = raw + dos->e_lfanew;
    if (*(u32 *)nt != PE_NT_SIGNATURE) {
        fprintf(stderr, "[pe] %s: bad NT signature\n", path);
        free(raw); return NULL;
    }
    pe_file_header *fh = (pe_file_header *)(nt + 4);
    pe_optional_header64 *opt = (pe_optional_header64 *)(fh + 1);
    if (fh->Machine != PE_FILE_MACHINE_AMD64 || opt->Magic != 0x20b) {
        fprintf(stderr, "[pe] %s: not PE32+ x86-64 (machine=%#x magic=%#x)\n",
                path, fh->Machine, opt->Magic);
        free(raw); return NULL;
    }
    pe_section_header *sec = (pe_section_header *)((u8 *)opt + fh->SizeOfOptionalHeader);
    if (getenv("PE_DEBUG")) {
        fprintf(stderr, "[pe] sections=%u optsize=%u entry=%#x imagebase=%#llx size=%#x hdrs=%#x\n",
                fh->NumberOfSections, fh->SizeOfOptionalHeader, opt->AddressOfEntryPoint,
                (unsigned long long)opt->ImageBase, opt->SizeOfImage, opt->SizeOfHeaders);
        for (u16 i = 0; i < fh->NumberOfSections; i++)
            fprintf(stderr, "[pe]  sec[%u] va=%#x vsz=%#x rawsz=%#x raw=%#x\n", i,
                    sec[i].VirtualAddress, sec[i].VirtualSize, sec[i].SizeOfRawData,
                    sec[i].PointerToRawData);
    }

    u64 want = opt->ImageBase;
    u32 size = opt->SizeOfImage;
    void *base = mmap((void *)want, size, PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    s64 delta = 0;
    if (base == MAP_FAILED || (u64)base != want) {
        if (base != MAP_FAILED) munmap(base, size);
        base = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (base == MAP_FAILED) {
            perror("[pe] mmap");
            free(raw); return NULL;
        }
        delta = (s64)((u8 *)base - (u8 *)want);
        fprintf(stderr, "[pe] preferred base %#llx unavailable, loaded at %p (delta %#llx)\n",
                (unsigned long long)want, base, (unsigned long long)delta);
    }

    memcpy(base, raw, opt->SizeOfHeaders);
    for (u16 i = 0; i < fh->NumberOfSections; i++) {
        u32 dst = sec[i].VirtualAddress;
        u32 sz = sec[i].SizeOfRawData;
        if (!sz) continue;
        if (sec[i].PointerToRawData + sz > raw_len) sz = raw_len - sec[i].PointerToRawData;
        memcpy((u8 *)base + dst, raw + sec[i].PointerToRawData, sz);
    }

    if (delta) apply_relocations(base, raw, opt, sec, fh->NumberOfSections, delta);

    int unresolved = resolve_imports(base, opt, resolve);
    if (unresolved)
        fprintf(stderr, "[pe] warning: %d unresolved import(s)\n", unresolved);

    free(raw);
    return base;
}

void *pe_export(void *base, const char *name) {
    pe_dos_header *dos = (pe_dos_header *)base;
    u8 *nt = (u8 *)base + dos->e_lfanew;
    pe_file_header *fh = (pe_file_header *)(nt + 4);
    pe_optional_header64 *opt = (pe_optional_header64 *)(fh + 1);
    if (opt->NumberOfRvaAndSizes <= PE_DIR_EXPORT) return NULL;
    pe_data_dir *dir = &opt->DataDirectory[PE_DIR_EXPORT];
    if (!dir->VirtualAddress) return NULL;

    pe_export_directory *ed = (pe_export_directory *)((u8 *)base + dir->VirtualAddress);
    u32 *names = (u32 *)((u8 *)base + ed->AddressOfNames);
    u16 *ords = (u16 *)((u8 *)base + ed->AddressOfNameOrdinals);
    u32 *funcs = (u32 *)((u8 *)base + ed->AddressOfFunctions);
    for (u32 i = 0; i < ed->NumberOfNames; i++) {
        const char *n = (const char *)base + names[i];
        if (strcmp(n, name) == 0)
            return (u8 *)base + funcs[ords[i]];
    }
    return NULL;
}
