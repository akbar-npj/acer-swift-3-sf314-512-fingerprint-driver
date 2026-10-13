/* Minimal PE32+ image loader — enough to map and run fpc_enclave.dll on Linux
 * natively, with no Wine. See native/README.md.
 *
 * Only what this DLL needs is implemented: section mapping, base relocations
 * (applied only if the preferred base is unavailable), the import directory
 * (resolved through shim_lookup), and the export directory.
 */
#ifndef FPC_PE_LOADER_H
#define FPC_PE_LOADER_H

#include <stddef.h>
#include <stdint.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

#define PE_DOS_SIGNATURE 0x5A4D
#define PE_NT_SIGNATURE 0x00004550
#define PE_FILE_MACHINE_AMD64 0x8664

#define PE_DIR_EXPORT 0
#define PE_DIR_IMPORT 1
#define PE_DIR_BASERELOC 5

#pragma pack(push, 1)
typedef struct {
    u16 e_magic, e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc, e_maxalloc;
    u16 e_ss, e_sp, e_csum, e_ip, e_cs, e_lfarlc, e_ovno, e_res[4];
    u16 e_oemid, e_oeminfo, e_res2[10];
    u32 e_lfanew;
} pe_dos_header;

typedef struct {
    u16 Machine, NumberOfSections;
    u32 TimeDateStamp, PointerToSymbolTable, NumberOfSymbols;
    u16 SizeOfOptionalHeader, Characteristics;
} pe_file_header;

typedef struct { u32 VirtualAddress, Size; } pe_data_dir;

typedef struct {
    u16 Magic;
    u8 MajorLinkerVersion, MinorLinkerVersion;
    u32 SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData;
    u32 AddressOfEntryPoint, BaseOfCode;
    u64 ImageBase;
    u32 SectionAlignment, FileAlignment;
    u16 MajorOperatingSystemVersion, MinorOperatingSystemVersion;
    u16 MajorImageVersion, MinorImageVersion;
    u16 MajorSubsystemVersion, MinorSubsystemVersion;
    u32 Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum;
    u16 Subsystem, DllCharacteristics;
    u64 SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit;
    u32 LoaderFlags, NumberOfRvaAndSizes;
    pe_data_dir DataDirectory[16];
} pe_optional_header64;

typedef struct {
    char Name[8];
    u32 VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData;
    u32 PointerToRelocations, PointerToLinenumbers;
    u16 NumberOfRelocations, NumberOfLinenumbers;
    u32 Characteristics;
} pe_section_header;

typedef struct {
    u32 Characteristics, TimeDateStamp;
    u16 MajorVersion, MinorVersion;
    u32 Name, Base, NumberOfFunctions, NumberOfNames;
    u32 AddressOfFunctions, AddressOfNames, AddressOfNameOrdinals;
} pe_export_directory;

typedef struct {
    u32 OriginalFirstThunk, TimeDateStamp, ForwarderChain, Name, FirstThunk;
} pe_import_descriptor;

typedef struct { u16 Hint; char Name[1]; } pe_import_by_name;

typedef struct { u32 VirtualAddress, SizeOfBlock; } pe_base_relocation;
#pragma pack(pop)

/* Resolve one imported symbol. `dll` is the bare module name (lower-cased),
 * `name` the exported function name. Return a callable address or NULL. */
typedef void *(*pe_resolve_fn)(const char *dll, const char *name);

/* Map the PE at `path` into memory, apply relocations and imports.
 * Returns the image base, or NULL on failure (message on stderr). */
void *pe_load(const char *path, pe_resolve_fn resolve);

/* Look up an exported function by name in a loaded image. */
void *pe_export(void *base, const char *name);

#endif /* FPC_PE_LOADER_H */
