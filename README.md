# pe-signgen

**Cross-version binary signatures and RVA offsets for Windows PE functions**

---

## Overview

`pe-signgen` is a tool for reverse engineers and security researchers that automatically generates:

* **Binary signatures** (byte patterns with wildcards) for **unexported and exported** functions
* **RVA and file offsets** for locating functions directly in binaries
* **Cross-build signatures** that work across many Windows versions
* **Multiple output formats** optimized for different use cases
* Support for **x64, ARM64, and WoW64** architectures

The **core idea** is to provide a **systematic, robust way to access unexported functions** across Windows 10/11 builds. It leverages:

* [Winbindex](https://github.com/m417z/winbindex) for Windows build metadata
* Microsoft's public symbol servers for PDBs
* Local caching for reproducible, offline-friendly workflows

> ⚠️ **Windows version support**
> `pe-signgen` supports **Windows 10 and Windows 11 only**.
> This is a deliberate design choice: Winbindex does not provide complete data for older versions.

---

## Use Cases

* **Unexported Windows internals**
  Generate signatures for functions like `LdrpInitializeTls`, `RtlpInsertInvertedFunctionTableEntry`, etc.

* **Game hacking / anti-cheat research**
  Generate stable signatures that survive game updates

* **Security research**
  Locate security-critical routines across Windows builds

* **Automation**
  Scriptable signature and offset generation for entire sets of internal APIs

---

## Output Formats

`pe-signgen` provides three distinct output formats for different use cases:

### 1. **JSON Format**

Structured data for automation, scripting, and integration with other tools.

```bash
pe-signgen --signature ntdll!NtCreateFile -o ntcreatefile.json --output-format json
```

**Output structure:**

```json
{
  "dll_name": "ntdll",
  "function_name": "NtCreateFile",
  "architecture": "x64",
  "generated": "2024-12-11T15:30:00.123456",
  "total_builds": 1247,
  "unique_signatures": 3,
  "signature_groups": [
    {
      "matched_symbol": "NtCreateFile",
      "signature": "4C 8B DC 49 89 5B 08 49 89 6B 10 49 89 73 18 ...",
      "length": 48,
      "build_count": 845,
      "versions": [
        { "major": 10240, "minor": 16384, "build": "10240.16384" },
        { "major": 10586, "minor": 0, "build": "10586.0" }
      ]
    }
  ]
}
```

Notes:

* `major` and `minor` are derived from the build string by splitting at the first `.`.
  Example: `"10240.16384" → major = 10240, minor = 16384`.
* `build` is the original build string key used internally.

---

### 2. **Binary Format** (WSIG/WOFF)

Compact, runtime-ready binary formats optimized for embedded systems and low-overhead scanning.

These match the on-disk layout implemented in `write_wsig()` and `write_woff()`.

---

#### WSIG Format (Windows Signature)

**Magic:** `WSO\0` (0x57 0x53 0x4F 0x00)
**Current Version:** 1
**Purpose:** Store binary signatures with wildcard masks and associated Windows build versions

##### File Structure (conceptual)

```
┌─────────────────────────────────────┐
│         Header (36 bytes)           │
├─────────────────────────────────────┤
│      DLL Name (variable)            │
├─────────────────────────────────────┤
│    Function Name (variable)         │
├─────────────────────────────────────┤
│   Signature / Mask / Build blobs    │ ← Arbitrary order, see notes
├─────────────────────────────────────┤ ← Aligned to 4 bytes
│   Groups Table (24 × N bytes)       │
└─────────────────────────────────────┘
```

**Important layout notes (matches `write_wsig`)**

* After the header, the DLL and function names are written as UTF‑8 bytes.
* For each signature group, the pattern bytes and mask bytes are written, followed by the build array for that group.
* These per-group regions are **not** grouped globally by type: patterns, masks, and build arrays may be interleaved.
* The builder aligns to **4 bytes** before each build array and before the groups table. This can introduce padding.
* Consumers must **always** follow the offsets in the header and group entries; do **not** rely on the conceptual diagram for physical contiguity.

##### Header Layout (36 bytes)

```c
// Packed as: "<4sIIIIIIII" (little-endian)

typedef struct {
    char     magic[4];   // "WSO\0" (WSIG_MAGIC)
    uint32_t version;    // FORMAT_VERSION (currently 1)
    uint32_t arch;       // Architecture code (1=x64, 2=ARM64, 3=WoW64)
    uint32_t dll_off;    // Offset to DLL name string
    uint32_t dll_len;    // Length of DLL name in bytes
    uint32_t func_off;   // Offset to function name string
    uint32_t func_len;   // Length of function name in bytes
    uint32_t group_count;// Number of signature groups
    uint32_t groups_off; // Offset to groups table
} wsig_header_t; // 36 bytes
```

##### Group Entry (24 bytes)

Each signature group represents a unique pattern that applies to one or more Windows builds.

```c
// Packed as: "<IIIIII" (little-endian)

typedef struct {
    uint32_t sig_off;    // Offset to signature pattern bytes
    uint32_t sig_len;    // Length of signature pattern (in bytes)
    uint32_t mask_off;   // Offset to wildcard mask bytes
    uint32_t mask_len;   // Length of wildcard mask (≈ ceil(sig_len/8))
    uint32_t builds_off; // Offset to build version array
    uint32_t build_cnt;  // Number of builds using this signature
} wsig_group_t; // 24 bytes
```

##### Build Version Entry (8 bytes)

Each build entry identifies a specific Windows version that uses this signature.

```c
typedef struct {
    uint32_t major; // e.g. 19041
    uint32_t minor; // e.g. 1234
} wsig_build_t; // 8 bytes
```

`major` and `minor` come from splitting the build string (`"A.B" → A, B`). The original build string is not stored in the binary format; if you need it, keep it externally (it is present in the JSON output).

##### Wildcard Mask Format

The mask is a **bitmask** where each bit corresponds to a byte in the signature pattern:

* **Bit = 1:** Byte must match exactly (fixed byte)
* **Bit = 0:** Byte is wildcarded (ignore this byte during matching)

**Example:**

```
Signature: 4C 8B DC 49 89 ?? 08 49
Mask bits: 1  1  1  1  1  0  1  1  (MSB first within each byte)
Mask byte: 0xBF (binary: 10111111)
```

Mask bytes are stored and interpreted in **little-endian bit order** within each byte (exactly as used in the C helpers and `parse_signature`):

```c
uint8_t bit = (mask_bytes[byte_index >> 3] >> (byte_index & 7)) & 1u;
```

##### String Storage

* DLL and function names are stored as **UTF‑8**, **without null terminators**.
* Use `*_len` to determine the length; do **not** read past that.
* There are no alignment requirements for the strings themselves.
* Additional data regions (build arrays and the groups table) are aligned to 4‑byte boundaries; treat any padding as opaque.

---

#### WOFF Format (Windows Offset)

**Magic:** `WOF\0` (0x57 0x4F 0x46 0x00)
**Current Version:** 1
**Purpose:** Store direct RVA and file offsets for functions across Windows builds

##### File Structure

```
┌─────────────────────────────────────┐
│         Header (36 bytes)           │
├─────────────────────────────────────┤
│      DLL Name (variable)            │
├─────────────────────────────────────┤
│    Function Name (variable)         │
├─────────────────────────────────────┤
│ Matched Symbol Names (variable)     │ ← One UTF‑8 string per entry
├─────────────────────────────────────┤ ← Aligned to 4 bytes
│   Entries Table (32 × N bytes)      │
└─────────────────────────────────────┘
```

Layout details (matches `write_woff`):

* After the header placeholder, the DLL and function names are written as UTF‑8 bytes.
* For each build, the matched symbol name is written as a UTF‑8 string (no terminator). These form a simple string pool.
* The writer then aligns to 4 bytes and writes the fixed-size entries table.
* Each entry contains offsets (`matched_off`, `matched_len`) pointing into this string pool.

##### Header Layout (36 bytes)

```c
// Packed as: "<4sIIIIIIII" (little-endian)

typedef struct {
    char     magic[4];   // "WOF\0" (WOFF_MAGIC)
    uint32_t version;    // FORMAT_VERSION (currently 1)
    uint32_t arch;       // Architecture code (1=x64, 2=ARM64, 3=WoW64)
    uint32_t dll_off;    // Offset to DLL name string
    uint32_t dll_len;    // Length of DLL name in bytes
    uint32_t func_off;   // Offset to function name string
    uint32_t func_len;   // Length of function name in bytes
    uint32_t entry_cnt;  // Number of offset entries
    uint32_t entries_off;// Offset to entries table
} woff_header_t; // 36 bytes
```

##### Offset Entry (32 bytes)

Each entry maps a Windows build to the function's location in that build.

```c
// Packed as: "<IIQQII" (little-endian)

typedef struct {
    uint32_t major;       // Windows major version (e.g., 19041)
    uint32_t minor;       // Windows minor version (e.g., 1234)
    uint64_t rva;         // Relative Virtual Address in the DLL
    uint64_t file_offset; // Raw file offset in the DLL on disk
    uint32_t matched_off; // Offset to matched symbol name string
    uint32_t matched_len; // Length of matched symbol name
} woff_entry_t; // 32 bytes
```

##### Usage Notes

* **RVA** is the memory offset when the DLL is loaded at its preferred base.
* **File offset** is the raw position in the PE file on disk.
* **Matched symbol** may differ from the requested function (e.g., forwarded exports).
  The string is stored once in the string pool; `matched_off`/`matched_len` reference it.
* Entries are **sorted by build version** (`major`, then `minor`) for efficient lookup.

---

#### Architecture Codes

Both binary formats use the same architecture encoding (via `ARCH_CODE_MAP`):

| Code | Architecture | Description                  |
| ---- | ------------ | ---------------------------- |
| 1    | x64          | 64-bit AMD64/Intel64         |
| 2    | ARM64        | 64-bit ARM (AArch64)         |
| 3    | WoW64        | 32-bit x86 on 64-bit Windows |

Unknown architecture strings default to `1` (x64) internally; the CLI restricts values to the supported set.

---

### 3. **C Header Format**

Ready-to-compile C headers with type-safe structures and data arrays.

`pe-signgen` can emit two *kinds* of C headers:

* **WSIG headers** – for signature and mask data (from `write_wsig_header`).
* **WOFF headers** – for direct RVA/file-offset tables (from `write_woff_header`).

The `--output-format cheader` option selects C headers; combining it with `--offsets` switches between WSIG and WOFF variants.

#### WSIG C Header

```bash
pe-signgen --signature ntdll!RtlpInitializeThreadActivationContextStack \
  -o rtlp_init_actx.h --output-format cheader
```

**Generated header structure (simplified, matches `write_wsig_header`):**

```c
/* Auto-generated WSIG header for ntdll ! RtlpInitializeThreadActivationContextStack ! x64. */
#ifndef WSIG_NTDLL_RTLPINITIALIZETHREADACTIVATIONCONTEXTSTACK_X64_H
#define WSIG_NTDLL_RTLPINITIALIZETHREADACTIVATIONCONTEXTSTACK_X64_H

#include <stdint.h>
#include <stddef.h>

#define WSIG_NTDLL_RTLPINITIALIZETHREADACTIVATIONCONTEXTSTACK_X64_DLL_NAME  "ntdll"
#define WSIG_NTDLL_RTLPINITIALIZETHREADACTIVATIONCONTEXTSTACK_X64_FUNCTION_NAME "RtlpInitializeThreadActivationContextStack"
#define WSIG_NTDLL_RTLPINITIALIZETHREADACTIVATIONCONTEXTSTACK_X64_ARCH "x64"

/* Per-version build identifier. */
typedef struct {
    uint32_t major;
    uint32_t minor;
} WSIG_NTDLL_RTLPINITIALIZETHREADACTIVATIONCONTEXTSTACK_X64_version_t;

/* Signature group entry. */
typedef struct {
    const uint8_t *pattern;
    const uint8_t *mask;
    uint32_t length;
    uint32_t build_count;
    const WSIG_NTDLL_RTLPINITIALIZETHREADACTIVATIONCONTEXTSTACK_X64_version_t *versions;
} WSIG_NTDLL_RTLPINITIALIZETHREADACTIVATIONCONTEXTSTACK_X64_group_t;

/* One pattern/mask/versions triple per group. */
static const uint8_t WSIG_NTDLL_RTLPINITIALIZETHREADACTIVATIONCONTEXTSTACK_X64_group0_pattern[] = { /* ... */ };
static const uint8_t WSIG_NTDLL_RTLPINITIALIZETHREADACTIVATIONCONTEXTSTACK_X64_group0_mask[]    = { /* ... */ };
static const WSIG_NTDLL_RTLPINITIALIZETHREADACTIVATIONCONTEXTSTACK_X64_version_t
    WSIG_NTDLL_RTLPINITIALIZETHREADACTIVATIONCONTEXTSTACK_X64_group0_versions[] = {
        { 10240u, 16384u }, /* 10240.16384 */
        /* ... */
    };

static const WSIG_NTDLL_RTLPINITIALIZETHREADACTIVATIONCONTEXTSTACK_X64_group_t
    WSIG_NTDLL_RTLPINITIALIZETHREADACTIVATIONCONTEXTSTACK_X64_GROUPS[] = {
        {
            WSIG_NTDLL_RTLPINITIALIZETHREADACTIVATIONCONTEXTSTACK_X64_group0_pattern,
            WSIG_NTDLL_RTLPINITIALIZETHREADACTIVATIONCONTEXTSTACK_X64_group0_mask,
            (uint32_t)(sizeof(WSIG_NTDLL_RTLPINITIALIZETHREADACTIVATIONCONTEXTSTACK_X64_group0_pattern) /
                       sizeof(WSIG_NTDLL_RTLPINITIALIZETHREADACTIVATIONCONTEXTSTACK_X64_group0_pattern[0])),
            (uint32_t)(sizeof(WSIG_NTDLL_RTLPINITIALIZETHREADACTIVATIONCONTEXTSTACK_X64_group0_versions) /
                       sizeof(WSIG_NTDLL_RTLPINITIALIZETHREADACTIVATIONCONTEXTSTACK_X64_group0_versions[0])),
            WSIG_NTDLL_RTLPINITIALIZETHREADACTIVATIONCONTEXTSTACK_X64_group0_versions
        }, /* group 0 (RtlpInitializeThreadActivationContextStack) */
        /* ... */
};

static const size_t WSIG_NTDLL_RTLPINITIALIZETHREADACTIVATIONCONTEXTSTACK_X64_GROUP_COUNT =
    sizeof(WSIG_NTDLL_RTLPINITIALIZETHREADACTIVATIONCONTEXTSTACK_X64_GROUPS) /
    sizeof(WSIG_NTDLL_RTLPINITIALIZETHREADACTIVATIONCONTEXTSTACK_X64_GROUPS[0]);

#endif /* WSIG_NTDLL_RTLPINITIALIZETHREADACTIVATIONCONTEXTSTACK_X64_H */
```

**Integration example (corrected to match the generated types):**

```c
#include "rtlp_init_actx.h"

static inline int match_byte(uint8_t want, uint8_t got,
                             const uint8_t *mbits, uint32_t i) {
    uint8_t bit = (mbits[i >> 3] >> (i & 7)) & 1u;
    return bit ? (want == got) : 1;
}

static const uint8_t *
find_signature(const uint8_t *base, size_t size,
               const uint8_t *pattern,
               const uint8_t *mbits,
               uint32_t sig_len) {
    if (!base || !pattern || !mbits || sig_len == 0)
        return NULL;
    if (size < sig_len)
        return NULL;

    // Find first non-wildcard byte as anchor
    uint32_t anchor = sig_len;
    for (uint32_t i = 0; i < sig_len; ++i) {
        if ((mbits[i >> 3] >> (i & 7)) & 1u) {
            anchor = i;
            break;
        }
    }
    if (anchor == sig_len)
        return base; // all wildcards

    const uint8_t anchor_val = pattern[anchor];
    const size_t last_pos = size - (size_t)sig_len;

    for (size_t pos = 0; pos <= last_pos; ++pos) {
        if (base[pos + anchor] != anchor_val)
            continue;

        uint32_t i = 0;
        for (; i < sig_len; ++i) {
            if (!match_byte(pattern[i], base[pos + i], mbits, i))
                break;
        }
        if (i == sig_len)
            return base + pos;
    }
    return NULL;
}

static void
fetch_signature(uint32_t major, uint32_t minor,
                const WSIG_NTDLL_RTLPINITIALIZETHREADACTIVATIONCONTEXTSTACK_X64_group_t *groups,
                size_t group_len,
                const uint8_t **signature_dest,
                const uint8_t **mask_dest,
                uint32_t *signature_len_dest) {
    *signature_dest = NULL;
    *mask_dest = NULL;
    *signature_len_dest = 0;

    const WSIG_NTDLL_RTLPINITIALIZETHREADACTIVATIONCONTEXTSTACK_X64_group_t *closest = NULL;
    uint32_t best_distance = 0xFFFFFFFFu;

    for (size_t gi = 0; gi < group_len; ++gi) {
        const WSIG_NTDLL_RTLPINITIALIZETHREADACTIVATIONCONTEXTSTACK_X64_group_t *g = &groups[gi];
        for (uint32_t vi = 0; vi < g->build_count; ++vi) {
            uint32_t m = g->versions[vi].major;
            uint32_t n = g->versions[vi].minor;

            uint32_t distance = (m > major ? m - major : major - m) * 10000u +
                                (n > minor ? n - minor : minor - n);

            if (distance < best_distance) {
                best_distance = distance;
                closest = g;
            }

            if (m == major && n == minor) {
                *signature_dest = g->pattern;
                *mask_dest = g->mask;
                *signature_len_dest = g->length;
                return;
            }
        }
    }

    if (closest) {
        *signature_dest = closest->pattern;
        *mask_dest = closest->mask;
        *signature_len_dest = closest->length;
    }
}
```

You can then wire this into your own loader-specific code (e.g. using `GetModuleHandleA`, walking PE sections, etc.). The header intentionally only provides data; helper functions are up to the consumer.

#### WOFF C Header

For offset-only use cases, `write_woff_header` emits a small header describing a sorted table of `(major, minor, rva, file_offset)` entries.

**Layout (matches `write_woff_header`):**

```c
/* Auto-generated WOFF header for ntdll ! RtlpInitializeThreadActivationContextStack ! x64. */
#ifndef WOFF_NTDLL_RTLPINITIALIZETHREADACTIVATIONCONTEXTSTACK_X64_H
#define WOFF_NTDLL_RTLPINITIALIZETHREADACTIVATIONCONTEXTSTACK_X64_H

#include <stdint.h>
#include <stddef.h>

#define WOFF_NTDLL_RTLPINITIALIZETHREADACTIVATIONCONTEXTSTACK_X64_DLL_NAME  "ntdll"
#define WOFF_NTDLL_RTLPINITIALIZETHREADACTIVATIONCONTEXTSTACK_X64_FUNCTION_NAME "RtlpInitializeThreadActivationContextStack"
#define WOFF_NTDLL_RTLPINITIALIZETHREADACTIVATIONCONTEXTSTACK_X64_ARCH "x64"

/* Per-build offset entry. */
typedef struct {
    uint32_t major;
    uint32_t minor;
    uint64_t rva;
    uint64_t file_offset;
} WOFF_NTDLL_RTLPINITIALIZETHREADACTIVATIONCONTEXTSTACK_X64_entry_t;

static const WOFF_NTDLL_RTLPINITIALIZETHREADACTIVATIONCONTEXTSTACK_X64_entry_t
    WOFF_NTDLL_RTLPINITIALIZETHREADACTIVATIONCONTEXTSTACK_X64_ENTRIES[] = {
        { 10240u, 16384u, 0x5B195ULL, 0x5A595ULL }, /* 10240.16384 (RtlpInitializeThreadActivationContextStack) */
        /* ... (sorted by major, then minor) ... */
};

static const size_t WOFF_NTDLL_RTLPINITIALIZETHREADACTIVATIONCONTEXTSTACK_X64_ENTRY_COUNT =
    sizeof(WOFF_NTDLL_RTLPINITIALIZETHREADACTIVATIONCONTEXTSTACK_X64_ENTRIES) /
    sizeof(WOFF_NTDLL_RTLPINITIALIZETHREADACTIVATIONCONTEXTSTACK_X64_ENTRIES[0]);

#endif /* WOFF_NTDLL_RTLPINITIALIZETHREADACTIVATIONCONTEXTSTACK_X64_H */
```

This is useful when you trust the offsets themselves and do not need pattern-matching.

---

## Installation

### Prerequisites

* Python 3.8+
* Git
* Internet connection (first run)
* ~10GB disk space for full cache

### Install from Pip

```bash
pip install pe-signgen
```

### Install from Source

```bash
git clone https://github.com/forentfraps/pe-signgen.git
cd pe-signgen
pip install -r requirements.txt
pip install -e .
```

---

## Quick Start

### Generate a Signature

```bash
pe-signgen --signature ntdll!LdrLoadDll
```

### Generate Offsets

```bash
pe-signgen --signature kernel32!CreateFileW --offsets
```

### Save as JSON

```bash
pe-signgen --signature ntdll!NtCreateFile -o out.json --output-format json
```

---

## Command-Line Options

### Basic Syntax

```bash
pe-signgen --signature DLL!FUNCTION [OPTIONS]
```

### Architecture

```bash
--arch x64   # default
--arch arm64
--arch wow64
```

### Version Filtering

```bash
--os-version win10       # Only Windows 10
--os-version win11       # Only Windows 11
--min-version 10.0       # Minimum version
--max-version 11.0       # Maximum version
```

### Signature Length Control

```bash
--min-length 32          # Minimum signature length
--max-length 64          # Maximum signature length
```

### Output Options

```bash
-o, --output PATH        # Output file path
--output-format FORMAT   # json | binary | cheader
--offsets                # Generate offsets instead of signatures
```

### Performance

```bash
--workers 16             # Parallel workers (default: CPU count)
--no-cache               # Disable caching
--no-git-update          # Skip Winbindex updates
```

### Verbosity

```bash
--verbose                # Detailed output
--quiet                  # Minimal output
--no-progress            # Disable progress bars
```

---

## Caching

### Cache Layout

```text
~/.cache/pe-signgen/
│
├── dlls/           # Downloaded DLLs
├── pdbs/           # Downloaded PDBs
├── signatures/     # Generated signatures
└── winbindex_data/ # Winbindex metadata
```

### Cache Control

```bash
# Disable cache for fresh generation
pe-signgen --signature ntdll!NtCreateFile --no-cache

# Clear cache
rm -rf ~/.cache/pe-signgen

# Custom cache location
export PE_SIGNGEN_CACHE=/custom/path
pe-signgen --signature ntdll!NtCreateFile
```

---

## Performance

**Example performance (12-core CPU, 100 Mbps):**

| Operation                         | Time        |
| --------------------------------- | ----------- |
| First run (no cache)              | 5–10 min    |
| Cached run                        | < 1 sec     |
| Per-build analysis                | 0.1–0.5 sec |
| Full run (1000 builds, 8 workers) | 2–4 min     |

**Resource requirements:**

* **Disk:** ~10 GB for full DLL/PDB cache
* **Memory:** ~500 MB peak usage
* **Network:** Several GB on first run

---

## Known Limitations

* **Windows version coverage:** Only Windows **10 and 11** (Winbindex limitation)
* **Build availability:** Not every Win10/11 build exists in Winbindex

---

## Development

```bash
git clone https://github.com/forentfraps/pe-signgen.git
cd pe-signgen
pip install -e ".[dev]"

# Code formatting
black pe_signgen/

# Type checking
mypy pe_signgen/
```

---

## License

MIT License – see [LICENSE](LICENSE).

---

## Credits

* **Winbindex** – Windows build metadata by [@m417z](https://github.com/m417z)
* **pefile** – PE parsing library
* **winpdb-rs** – PDB parsing Python bindings

Inspired by the need for robust, automated signature generation for internal Windows APIs.

---

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

---

## Support

* **Issues:** [GitHub Issues](https://github.com/forentfraps/pe-signgen/issues)
* **Discussions:** [GitHub Discussions](https://github.com/forentfraps/pe-signgen/discussions)
