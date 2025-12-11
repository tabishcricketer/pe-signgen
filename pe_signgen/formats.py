from __future__ import annotations

import json
import re
import struct
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import BinaryIO

from .constants import (
    WSIG_MAGIC,
    WOFF_MAGIC,
    FORMAT_VERSION,
    ARCH_CODE_MAP,
)
from .exceptions import InvalidFormatError
from .signatures import parse_signature


@dataclass
class BinaryBuilder:
    """Helper for building binary data with offset tracking."""

    buffer: bytearray

    def __init__(self):
        self.buffer = bytearray()

    def tell(self) -> int:
        """Current position in buffer."""
        return len(self.buffer)

    def align(self, boundary: int) -> None:
        """Pad to alignment boundary."""
        padding = (-len(self.buffer)) % boundary
        if padding:
            self.buffer.extend(b"\x00" * padding)

    def write(self, data: bytes) -> int:
        """Write data and return starting offset."""
        offset = self.tell()
        self.buffer.extend(data)
        return offset

    def write_u32(self, value: int) -> int:
        """Write little-endian u32."""
        return self.write(struct.pack("<I", value))

    def write_u64(self, value: int) -> int:
        """Write little-endian u64."""
        return self.write(struct.pack("<Q", value))

    def write_struct(self, fmt: str, *values) -> int:
        """Write packed struct."""
        return self.write(struct.pack(fmt, *values))

    def patch(self, offset: int, data: bytes) -> None:
        """Patch data at specific offset."""
        self.buffer[offset : offset + len(data)] = data


def _build_key(build: str) -> tuple[int, int]:
    """Convert build string to sortable tuple."""
    parts = build.split(".")
    try:
        return (int(parts[0]), int(parts[1]) if len(parts) > 1 else 0)
    except (ValueError, IndexError):
        return (999999, 999999)


def _c_escape_string(value: str) -> str:
    """Escape a Python string for use as a C string literal."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _format_c_byte_array(
    name: str,
    data: bytes,
    indent: str = "    ",
    bytes_per_line: int = 12,
) -> str:
    """Format bytes as a C uint8_t array definition."""
    if not data:
        # Empty arrays are rare here, but handle gracefully
        return f"static const uint8_t {name}[] = {{ }};\n"

    lines: list[str] = []
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i : i + bytes_per_line]
        chunk_txt = ", ".join(f"0x{b:02X}" for b in chunk)
        lines.append(f"{indent}{chunk_txt}")

    inner = ",\n".join(lines)
    return f"static const uint8_t {name}[] = {{\n{inner}\n}};\n"


def _make_c_prefix(kind: str, dll: str, func: str, arch: str) -> str:
    """
    Make a C identifier prefix from kind/dll/func/arch.

    Example: kind="WSIG", dll="ntdll.dll", func="NtOpenFile", arch="x64"
      -> "WSIG_NTDLL_DLL_NTOPENFILE_X64"
    """
    raw = f"{kind}_{dll}_{func}_{arch}"
    ident = re.sub(r"[^0-9A-Za-z_]", "_", raw)
    if not (ident[0].isalpha() or ident[0] == "_"):
        ident = "_" + ident
    return ident.upper()


# WSIG Format

"""
WSIG-O Layout (all little-endian):

Header (36 bytes):
  magic:       4 bytes  = b"WSO\0"
  version:     u32      = 1
  arch:        u32      = {x64:1, arm64:2, wow64:3}
  dll_off:     u32
  dll_len:     u32
  func_off:    u32
  func_len:    u32
  group_count: u32
  groups_off:  u32

Groups Table (group_count * 24 bytes):
  sig_off:     u32
  sig_len:     u32
  mask_off:    u32
  mask_len:    u32
  builds_off:  u32
  build_cnt:   u32

Builds Array (per group, build_cnt * 8 bytes):
  major:       u32
  minor:       u32
"""

WSIG_HEADER_FORMAT = "<4sIIIIIIII"
WSIG_HEADER_SIZE = struct.calcsize(WSIG_HEADER_FORMAT)
WSIG_GROUP_FORMAT = "<IIIIII"
WSIG_GROUP_SIZE = struct.calcsize(WSIG_GROUP_FORMAT)


def write_wsig(
    dll: str,
    func: str,
    arch: str,
    results: dict[str, tuple[str, int, str, int]],
    groups: dict[str, list[str]],
    output: Path,
) -> None:
    """
    Write signatures to WSIG binary format.

    Args:
        dll: DLL name
        func: Function name
        arch: Architecture
        results: Build -> (signature, length, matched, rva)
        groups: Signature -> list of builds
        output: Output file path
    """
    arch_code = ARCH_CODE_MAP.get(arch.lower(), 1)

    bb = BinaryBuilder()

    bb.write(b"\x00" * WSIG_HEADER_SIZE)

    dll_bytes = dll.encode("utf-8")
    func_bytes = func.encode("utf-8")
    dll_off = bb.write(dll_bytes)
    func_off = bb.write(func_bytes)

    # Sort groups by earliest build
    sorted_groups = sorted(
        groups.items(),
        key=lambda kv: (
            _build_key(min(kv[1], key=_build_key)) if kv[1] else (999999, 999999)
        ),
    )

    group_meta: list[tuple[int, int, int, int, int, int]] = []

    for sig, builds in sorted_groups:
        pattern, mask = parse_signature(sig)

        sig_off = bb.write(pattern)
        mask_off = bb.write(mask)

        bb.align(4)
        builds_sorted = sorted(builds, key=_build_key)
        builds_data = bytearray()
        for build in builds_sorted:
            major, minor = _build_key(build)
            builds_data.extend(struct.pack("<II", major, minor))

        builds_off = bb.write(builds_data)

        group_meta.append(
            (sig_off, len(pattern), mask_off, len(mask), builds_off, len(builds_sorted))
        )

    bb.align(4)
    groups_off = bb.tell()

    for sig_off, sig_len, mask_off, mask_len, builds_off, build_cnt in group_meta:
        bb.write_struct(
            WSIG_GROUP_FORMAT,
            sig_off,
            sig_len,
            mask_off,
            mask_len,
            builds_off,
            build_cnt,
        )

    header = struct.pack(
        WSIG_HEADER_FORMAT,
        WSIG_MAGIC,
        FORMAT_VERSION,
        arch_code,
        dll_off,
        len(dll_bytes),
        func_off,
        len(func_bytes),
        len(group_meta),
        groups_off,
    )
    bb.patch(0, header)

    output.write_bytes(bb.buffer)


# WOFF Format

"""
WOFF-O Layout (all little-endian):

Header (36 bytes):
  magic:       4 bytes  = b"WOF\0"
  version:     u32      = 1
  arch:        u32
  dll_off:     u32
  dll_len:     u32
  func_off:    u32
  func_len:    u32
  entry_cnt:   u32
  entries_off: u32

Entries Table (entry_cnt * 32 bytes):
  major:       u32
  minor:       u32
  rva:         u64
  file_off:    u64
  matched_off: u32
  matched_len: u32
"""

WOFF_HEADER_FORMAT = "<4sIIIIIIII"
WOFF_HEADER_SIZE = struct.calcsize(WOFF_HEADER_FORMAT)
WOFF_ENTRY_FORMAT = "<IIQQII"
WOFF_ENTRY_SIZE = struct.calcsize(WOFF_ENTRY_FORMAT)


def write_woff(
    dll: str,
    func: str,
    arch: str,
    offsets: dict[str, tuple[int, int, str]],
    output: Path,
) -> None:
    """
    Write offsets to WOFF binary format.

    Args:
        dll: DLL name
        func: Function name
        arch: Architecture
        offsets: Build -> (rva, file_offset, matched_name)
        output: Output file path
    """
    arch_code = ARCH_CODE_MAP.get(arch.lower(), 1)

    bb = BinaryBuilder()

    bb.write(b"\x00" * WOFF_HEADER_SIZE)

    dll_bytes = dll.encode("utf-8")
    func_bytes = func.encode("utf-8")
    dll_off = bb.write(dll_bytes)
    func_off = bb.write(func_bytes)

    builds_sorted = sorted(offsets.keys(), key=_build_key)

    matched_meta: list[tuple[int, int]] = []
    for build in builds_sorted:
        _, _, matched = offsets[build]
        matched_bytes = matched.encode("utf-8")
        m_off = bb.write(matched_bytes)
        matched_meta.append((m_off, len(matched_bytes)))

    bb.align(4)
    entries_off = bb.tell()

    for idx, build in enumerate(builds_sorted):
        rva, file_off, _ = offsets[build]
        major, minor = _build_key(build)
        m_off, m_len = matched_meta[idx]

        bb.write_struct(WOFF_ENTRY_FORMAT, major, minor, rva, file_off, m_off, m_len)

    header = struct.pack(
        WOFF_HEADER_FORMAT,
        WOFF_MAGIC,
        FORMAT_VERSION,
        arch_code,
        dll_off,
        len(dll_bytes),
        func_off,
        len(func_bytes),
        len(builds_sorted),
        entries_off,
    )
    bb.patch(0, header)

    output.write_bytes(bb.buffer)


# JSON Export


def write_json(
    dll: str,
    func: str,
    arch: str,
    results: dict[str, tuple[str, int, str, int]],
    groups: dict[str, list[str]],
    output: Path,
) -> None:
    """
    Write signatures to JSON format.

    Args:
        dll: DLL name
        func: Function name
        arch: Architecture
        results: Build -> (signature, length, matched, rva)
        groups: Signature -> list of builds
        output: Output file path
    """
    sorted_groups = sorted(
        groups.items(),
        key=lambda kv: (
            _build_key(min(kv[1], key=_build_key)) if kv[1] else (999999, 999999)
        ),
    )

    data = {
        "dll_name": dll,
        "function_name": func,
        "architecture": arch,
        "generated": datetime.now().isoformat(),
        "total_builds": len(results),
        "unique_signatures": len(groups),
        "signature_groups": [],
    }

    for sig, builds in sorted_groups:
        builds_sorted = sorted(builds, key=_build_key)
        first_build = builds_sorted[0]
        _, length, matched, _ = results[first_build]

        versions = []
        for build in builds_sorted:
            major, minor = _build_key(build)
            versions.append({"major": major, "minor": minor, "build": build})

        data["signature_groups"].append(
            {
                "matched_symbol": matched,
                "signature": sig,
                "length": length,
                "build_count": len(builds),
                "versions": versions,
            }
        )

    output.write_text(json.dumps(data, indent=2), encoding="utf-8")


# C Header Export


def write_wsig_header(
    dll: str,
    func: str,
    arch: str,
    results: dict[str, tuple[str, int, str, int]],
    groups: dict[str, list[str]],
    output: Path,
) -> None:
    """
    Write signatures to a C header (.h) suitable for embedding.

    All identifiers are namespaced by a prefix derived from (WSIG, dll, func, arch),
    so multiple generated headers can be safely included together.

    Layout:

        #define <PREFIX>_DLL_NAME      "ntdll"
        #define <PREFIX>_FUNCTION_NAME "LdrpInitializeTls"
        #define <PREFIX>_ARCH          "x64"

        typedef struct {
            uint32_t major;
            uint32_t minor;
        } <PREFIX>_version_t;

        typedef struct {
            const uint8_t *pattern;
            const uint8_t *mask;
            uint32_t length;
            uint32_t build_count;
            const <PREFIX>_version_t *versions;
        } <PREFIX>_group_t;

        static const uint8_t <PREFIX>_group0_pattern[] = { ... };
        static const uint8_t <PREFIX>_group0_mask[]    = { ... };
        static const <PREFIX>_version_t <PREFIX>_group0_versions[] = { ... };

        static const <PREFIX>_group_t <PREFIX>_GROUPS[] = { ... };
        static const size_t <PREFIX>_GROUP_COUNT = ...;
    """
    sorted_groups = sorted(
        groups.items(),
        key=lambda kv: (
            _build_key(min(kv[1], key=_build_key)) if kv[1] else (999999, 999999)
        ),
    )

    dll_c = _c_escape_string(dll)
    func_c = _c_escape_string(func)
    arch_c = _c_escape_string(arch)
    prefix = _make_c_prefix("WSIG", dll, func, arch)

    version_t = f"{prefix}_version_t"
    group_t = f"{prefix}_group_t"
    groups_array = f"{prefix}_GROUPS"
    group_count_macro = f"{prefix}_GROUP_COUNT"
    dll_macro = f"{prefix}_DLL_NAME"
    func_macro = f"{prefix}_FUNCTION_NAME"
    arch_macro = f"{prefix}_ARCH"

    guard = f"{prefix}_H"

    lines: list[str] = []

    # Header prologue + guard
    lines.append(f"/* Auto-generated WSIG header for {dll} ! {func} ! {arch}. */\n")
    lines.append(f"#ifndef {guard}\n")
    lines.append(f"#define {guard}\n\n")
    lines.append("#include <stdint.h>\n")
    lines.append("#include <stddef.h>\n\n")

    # Basic metadata
    lines.append(f'#define {dll_macro}  "{dll_c}"\n')
    lines.append(f'#define {func_macro} "{func_c}"\n')
    lines.append(f'#define {arch_macro} "{arch_c}"\n\n')

    # Type definitions (namespaced)
    lines.append("/* Per-version build identifier. */\n")
    lines.append("typedef struct {\n")
    lines.append("    uint32_t major;\n")
    lines.append("    uint32_t minor;\n")
    lines.append(f"}} {version_t};\n\n")

    lines.append("/* Signature group entry. */\n")
    lines.append("typedef struct {\n")
    lines.append("    const uint8_t *pattern;\n")
    lines.append("    const uint8_t *mask;\n")
    lines.append("    uint32_t length;\n")
    lines.append("    uint32_t build_count;\n")
    lines.append(f"    const {version_t} *versions;\n")
    lines.append(f"}} {group_t};\n\n")

    # Per-group data: pattern, mask, versions
    for idx, (sig, builds) in enumerate(sorted_groups):
        pattern, mask = parse_signature(sig)
        builds_sorted = sorted(builds, key=_build_key)

        pattern_name = f"{prefix}_group{idx}_pattern"
        mask_name = f"{prefix}_group{idx}_mask"
        versions_name = f"{prefix}_group{idx}_versions"

        # Pattern and mask arrays
        lines.append(_format_c_byte_array(pattern_name, pattern))
        lines.append("\n")
        lines.append(_format_c_byte_array(mask_name, mask))
        lines.append("\n")

        # Versions array
        lines.append(f"static const {version_t} {versions_name}[] = {{\n")
        for build in builds_sorted:
            major, minor = _build_key(build)
            lines.append(f"    {{ {major}u, {minor}u }}, /* {build} */\n")
        lines.append("};\n\n")

    # Groups array
    lines.append(f"static const {group_t} {groups_array}[] = {{\n")
    for idx, (_, builds) in enumerate(sorted_groups):
        builds_sorted = sorted(builds, key=_build_key)
        first_build = builds_sorted[0]
        _, _, matched, _ = results[first_build]

        pattern_name = f"{prefix}_group{idx}_pattern"
        mask_name = f"{prefix}_group{idx}_mask"
        versions_name = f"{prefix}_group{idx}_versions"

        lines.append(
            "    { "
            f"{pattern_name}, "
            f"{mask_name}, "
            f"(uint32_t)(sizeof({pattern_name}) / sizeof({pattern_name}[0])), "
            f"(uint32_t)(sizeof({versions_name}) / sizeof({versions_name}[0])), "
            f"{versions_name}"
            f" }}, /* group {idx} ({matched}) */\n"
        )
    lines.append("};\n\n")

    lines.append(
        f"static const size_t {group_count_macro} = "
        f"sizeof({groups_array}) / sizeof({groups_array}[0]);\n\n"
    )

    lines.append(f"#endif /* {guard} */\n")

    output.write_text("".join(lines), encoding="utf-8")


def write_woff_header(
    dll: str,
    func: str,
    arch: str,
    offsets: dict[str, tuple[int, int, str]],
    output: Path,
) -> None:
    """
    Write offsets to a C header (.h) for embedding.

    All identifiers are namespaced by a prefix derived from (WOFF, dll, func, arch),
    so multiple generated headers can be safely included together.

    Layout:

        #define <PREFIX>_DLL_NAME      "ntdll"
        #define <PREFIX>_FUNCTION_NAME "LdrpInitializeTls"
        #define <PREFIX>_ARCH          "x64"

        typedef struct {
            uint32_t major;
            uint32_t minor;
            uint64_t rva;
            uint64_t file_offset;
        } <PREFIX>_entry_t;

        static const <PREFIX>_entry_t <PREFIX>_ENTRIES[] = {
            { 10240u, 16384u, 0x5B195ULL, 0x5A595ULL }, /* 10240.16384 (LdrpInitializeTls) */
            ...
        };

        static const size_t <PREFIX>_ENTRY_COUNT = ...;
    """
    dll_c = _c_escape_string(dll)
    func_c = _c_escape_string(func)
    arch_c = _c_escape_string(arch)
    prefix = _make_c_prefix("WOFF", dll, func, arch)

    builds_sorted = sorted(offsets.keys(), key=_build_key)

    entry_t = f"{prefix}_entry_t"
    entries_array = f"{prefix}_ENTRIES"
    entry_count_macro = f"{prefix}_ENTRY_COUNT"
    dll_macro = f"{prefix}_DLL_NAME"
    func_macro = f"{prefix}_FUNCTION_NAME"
    arch_macro = f"{prefix}_ARCH"

    guard = f"{prefix}_H"

    lines: list[str] = []

    # Header prologue + guard
    lines.append(f"/* Auto-generated WOFF header for {dll} ! {func} ! {arch}. */\n")
    lines.append(f"#ifndef {guard}\n")
    lines.append(f"#define {guard}\n\n")
    lines.append("#include <stdint.h>\n")
    lines.append("#include <stddef.h>\n\n")

    # Basic metadata
    lines.append(f'#define {dll_macro}  "{dll_c}"\n')
    lines.append(f'#define {func_macro} "{func_c}"\n')
    lines.append(f'#define {arch_macro} "{arch_c}"\n\n')

    # Type definition (namespaced)
    lines.append("/* Per-build offset entry. */\n")
    lines.append("typedef struct {\n")
    lines.append("    uint32_t major;\n")
    lines.append("    uint32_t minor;\n")
    lines.append("    uint64_t rva;\n")
    lines.append("    uint64_t file_offset;\n")
    lines.append(f"}} {entry_t};\n\n")

    # Entries
    lines.append(f"static const {entry_t} {entries_array}[] = {{\n")
    for build in builds_sorted:
        rva, file_off, matched = offsets[build]
        major, minor = _build_key(build)

        lines.append(
            "    { "
            f"{major}u, {minor}u, "
            f"0x{rva:X}ULL, 0x{file_off:X}ULL"
            f" }}, /* {build} ({matched}) */\n"
        )
    lines.append("};\n\n")

    lines.append(
        f"static const size_t {entry_count_macro} = "
        f"sizeof({entries_array}) / sizeof({entries_array}[0]);\n\n"
    )

    lines.append(f"#endif /* {guard} */\n")

    output.write_text("".join(lines), encoding="utf-8")
