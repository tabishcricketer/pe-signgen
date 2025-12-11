"""Signature generation for PE functions."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

import pefile

from .constants import (
    DEFAULT_MIN_SIGNATURE_LENGTH,
    DEFAULT_MAX_SIGNATURE_LENGTH,
    SIGNATURE_LENGTH_STEP,
)
from .pe_parsing import get_relocations_in_range
from .symbols import find_function


def bytes_to_signature(
    data: bytes,
    relocated_offsets: set[int],
    base_offset: int,
) -> str:
    """
    Convert bytes to IDA-style signature with wildcards.

    Args:
        data: Raw bytes
        relocated_offsets: Set of file offsets that have relocations
        base_offset: Starting file offset of data

    Returns:
        Space-separated hex string with ?? for wildcards
    """
    parts = []
    for i, byte in enumerate(data):
        if base_offset + i in relocated_offsets:
            parts.append("??")
        else:
            parts.append(f"{byte:02X}")
    return " ".join(parts)


def parse_signature(sig: str) -> tuple[bytes, bytes]:
    """
    Parse signature string to pattern and mask bytes.

    Args:
        sig: Space-separated hex string with ?? wildcards

    Returns:
        Tuple of (pattern_bytes, mask_bytes)
        - pattern_bytes: Raw bytes (wildcards as 0x00)
        - mask_bytes: Packed bits (1=match, 0=wildcard, LSB first)
    """
    parts = sig.split()
    pattern = bytearray()
    mask_bits: list[int] = []

    for part in parts:
        if part == "??":
            pattern.append(0x00)
            mask_bits.append(0)
        else:
            pattern.append(int(part, 16))
            mask_bits.append(1)

    # Pack mask bits into bytes
    mask = bytearray()
    for i in range(0, len(mask_bits), 8):
        byte = 0
        for j in range(min(8, len(mask_bits) - i)):
            if mask_bits[i + j]:
                byte |= 1 << j
        mask.append(byte)

    return bytes(pattern), bytes(mask)


def _build_skip_table(pattern: bytes, mask: list[bool]) -> list[int]:
    """Build Boyer-Moore-like skip table for pattern."""
    length = len(pattern)
    skip = [length] * 256

    for i in range(length - 1):
        if mask[i]:
            skip[pattern[i]] = length - 1 - i

    return skip


def _is_pattern_unique_optimized(
    data: bytes,
    pattern: bytes,
    mask: list[bool],
    expected_offset: int,
) -> bool:
    """
    Check if pattern is unique in data using optimized search.

    Uses a simplified Boyer-Moore approach for non-wildcard bytes.
    """
    length = len(pattern)
    data_len = len(data)

    if length == 0 or data_len < length:
        return False

    # Find first non-wildcard byte from the end (anchor)
    anchor_idx = -1
    for i in range(length - 1, -1, -1):
        if mask[i]:
            anchor_idx = i
            break

    if anchor_idx < 0:
        # All wildcards - can't be unique
        return False

    anchor_byte = pattern[anchor_idx]
    skip = _build_skip_table(pattern, mask)

    matches = 0
    match_offset = -1
    i = length - 1

    while i < data_len:
        # Quick check at anchor position
        j = length - 1
        k = i

        while j >= 0:
            if mask[j] and data[k] != pattern[j]:
                break
            j -= 1
            k -= 1

        if j < 0:
            # Full match
            found_at = i - length + 1
            matches += 1
            if matches > 1:
                return False
            if found_at != expected_offset:
                return False
            match_offset = found_at
            i += 1
        else:
            # Skip based on mismatched byte
            i += max(1, skip[data[i]] if mask[length - 1] else 1)

    return matches == 1 and match_offset == expected_offset


def generate_signature(
    pe_path: str,
    pdb_path: str,
    func_name: str,
    *,
    min_length: int = DEFAULT_MIN_SIGNATURE_LENGTH,
    max_length: int = DEFAULT_MAX_SIGNATURE_LENGTH,
) -> tuple[str, int, str, int]:
    """
    Generate a unique signature for a function.

    Args:
        pe_path: Path to PE file
        pdb_path: Path to PDB file
        func_name: Function name
        min_length: Minimum signature length
        max_length: Maximum signature length

    Returns:
        Tuple of (signature, length, matched_name, rva)
    """
    # Find function location
    file_offset, rva, matched = find_function(pe_path, pdb_path, func_name)

    # Load PE and data
    pe = pefile.PE(pe_path, fast_load=True)
    pe.parse_data_directories()
    data = Path(pe_path).read_bytes()

    # Try increasing lengths until unique
    for length in range(min_length, max_length + 1, SIGNATURE_LENGTH_STEP):
        if file_offset + length > len(data):
            length = len(data) - file_offset
            if length < min_length:
                break

        chunk = data[file_offset : file_offset + length]
        relocs = get_relocations_in_range(pe, file_offset, length)
        mask = [file_offset + i not in relocs for i in range(length)]

        if _is_pattern_unique_optimized(data, chunk, mask, file_offset):
            sig = bytes_to_signature(chunk, relocs, file_offset)
            return sig, length, matched, rva

        if file_offset + length >= len(data):
            break

    # Fallback: return max length (may not be unique)
    length = min(max_length, len(data) - file_offset)
    chunk = data[file_offset : file_offset + length]
    relocs = get_relocations_in_range(pe, file_offset, length)
    sig = bytes_to_signature(chunk, relocs, file_offset)

    return sig, length, matched, rva


def group_by_signature(
    results: dict[str, tuple[str, int, str, int]],
) -> dict[str, list[str]]:
    """
    Group builds by their signature.

    Args:
        results: Dict mapping build -> (signature, length, matched, rva)

    Returns:
        Dict mapping signature -> list of builds
    """
    groups: dict[str, list[str]] = defaultdict(list)

    for build, (sig, _length, _matched, _rva) in results.items():
        groups[sig].append(build)

    return dict(groups)
