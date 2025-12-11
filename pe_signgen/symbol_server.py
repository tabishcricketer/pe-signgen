"""Microsoft Symbol Server utilities."""

from __future__ import annotations

from pathlib import Path

from .constants import MS_SYMBOL_SERVER
from .pe_parsing import CodeViewRSDS, CodeViewNB10, CodeViewInfo, parse_codeview


def compute_pe_url(pe_name: str, timestamp: int, virtual_size: int) -> str:
    """
    Compute the symbol server URL for a PE file.

    Args:
        pe_name: PE filename (e.g., "ntdll.dll")
        timestamp: PE timestamp from header
        virtual_size: PE virtual size from optional header

    Returns:
        Full URL to download the PE from symbol server
    """
    # Timestamp: 8 hex digits, uppercase
    ts_hex = f"{timestamp & 0xFFFFFFFF:08X}"
    # Size: lowercase hex, no padding
    size_hex = f"{virtual_size:x}"

    return f"{MS_SYMBOL_SERVER}/{pe_name}/{ts_hex}{size_hex}/{pe_name}"


def compute_pdb_url(pdb_name: str, guid: str, age: int) -> str:
    """
    Compute the symbol server URL for a PDB file.

    Args:
        pdb_name: PDB filename (e.g., "ntdll.pdb")
        guid: GUID as uppercase hex string without dashes
        age: PDB age

    Returns:
        Full URL to download the PDB from symbol server
    """
    # Age: lowercase hex
    age_hex = f"{age:x}"

    return f"{MS_SYMBOL_SERVER}/{pdb_name}/{guid}{age_hex}/{pdb_name}"


def compute_pdb_url_from_pe(pe_data: bytes) -> tuple[str, CodeViewInfo]:
    """
    Parse PE and compute PDB download URL.

    Args:
        pe_data: Raw PE file bytes

    Returns:
        Tuple of (pdb_url, codeview_info)

    Raises:
        PEParseError: If PE is invalid
        CodeViewNotFoundError: If no CodeView info found
    """
    info = parse_codeview(pe_data)

    if isinstance(info, CodeViewRSDS):
        url = compute_pdb_url(info.pdb_name, info.guid, info.age)
    else:
        # NB10 format - use timestamp instead of GUID
        url = f"{MS_SYMBOL_SERVER}/{info.pdb_name}/{info.timestamp:08X}{info.age:x}/{info.pdb_name}"

    return url, info


def get_pe_url_for_entry(dll_name: str, entry: dict) -> str:
    """
    Compute PE download URL from winbindex entry.

    Args:
        dll_name: DLL name (with or without extension)
        entry: Winbindex entry dictionary

    Returns:
        Full URL to download the PE
    """
    from .pe_parsing import extract_pe_info

    # Ensure .dll extension
    if not dll_name.lower().endswith(".dll"):
        dll_name = f"{dll_name}.dll"

    timestamp, virtual_size = extract_pe_info(entry)
    return compute_pe_url(dll_name, timestamp, virtual_size)
