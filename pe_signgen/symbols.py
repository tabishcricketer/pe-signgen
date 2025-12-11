"""Symbol resolution for PE files."""
from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING

import winpdb_rs

from .exceptions import SymbolNotFoundError
from .logging_config import log_debug

if TYPE_CHECKING:
    import pefile


_STDCALL_RE = re.compile(r"@\d+$")


def _canonicalize(name: str) -> set[str]:
    """
    Generate canonical variants of a symbol name.
    
    Windows symbols may appear with different decorations:
    - Leading underscore (x86 C calling convention)
    - Trailing @N (stdcall decoration)
    - Case variations
    
    Args:
        name: Function name to canonicalize
        
    Returns:
        Set of name variants to search for
        
    Examples:
        >>> _canonicalize("CreateFileW")
        {'CreateFileW', 'createfilew', '_CreateFileW', '_createfilew'}
        >>> _canonicalize("_NtCreateFile@20")
        {'_NtCreateFile@20', '_ntcreatefile@20', 'NtCreateFile@20', 
         'ntcreatefile@20', '_NtCreateFile', '_ntcreatefile', 
         'NtCreateFile', 'ntcreatefile'}
    """
    variants = {name, name.lower()}
    
    # Strip underscore prefix (x86 C calling convention)
    if name.startswith("_"):
        stripped = name[1:]
        variants.update({stripped, stripped.lower()})
    
    # Strip stdcall decoration (@N suffix)
    for base in list(variants):
        clean = _STDCALL_RE.sub("", base)
        if clean != base:
            variants.add(clean)
            variants.add(clean.lower())
    
    return variants


def _find_in_exports(pe: pefile.PE, func_name: str) -> tuple[int, str] | None:
    """
    Find function RVA in PE export table.
    
    This is the fastest lookup method as it doesn't require PDB files.
    Only works for exported functions.
    
    Args:
        pe: Parsed PE file
        func_name: Function name to find
        
    Returns:
        Tuple of (rva, matched_name) if found, None otherwise
    """
    try:
        exports = pe.DIRECTORY_ENTRY_EXPORT.symbols
    except AttributeError:
        return None
    
    variants = _canonicalize(func_name)
    variant_lower = {v.lower() for v in variants}
    
    for sym in exports:
        if not sym.name:
            continue
        
        try:
            name = sym.name.decode("utf-8", errors="replace")
        except AttributeError:
            name = str(sym.name)
        
        name_lower = name.lower()
        
        # Exact match (case-insensitive)
        if name_lower in variant_lower:
            return sym.address, name
        
        # Prefix match for decorated names (e.g., @N suffix variations)
        for v in variant_lower:
            if (name_lower.startswith(v) or v.startswith(name_lower)) and ("@" in func_name):
                return sym.address, name
    
    return None


def _find_in_pdb(pdb_path: str, func_name: str) -> tuple[int, int, int, str] | None:
    """
    Find symbol using winpdb_rs library.
    
    Args:
        pdb_path: Path to PDB file
        func_name: Function name to find
        
    Returns:
        Tuple of (segment, offset, rva, matched_name) if found, None otherwise
        
    Note:
        Uses the winpdb_rs Rust library for reliable PDB parsing.
        This handles all PDB format variations correctly.
    """
    try:
        result = winpdb_rs.get_function_info(pdb_path, func_name)
        if result is not None:
            segment, offset, rva, matched = result
            log_debug(f"PDB lookup success: {matched} at segment={segment} offset=0x{offset:x} rva=0x{rva:x}")
            return segment, offset, rva, matched
    except (OSError, IOError) as e:
        log_debug(f"PDB lookup I/O error: {e}")
    except (ValueError, TypeError) as e:
        log_debug(f"PDB lookup parse error: {e}")
    except Exception as e:
        log_debug(f"PDB lookup unexpected error: {type(e).__name__}: {e}")
    
    return None


def _rva_to_file_offset(pe: pefile.PE, rva: int) -> int:
    """
    Convert RVA to file offset using PE sections.
    
    Args:
        pe: Parsed PE file
        rva: Relative Virtual Address
        
    Returns:
        File offset
        
    Raises:
        ValueError: If RVA is not in any section
    """
    # Try pefile's built-in method first
    try:
        return pe.get_offset_from_rva(rva)
    except (AttributeError, ValueError):
        pass
    
    # Manual fallback - search sections
    if not hasattr(pe, 'sections') or not pe.sections:
        raise ValueError(f"RVA 0x{rva:x} cannot be converted: no sections in PE")
    
    for section in pe.sections:
        start = section.VirtualAddress
        size = section.Misc_VirtualSize
        if start <= rva < start + size:
            return section.PointerToRawData + (rva - start)
    
    raise ValueError(f"RVA 0x{rva:x} not in any section")


def find_function(
    pe_path: str,
    pdb_path: str,
    func_name: str,
) -> tuple[int, int, str]:
    """
    Find a function's file offset and RVA.
    
    Resolution order:
    1. PE export table (fastest, no PDB needed)
    2. PDB file using winpdb_rs library (most reliable)
    
    Args:
        pe_path: Path to PE file
        pdb_path: Path to PDB file
        func_name: Function name to find
        
    Returns:
        Tuple of (file_offset, rva, matched_name)
        
    Raises:
        FileNotFoundError: If PE file doesn't exist
        SymbolNotFoundError: If symbol not found in exports or PDB
        
    Examples:
        >>> file_off, rva, name = find_function("ntdll.dll", "ntdll.pdb", "NtCreateFile")
        >>> print(f"Found {name} at file offset 0x{file_off:x}, RVA 0x{rva:x}")
    """
    pe_path_obj = Path(pe_path)
    if not pe_path_obj.exists():
        raise FileNotFoundError(pe_path)
    
    # Parse PE file
    import pefile
    pe = pefile.PE(pe_path, fast_load=True)
    pe.parse_data_directories()
    
    # Try export table (fastest)
    export_result = _find_in_exports(pe, func_name)
    if export_result is not None:
        rva, matched = export_result
        file_offset = _rva_to_file_offset(pe, rva)
        log_debug(f"Found {matched} in exports at RVA 0x{rva:x}")
        return file_offset, rva, matched
    
    # Try PDB file
    pdb_path_obj = Path(pdb_path)
    if not pdb_path_obj.exists():
        raise SymbolNotFoundError(
            func_name, 
            f"Not in exports and PDB not found at {pdb_path}"
        )
    
    pdb_result = _find_in_pdb(pdb_path, func_name)
    if pdb_result is not None:
        segment, offset, rva, matched = pdb_result
        
        # If RVA is 0, compute it from segment:offset
        # (Some PDB formats store segment:offset instead of RVA)
        if rva == 0 and segment > 0 and segment <= len(pe.sections):
            section = pe.sections[segment - 1]
            rva = section.VirtualAddress + offset
            log_debug(f"Computed RVA 0x{rva:x} from segment {segment}, offset 0x{offset:x}")
        
        file_offset = _rva_to_file_offset(pe, rva)
        return file_offset, rva, matched
    
    # Symbol not found in any source
    raise SymbolNotFoundError(func_name, pdb_path)


def get_all_symbols(pdb_path: str) -> list:
    """
    Get all public symbols from a PDB file.
    
    Args:
        pdb_path: Path to PDB file
        
    Returns:
        List of symbol information objects from winpdb_rs,
        or empty list if PDB cannot be parsed.
        
    Note:
        Uses winpdb_rs library for reliable parsing.
        Returns empty list on any error to avoid breaking callers.
    """
    try:
        result = winpdb_rs.get_all_symbols(pdb_path)
        return result.symbols
    except (OSError, IOError, AttributeError, ValueError) as e:
        log_debug(f"Failed to get symbols from {pdb_path}: {e}")
        return []
