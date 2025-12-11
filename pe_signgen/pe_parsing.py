"""PE and PDB binary parsing utilities."""
from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


from .constants import (
    DOS_MAGIC,
    PE_MAGIC,
    PE32_MAGIC,
    PE32PLUS_MAGIC,
    PE32_OPTIONAL_HEADER_MIN_SIZE,
    DEBUG_TYPE_CODEVIEW,
    CODEVIEW_RSDS,
    CODEVIEW_NB10,
    IMAGE_REL_BASED_HIGHLOW,
    IMAGE_REL_BASED_DIR64,
    RELOC_SIZE_32BIT,
    RELOC_SIZE_64BIT,
    SECTION_HEADER_SIZE,
    MACHINE_AMD64,
    MACHINE_I386,
    MACHINE_ARM64,
    ARCH_ALIASES,
    PDB_MAX_PATH_SCAN,
    PDB_MAX_PATH_LENGTH,
)
from .exceptions import PEParseError, CodeViewNotFoundError, StructParseError, RelocationError
from .logging_config import log_debug 

try:
    import pefile
except ImportError:
    pefile = None


@dataclass(frozen=True)
class CodeViewRSDS:
    """RSDS CodeView debug information."""
    pdb_name: str
    guid: str
    age: int
    
    def get_symbol_server_path(self) -> str:
        """Get the path component for Microsoft symbol server."""
        return f"{self.pdb_name}/{self.guid}{self.age:x}/{self.pdb_name}"


@dataclass(frozen=True)
class CodeViewNB10:
    """NB10 CodeView debug information (legacy)."""
    pdb_name: str
    timestamp: int
    age: int


CodeViewInfo = CodeViewRSDS | CodeViewNB10


def _rva_to_file_offset(
    pe_data: bytes,
    rva: int,
    section_table_offset: int,
    num_sections: int,
) -> int | None:
    """
    Convert RVA to file offset using section table.
    
    Args:
        pe_data: Raw PE file bytes
        rva: Relative Virtual Address to convert
        section_table_offset: Offset to first section header
        num_sections: Number of sections
        
    Returns:
        File offset or None if RVA not in any section
    """
    for i in range(num_sections):
        offset = section_table_offset + SECTION_HEADER_SIZE * i
        if offset + SECTION_HEADER_SIZE > len(pe_data):
            break
        
        # Section header layout: Name[8], VirtualSize[4], VirtualAddress[4], 
        #                        SizeOfRawData[4], PointerToRawData[4], ...
        virt_size, virt_addr, raw_size, raw_ptr = struct.unpack_from(
            "<IIII", pe_data, offset + 8
        )
        
        section_end = virt_addr + max(virt_size, raw_size)
        if virt_addr <= rva < section_end:
            return raw_ptr + (rva - virt_addr)
    
    return None


def parse_codeview(pe_data: bytes) -> CodeViewInfo:
    """
    Parse CodeView debug information from PE file.
    
    Args:
        pe_data: Raw PE file bytes
        
    Returns:
        CodeViewRSDS or CodeViewNB10 info
        
    Raises:
        PEParseError: If PE structure is invalid
        CodeViewNotFoundError: If no CodeView info found
    """
    # Validate DOS header
    if len(pe_data) < 64 or pe_data[:2] != DOS_MAGIC:
        raise PEParseError("Invalid DOS header")
    
    # Get PE header offset
    e_lfanew = struct.unpack_from("<I", pe_data, 0x3C)[0]
    if e_lfanew + 4 > len(pe_data):
        raise PEParseError("Invalid e_lfanew")
    
    # Validate PE signature
    if pe_data[e_lfanew:e_lfanew + 4] != PE_MAGIC:
        raise PEParseError("Invalid PE signature")
    
    # Parse COFF header
    coff_offset = e_lfanew + 4
    if coff_offset + 20 > len(pe_data):
        raise PEParseError("Truncated COFF header")
    
    num_sections = struct.unpack_from("<H", pe_data, coff_offset + 2)[0]
    optional_header_size = struct.unpack_from("<H", pe_data, coff_offset + 16)[0]
    
    if optional_header_size < PE32_OPTIONAL_HEADER_MIN_SIZE:
        raise PEParseError(f"Optional header too small: {optional_header_size}")
    
    # Parse optional header
    optional_offset = coff_offset + 20
    magic = struct.unpack_from("<H", pe_data, optional_offset)[0]
    
    if magic == PE32_MAGIC:
        data_dir_offset = optional_offset + 96
    elif magic == PE32PLUS_MAGIC:
        data_dir_offset = optional_offset + 112
    else:
        raise PEParseError(f"Unknown optional header magic: {magic:#x}")
    
    # Get debug directory RVA and size (6th data directory)
    debug_dir_offset = data_dir_offset + 6 * 8
    if debug_dir_offset + 8 > len(pe_data):
        raise PEParseError("Truncated data directories")
    
    debug_rva, debug_size = struct.unpack_from("<II", pe_data, debug_dir_offset)
    section_table_offset = optional_offset + optional_header_size
    
    # Helper for RVA conversion
    def rva_to_offset(rva: int) -> int | None:
        return _rva_to_file_offset(pe_data, rva, section_table_offset, num_sections)
    
    # Try to parse debug directory
    if debug_rva and debug_size:
        debug_offset = rva_to_offset(debug_rva)
        if debug_offset is not None and debug_offset + debug_size <= len(pe_data):
            result = _parse_debug_directory(
                pe_data, debug_offset, debug_size, rva_to_offset
            )
            if result is not None:
                return result
    
    # Fallback: scan for RSDS signature
    result = _scan_for_rsds(pe_data)
    if result is not None:
        return result
    
    raise CodeViewNotFoundError("No CodeView debug information found")


def _parse_debug_directory(
    pe_data: bytes,
    debug_offset: int,
    debug_size: int,
    rva_to_offset: Callable[[int], int | None],
) -> CodeViewInfo | None:
    """Parse debug directory entries."""
    num_entries = debug_size // 28
    
    for i in range(num_entries):
        entry_offset = debug_offset + i * 28
        if entry_offset + 28 > len(pe_data):
            break
        
        # Debug directory entry structure
        (
            _characteristics,
            _timestamp,
            _major_version,
            _minor_version,
            debug_type,
            size_of_data,
            address_of_raw_data,
            pointer_to_raw_data,
        ) = struct.unpack_from("<IIHHIIII", pe_data, entry_offset)
        
        if debug_type != DEBUG_TYPE_CODEVIEW or size_of_data < 16:
            continue
        
        # Determine data location
        data_ptr = pointer_to_raw_data
        if not (0 <= data_ptr < len(pe_data)):
            data_ptr = rva_to_offset(address_of_raw_data) or 0
        
        if data_ptr + size_of_data > len(pe_data):
            continue
        
        result = _parse_codeview_data(pe_data, data_ptr, size_of_data)
        if result is not None:
            return result
    
    return None


def _parse_codeview_data(
    pe_data: bytes,
    offset: int,
    size: int,
) -> CodeViewInfo | None:
    """Parse CodeView data at given offset."""
    signature = pe_data[offset:offset + 4]
    
    if signature == CODEVIEW_RSDS and size >= 24:
        # RSDS format: signature[4], GUID[16], age[4], path[...]
        guid_bytes = pe_data[offset + 4:offset + 20]
        age = struct.unpack_from("<I", pe_data, offset + 20)[0]
        
        # Parse path
        path_end = min(offset + 24 + size, len(pe_data))
        path_data = pe_data[offset + 24:path_end]
        pdb_path = path_data.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        pdb_name = Path(pdb_path).name
        
        # Format GUID as uppercase hex without dashes
        guid = _format_guid(guid_bytes)
        
        return CodeViewRSDS(pdb_name=pdb_name, guid=guid, age=age)
    
    elif signature == CODEVIEW_NB10 and size >= 16:
        # NB10 format: signature[4], offset[4], timestamp[4], age[4], path[...]
        timestamp = struct.unpack_from("<I", pe_data, offset + 8)[0]
        age = struct.unpack_from("<I", pe_data, offset + 12)[0]
        
        path_end = min(offset + 16 + size, len(pe_data))
        path_data = pe_data[offset + 16:path_end]
        pdb_path = path_data.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        pdb_name = Path(pdb_path).name
        
        return CodeViewNB10(pdb_name=pdb_name, timestamp=timestamp, age=age)
    
    return None


def _scan_for_rsds(pe_data: bytes) -> CodeViewRSDS | None:
    """
    Fallback: scan entire file for RSDS signature.
    
    This is used when the debug directory is missing or corrupted.
    """
    pos = 0
    while True:
        pos = pe_data.find(CODEVIEW_RSDS, pos)
        if pos < 0:
            break
        
        if pos + 24 > len(pe_data):
            break
        
        try:
            guid_bytes = pe_data[pos + 4:pos + 20]
            if len(guid_bytes) < 16:
                pos += 4
                continue
            
            age = struct.unpack("<I", pe_data[pos + 20:pos + 24])[0]
            
            # Try to extract PDB path
            max_tail = min(len(pe_data), pos + 24 + PDB_MAX_PATH_SCAN)
            path_data = pe_data[pos + 24:max_tail]
            
            # Find null terminator
            null_pos = path_data.find(b"\x00")
            if null_pos < 0:
                pos += 4
                continue
            
            pdb_path = path_data[:null_pos].decode("utf-8", errors="replace")
            
            # Validate it looks like a PDB path
            if (pdb_path.lower().endswith(".pdb") and 
                0 < len(pdb_path) <= PDB_MAX_PATH_LENGTH):
                guid = _format_guid(guid_bytes)
                return CodeViewRSDS(
                    pdb_name=Path(pdb_path).name,
                    guid=guid,
                    age=age,
                )
        except (struct.error, UnicodeDecodeError, ValueError):
            pass
        
        pos += 4
    
    return None


def _format_guid(guid_bytes: bytes) -> str:
    """Format GUID bytes as uppercase hex string without dashes."""
    # GUID structure: Data1[4], Data2[2], Data3[2], Data4[8]
    data1 = struct.unpack_from("<I", guid_bytes, 0)[0]
    data2 = struct.unpack_from("<H", guid_bytes, 4)[0]
    data3 = struct.unpack_from("<H", guid_bytes, 6)[0]
    data4 = guid_bytes[8:16]
    
    return (
        f"{data1:08X}"
        f"{data2:04X}"
        f"{data3:04X}"
        f"{''.join(f'{b:02X}' for b in data4)}"
    )


def is_pe_complete(pe_data: bytes) -> bool:
    """
    Check if PE file contains all section data it claims to have.
    
    Args:
        pe_data: Raw PE file bytes
        
    Returns:
        True if file appears structurally complete
    """
    try:
        if len(pe_data) < 64 or pe_data[:2] != DOS_MAGIC:
            return False
        
        e_lfanew = struct.unpack_from("<I", pe_data, 0x3C)[0]
        if e_lfanew + 24 > len(pe_data):
            return False
        
        if pe_data[e_lfanew:e_lfanew + 4] != PE_MAGIC:
            return False
        
        coff_offset = e_lfanew + 4
        num_sections = struct.unpack_from("<H", pe_data, coff_offset + 2)[0]
        optional_header_size = struct.unpack_from("<H", pe_data, coff_offset + 16)[0]
        
        if optional_header_size < PE32_OPTIONAL_HEADER_MIN_SIZE:
            return False
        
        section_table_offset = coff_offset + 20 + optional_header_size
        
        # Find maximum file offset needed
        max_end = 0
        for i in range(num_sections):
            offset = section_table_offset + SECTION_HEADER_SIZE * i
            if offset + SECTION_HEADER_SIZE > len(pe_data):
                return False
            
            raw_size, raw_ptr = struct.unpack_from("<II", pe_data, offset + 16)
            if raw_ptr and raw_size:
                max_end = max(max_end, raw_ptr + raw_size)
        
        return len(pe_data) >= max_end
    
    except (struct.error, IndexError, ValueError):
        return False


def _file_offset_to_rva(pe: "pefile.PE", file_offset: int) -> int | None:
    """
    Convert file offset to RVA using section table.
    
    Args:
        pe: Parsed PE file
        file_offset: File offset to convert
        
    Returns:
        RVA or None if not in any section
    """
    if not hasattr(pe, 'sections') or not pe.sections:
        return None
    
    for section in pe.sections:
        raw_ptr = section.PointerToRawData
        raw_size = section.SizeOfRawData
        
        if raw_ptr <= file_offset < raw_ptr + raw_size:
            # file_offset is in this section
            offset_in_section = file_offset - raw_ptr
            rva = section.VirtualAddress + offset_in_section
            return rva
    
    return None


def get_relocations_in_range(
    pe: "pefile.PE",
    file_offset: int,
    length: int,
) -> set[int]:
    """
    Get set of file offsets that have relocations applied.
    
    Args:
        pe: Parsed PE file (pefile.PE object)
        file_offset: Start of range (file offset)
        length: Length of range
        
    Returns:
        Set of file offsets within range that are relocated
    """
    relocs: set[int] = set()
    
    if not hasattr(pe, "DIRECTORY_ENTRY_BASERELOC"):
        return relocs
    
    # Convert file offset range to RVA range for comparison
    # This is necessary because relocations are stored as RVAs
    start_rva = _file_offset_to_rva(pe, file_offset)
    end_rva = _file_offset_to_rva(pe, file_offset + length - 1)
    
    if start_rva is None or end_rva is None:
        # Can't convert to RVA - fall back to direct file offset checking
        # This is less reliable but better than nothing
        try:
            for block in pe.DIRECTORY_ENTRY_BASERELOC:
                for entry in block.entries:
                    if entry.type == 0:  # IMAGE_REL_BASED_ABSOLUTE (padding)
                        continue
                    
                    try:
                        entry_offset = pe.get_offset_from_rva(entry.rva)
                    except (AttributeError, ValueError):
                        continue
                    
                    if entry_offset is None:
                        continue
                    
                    # Determine relocation size
                    if entry.type == IMAGE_REL_BASED_HIGHLOW:
                        reloc_size = RELOC_SIZE_32BIT
                    elif entry.type == IMAGE_REL_BASED_DIR64:
                        reloc_size = RELOC_SIZE_64BIT
                    else:
                        reloc_size = 1
                    
                    # Add all bytes covered by this relocation
                    for i in range(reloc_size):
                        addr = entry_offset + i
                        if file_offset <= addr < file_offset + length:
                            relocs.add(addr)
        except (AttributeError, TypeError):
            pass
        
        return relocs
    
    # Adjust end_rva to be exclusive (one past the last byte)
    end_rva += 1
    
    try:
        for block in pe.DIRECTORY_ENTRY_BASERELOC:
            for entry in block.entries:
                if entry.type == 0:  # IMAGE_REL_BASED_ABSOLUTE (padding)
                    continue
                
                # Determine relocation size based on type
                if entry.type == IMAGE_REL_BASED_HIGHLOW:
                    reloc_size = RELOC_SIZE_32BIT
                elif entry.type == IMAGE_REL_BASED_DIR64:
                    reloc_size = RELOC_SIZE_64BIT
                else:
                    reloc_size = 1
                
                # Check if this relocation overlaps with our RVA range
                # Relocation spans from entry.rva to entry.rva + reloc_size
                reloc_end_rva = entry.rva + reloc_size
                
                # Check for overlap: [start_rva, end_rva) and [entry.rva, reloc_end_rva)
                if not (entry.rva < end_rva and reloc_end_rva > start_rva):
                    continue  # No overlap
                
                # This relocation is in our range - convert to file offset
                try:
                    entry_offset = pe.get_offset_from_rva(entry.rva)
                except (AttributeError, ValueError):
                    continue
                
                if entry_offset is None:
                    continue
                
                # Add all bytes of this relocation that fall in our file range
                for i in range(reloc_size):
                    addr = entry_offset + i
                    if file_offset <= addr < file_offset + length:
                        relocs.add(addr)
    
    except (AttributeError, TypeError):
        # Relocations might not be parseable
        pass
    
    return relocs


def match_architecture(entry: dict, arch: str) -> bool:
    """
    Check if a winbindex entry matches the requested architecture.
    
    Args:
        entry: Winbindex entry dictionary
        arch: Requested architecture (x64, arm64, wow64)
        
    Returns:
        True if entry matches the requested architecture
    """
    targets = {arch.lower()}
    targets.update(ARCH_ALIASES.get(arch.lower(), set()))
    
    # Check machineType in fileInfo
    file_info = entry.get("fileInfo") or {}
    machine_type = str(file_info.get("machineType", "")).lower()
    
    if machine_type:
        # Machine type is stored as decimal string
        if str(MACHINE_AMD64) in machine_type and ({"x64", "amd64"} & targets):
            return True
        if str(MACHINE_I386) in machine_type and ({"x86", "i386"} & targets):
            return True
        if str(MACHINE_ARM64) in machine_type and ("arm64" in targets):
            return True
        # If machine type is present but doesn't match, reject
        return False
    
    assembly_info = entry.get("assemblyIdentity") or {}
    for key in ("processorArchitecture", "fileArchitecture", "architecture"):
        value = assembly_info.get(key) or entry.get(key)
        if isinstance(value, str) and value.lower() in targets:
            return True
    
    # If no architecture info found, reject to be safe
    return False


def extract_pe_info(entry: dict) -> tuple[int, int]:
    """
    Extract timestamp and virtual size from winbindex entry.
    
    Args:
        entry: Winbindex entry dictionary
        
    Returns:
        Tuple of (timestamp, virtual_size)
        
    Raises:
        PEParseError: If required fields are missing or invalid
    """
    
    file_info = entry.get("fileInfo") or {}
    
    timestamp = file_info.get("timestamp")
    virtual_size = file_info.get("virtualSize") or file_info.get("imageSize") or file_info.get("size")
    
    if virtual_size is None:
        log_debug(f"Missing virtualSize in fileInfo: {file_info}")
    
    if timestamp is None or virtual_size is None:
        raise PEParseError(
            f"Missing required PE info in winbindex entry: "
            f"timestamp={timestamp}, virtualSize={virtual_size}"
        )
    
    return int(timestamp), int(virtual_size)
