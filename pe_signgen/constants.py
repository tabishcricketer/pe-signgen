"""Constants and configuration for pe-signgen."""

from __future__ import annotations

import os
import sys
from pathlib import Path

# =============================================================================
# Network Configuration
# =============================================================================

MS_SYMBOL_SERVER = "https://msdl.microsoft.com/download/symbols"
WINBINDEX_REPO = "https://github.com/m417z/winbindex.git"
WINBINDEX_BRANCH = "gh-pages"

HTTP_TIMEOUT_SECONDS = 120
HTTP_CHUNK_SIZE = 1 << 20  # 1 MB
MAX_DOWNLOAD_RETRIES = 3
GIT_TIMEOUT_SECONDS = 600

# =============================================================================
# PE Format Constants
# =============================================================================

DOS_MAGIC = b"MZ"
PE_MAGIC = b"PE\0\0"

# Optional header magic values
PE32_MAGIC = 0x10B
PE32PLUS_MAGIC = 0x20B

# Minimum size for optional header to contain data directories
PE32_OPTIONAL_HEADER_MIN_SIZE = 96
PE32PLUS_OPTIONAL_HEADER_MIN_SIZE = 112

# Data directory indices
DATA_DIR_EXPORT = 0
DATA_DIR_IMPORT = 1
DATA_DIR_DEBUG = 6

# Debug types
DEBUG_TYPE_CODEVIEW = 2

# CodeView signatures
CODEVIEW_RSDS = b"RSDS"
CODEVIEW_NB10 = b"NB10"

# RSDS header size (signature + GUID + age)
CODEVIEW_RSDS_HEADER_SIZE = 24  # 4 + 16 + 4

# Relocation types we handle
# Many other types exist but are rarely used in modern PE files
IMAGE_REL_BASED_HIGHLOW = 3  # 32-bit relocation
IMAGE_REL_BASED_DIR64 = 10  # 64-bit relocation

# Relocation sizes in bytes
RELOC_SIZE_32BIT = 4
RELOC_SIZE_64BIT = 8

# Section header size
SECTION_HEADER_SIZE = 40

# =============================================================================
# Signature Generation
# =============================================================================

DEFAULT_MIN_SIGNATURE_LENGTH = 16
DEFAULT_MAX_SIGNATURE_LENGTH = 128
# Align to DWORD boundaries for efficiency and typical instruction alignment
SIGNATURE_LENGTH_STEP = 4

# =============================================================================
# PDB Scanning Constants
# =============================================================================

# Maximum bytes to scan when looking for PDB path in debug directory
PDB_MAX_PATH_SCAN = 512
# Maximum expected PDB path length (Windows MAX_PATH is 260)
PDB_MAX_PATH_LENGTH = 240

# =============================================================================
# Cache Configuration
# =============================================================================

# Increment when cache format changes to invalidate old caches
CACHE_SCHEMA_VERSION = 2


def get_cache_dir() -> Path:
    """
    Get platform-appropriate cache directory.

    Priority order:
    1. PE_SIGNGEN_CACHE environment variable
    2. Platform-specific default:
       - Windows: %LOCALAPPDATA%\\pe-signgen or %USERPROFILE%\\AppData\\Local\\pe-signgen
       - macOS: ~/Library/Caches/pe-signgen
       - Linux/Unix: $XDG_CACHE_HOME/pe-signgen or ~/.cache/pe-signgen

    Returns:
        Path to cache directory (may not exist yet)
    """
    # Allow override via environment variable
    env_cache = os.environ.get("PE_SIGNGEN_CACHE")
    if env_cache:
        return Path(env_cache).expanduser().resolve()

    # Platform-specific defaults
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA")
        if base:
            return Path(base) / "pe-signgen"
        return Path.home() / "AppData" / "Local" / "pe-signgen"
    elif sys.platform == "darwin":
        return Path.home() / "Library" / "Caches" / "pe-signgen"
    else:  # Linux and other Unix-like systems
        xdg = os.environ.get("XDG_CACHE_HOME")
        if xdg:
            return Path(xdg) / "pe-signgen"
        return Path.home() / ".cache" / "pe-signgen"


# Derived cache paths
CACHE_DIR = get_cache_dir()
WINBINDEX_LOCAL = CACHE_DIR / "winbindex_data"
WINBINDEX_DATA_PATH = WINBINDEX_LOCAL / "data" / "by_filename_compressed"
DLL_CACHE_DIR = CACHE_DIR / "dlls"
PDB_CACHE_DIR = CACHE_DIR / "pdbs"
SIGNATURE_CACHE_DIR = CACHE_DIR / "signatures"

# =============================================================================
# Architecture Mappings
# =============================================================================

# Architecture aliases for flexible user input
ARCH_ALIASES: dict[str, set[str]] = {
    "x64": {"x64", "amd64"},
    "amd64": {"x64", "amd64"},
    "i386": {"x86", "i386"},
    "arm64": {"arm64", "aarch64"},
    "wow64": {"wow64", "x86", "i386"},  # WoW64 uses x86 binaries
}

# PE machine type values (from IMAGE_FILE_HEADER.Machine)
MACHINE_AMD64 = 0x8664  # x64 / AMD64 / x86-64
MACHINE_I386 = 0x14C  # x86 / i386 / 32-bit Intel
MACHINE_ARM64 = 0xAA64  # ARM64 / AArch64

# =============================================================================
# Binary Format Constants (WSIG/WOFF)
# =============================================================================

# Custom binary format magic numbers
WSIG_MAGIC = b"WSO\0"  # Windows Signature Offsets
WOFF_MAGIC = b"WOF\0"  # Windows Offsets File
FORMAT_VERSION = 1

# Architecture encoding for binary formats
ARCH_CODE_MAP: dict[str, int] = {
    "x86": 0,
    "x64": 1,
    "arm64": 2,
    "wow64": 3,
}

# =============================================================================
# Windows Version Mappings
# =============================================================================

# Friendly names to build number mappings
# Build numbers from: https://en.wikipedia.org/wiki/List_of_Microsoft_Windows_versions
WINDOWS_VERSION_ALIASES: dict[str, tuple[int, int]] = {
    # Windows 10
    "win10": (10240, 0),
    "windows10": (10240, 0),
    # Windows 11
    "win11": (22000, 0),
    "windows11": (22000, 0),
}
