"""
pe-signgen: Generate unique byte signatures for Windows PE functions.

This package downloads PE files and their PDB symbols from Microsoft's
symbol server, then generates cross-version compatible byte signatures
for specified functions.

"""

from __future__ import annotations

__version__ = "0.3.0"
__author__ = "pe-signgen contributors"

from .exceptions import (
    PESignGenError,
    DownloadError,
    PEParseError,
    PDBParseError,
    SymbolNotFoundError,
    CodeViewNotFoundError,
    WinbindexError,
    GitError,
    CacheError,
    InvalidFormatError,
)
from .signatures import generate_signature, group_by_signature, parse_signature
from .symbols import find_function, get_all_symbols
from .pipeline import download_all
from .cache import SignatureCache, BuildSignature, load_cache, save_cache
from .pe_parsing import parse_codeview, CodeViewRSDS, CodeViewNB10

__all__ = [
    # Version
    "__version__",
    # Exceptions
    "PESignGenError",
    "DownloadError",
    "PEParseError",
    "PDBParseError",
    "SymbolNotFoundError",
    "CodeViewNotFoundError",
    "WinbindexError",
    "GitError",
    "CacheError",
    "InvalidFormatError",
    # Core functions
    "generate_signature",
    "group_by_signature",
    "parse_signature",
    "find_function",
    "get_all_symbols",
    "download_all",
    # Cache
    "SignatureCache",
    "BuildSignature",
    "load_cache",
    "save_cache",
    # PE parsing
    "parse_codeview",
    "CodeViewRSDS",
    "CodeViewNB10",
]
