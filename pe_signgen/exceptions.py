"""Custom exceptions for pe-signgen."""
from __future__ import annotations


class PESignGenError(Exception):
    """Base exception for all pe-signgen errors."""
    pass


class DownloadError(PESignGenError):
    """Failed to download a file."""
    pass


class PEParseError(PESignGenError):
    """Failed to parse a PE file."""
    pass


class PDBParseError(PESignGenError):
    """Failed to parse a PDB file."""
    pass


class SymbolNotFoundError(PESignGenError):
    """Symbol not found in PDB or export table."""
    def __init__(self, symbol: str, pdb_path: str | None = None):
        self.symbol = symbol
        self.pdb_path = pdb_path
        msg = f"Symbol '{symbol}' not found"
        if pdb_path:
            msg += f" in {pdb_path}"
        super().__init__(msg)


class CodeViewNotFoundError(PEParseError):
    """No CodeView debug information in PE file."""
    pass


class WinbindexError(PESignGenError):
    """Error with winbindex data."""
    pass


class GitError(PESignGenError):
    """Git operation failed."""
    pass


class CacheError(PESignGenError):
    """Cache read/write error."""
    pass


class InvalidFormatError(PESignGenError):
    """Invalid binary format (WSIG/WOFF)."""
    pass


class NetworkError(PESignGenError):
    """Network operation failed."""
    pass


class FileVerificationError(PESignGenError):
    """File verification failed (corrupt or incomplete)."""
    pass


class StructParseError(PEParseError):
    """Failed to unpack binary struct."""
    pass


class RelocationError(PEParseError):
    """Error processing PE relocations."""
    pass
