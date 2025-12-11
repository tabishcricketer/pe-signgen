"""Data models for pe-signgen."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class SignatureJob:
    """Job specification for signature generation worker."""
    dll_path: Path
    pdb_path: Path
    func_name: str
    min_length: int
    max_length: int


@dataclass(frozen=True)
class SignatureResult:
    """Result from signature generation."""
    build: str
    signature: str | None
    length: int | None
    matched_name: str | None
    rva: int | None
    error: str | None
    
    @property
    def success(self) -> bool:
        """Whether signature generation succeeded."""
        return self.signature is not None
    
    def as_tuple(self) -> tuple[str, int, str, int] | None:
        """Convert to legacy tuple format (signature, length, matched, rva)."""
        if self.success:
            return (self.signature, self.length, self.matched_name, self.rva)
        return None


@dataclass(frozen=True)
class OffsetJob:
    """Job specification for offset generation worker."""
    dll_path: Path
    pdb_path: Path
    func_name: str


@dataclass(frozen=True)
class OffsetResult:
    """Result from offset generation."""
    build: str
    rva: int | None
    file_offset: int | None
    matched_name: str | None
    error: str | None
    
    @property
    def success(self) -> bool:
        """Whether offset generation succeeded."""
        return self.rva is not None
    
    def as_tuple(self) -> tuple[int, int, str] | None:
        """Convert to legacy tuple format (rva, file_offset, matched)."""
        if self.success:
            return (self.rva, self.file_offset, self.matched_name)
        return None


@dataclass(frozen=True)
class DownloadJob:
    """Job specification for download worker."""
    dll_name: str
    build: str
    entry: dict[str, Any]
    dll_dir: Path
    pdb_dir: Path


@dataclass(frozen=True)
class DownloadResult:
    """Result from download operation."""
    build: str
    dll_path: Path | None
    pdb_path: Path | None
    error: str | None
    
    @property
    def success(self) -> bool:
        """Whether download succeeded."""
        return self.dll_path is not None and self.error is None
