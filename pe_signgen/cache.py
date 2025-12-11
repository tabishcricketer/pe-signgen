"""Signature cache with version-based invalidation and parameter tracking."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, asdict, field
from datetime import datetime
from pathlib import Path
from typing import Any

from .constants import SIGNATURE_CACHE_DIR, CACHE_SCHEMA_VERSION
from .exceptions import CacheError
from .logging_config import log_info, log_warning, log_debug


@dataclass
class BuildSignature:
    """Signature data for a single build."""

    build: str
    major: int
    minor: int
    signature: str
    length: int
    matched_name: str
    rva: int = 0


@dataclass
class CacheParameters:
    """Parameters that affect signature generation."""

    min_length: int
    max_length: int

    def to_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dict."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CacheParameters:
        """Create from JSON dict."""
        return cls(
            min_length=data["min_length"],
            max_length=data["max_length"],
        )

    def matches(self, other: CacheParameters) -> bool:
        """Check if parameters match."""
        return (
            self.min_length == other.min_length and self.max_length == other.max_length
        )

    def __str__(self) -> str:
        """String representation for logging."""
        return f"min={self.min_length},max={self.max_length}"


@dataclass
class SignatureCache:
    """Cache of signatures for a dll+function+arch combination."""

    dll_name: str
    func_name: str
    arch: str
    schema_version: int
    timestamp: str
    parameters: CacheParameters
    signatures: dict[str, BuildSignature] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dict."""
        return {
            "dll_name": self.dll_name,
            "func_name": self.func_name,
            "arch": self.arch,
            "schema_version": self.schema_version,
            "timestamp": self.timestamp,
            "parameters": self.parameters.to_dict(),
            "signatures": {b: asdict(s) for b, s in self.signatures.items()},
            "errors": self.errors,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SignatureCache:
        """Create from JSON dict."""
        sigs = {}
        for build, sig_data in data.get("signatures", {}).items():
            sigs[build] = BuildSignature(**sig_data)

        # Handle old caches without parameters (for backward compatibility)
        if "parameters" in data:
            params = CacheParameters.from_dict(data["parameters"])
        else:
            # Default to old hardcoded values if not present
            from .constants import (
                DEFAULT_MIN_SIGNATURE_LENGTH,
                DEFAULT_MAX_SIGNATURE_LENGTH,
            )

            params = CacheParameters(
                min_length=DEFAULT_MIN_SIGNATURE_LENGTH,
                max_length=DEFAULT_MAX_SIGNATURE_LENGTH,
            )

        return cls(
            dll_name=data["dll_name"],
            func_name=data["func_name"],
            arch=data["arch"],
            schema_version=data.get("schema_version", 1),
            timestamp=data["timestamp"],
            parameters=params,
            signatures=sigs,
            errors=data.get("errors", {}),
        )


def _cache_dir_for(dll: str, func: str, arch: str) -> Path:
    """
    Get cache directory for a specific dll+func+arch.

    Structure: SIGNATURE_CACHE_DIR / arch / {dll_stem}_{safe_func}_{func_hash}

    Args:
        dll: DLL name
        func: Function name
        arch: Architecture (x64, arm64, wow64)

    Returns:
        Path to cache directory

    Examples:
        ntdll, LdrLoadDll, x64 -> .../signatures/x64/ntdll_LdrLoadDll_a1b2c3d4/
        kernel32, CreateFileW, wow64 -> .../signatures/x86/kernel32_CreateFileW_e5f6g7h8/
    """
    dll_stem = Path(dll).stem.lower()

    # Create a safe filename from function name (limit length, remove special chars)
    safe_func = re.sub(r"[^\w\-]", "_", func)[:32]

    # Add hash to handle collisions and very long function names
    func_hash = hashlib.md5(func.encode("utf-8")).hexdigest()[:8]

    # Structure: signatures/x64/ntdll_LdrLoadDll_a1b2c3d4/
    return SIGNATURE_CACHE_DIR / arch / f"{dll_stem}_{safe_func}_{func_hash}"


def load_cache(
    dll: str,
    func: str,
    arch: str,
    min_length: int,
    max_length: int,
) -> SignatureCache | None:
    """
    Load cached signatures if available and valid.

    Args:
        dll: DLL name
        func: Function name
        arch: Architecture
        min_length: Minimum signature length (must match cached value)
        max_length: Maximum signature length (must match cached value)

    Returns:
        SignatureCache if valid cache exists, None otherwise

    Returns None if:
    - Cache doesn't exist
    - Cache schema version doesn't match current version
    - Cache parameters don't match requested parameters
    - Cache is corrupted or invalid
    """
    cache_dir = _cache_dir_for(dll, func, arch)
    cache_file = cache_dir / "signatures.json"

    if not cache_file.exists():
        log_debug(f"No cache found at {cache_file}")
        return None

    try:
        data = json.loads(cache_file.read_text(encoding="utf-8"))
        cache = SignatureCache.from_dict(data)

        # Check schema version
        if cache.schema_version != CACHE_SCHEMA_VERSION:
            log_info(
                f"Cache schema version mismatch "
                f"(cached: {cache.schema_version}, current: {CACHE_SCHEMA_VERSION}), "
                f"invalidating cache"
            )
            return None

        # Check parameters match
        requested_params = CacheParameters(min_length=min_length, max_length=max_length)

        if not cache.parameters.matches(requested_params):
            log_info(
                f"Cache parameters mismatch "
                f"(cached: {cache.parameters}, requested: {requested_params}), "
                f"invalidating cache"
            )
            return None

        log_debug(
            f"Loaded cache from {cache_dir.name}: "
            f"{len(cache.signatures)} signatures, {len(cache.errors)} errors"
        )
        return cache

    except Exception as e:
        log_warning(f"Failed to load cache from {cache_file}: {e}")
        return None


def save_cache(cache: SignatureCache) -> None:
    """
    Save signature cache to disk with validation.

    Uses atomic write to prevent corruption:
    1. Write to temporary file
    2. Validate written data
    3. Atomically replace old cache file

    Args:
        cache: SignatureCache to save

    Raises:
        CacheError: If save or validation fails
    """
    cache_dir = _cache_dir_for(cache.dll_name, cache.func_name, cache.arch)
    cache_dir.mkdir(parents=True, exist_ok=True)

    cache_file = cache_dir / "signatures.json"
    tmp_file = cache_dir / "signatures.json.tmp"

    try:
        # Update schema version and timestamp
        cache.schema_version = CACHE_SCHEMA_VERSION
        cache.timestamp = datetime.now().isoformat()

        # Serialize to JSON with pretty printing
        json_data = json.dumps(cache.to_dict(), indent=2)

        # Validate JSON is well-formed
        try:
            json.loads(json_data)
        except json.JSONDecodeError as e:
            raise CacheError(f"Generated invalid JSON: {e}") from e

        # Write to temporary file
        tmp_file.write_text(json_data, encoding="utf-8")

        # Validate written data can be loaded back
        try:
            SignatureCache.from_dict(json.loads(tmp_file.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            raise CacheError(f"Written cache failed validation: {e}") from e

        # Atomic replace (on POSIX this is atomic, on Windows it's best-effort)
        tmp_file.replace(cache_file)

        log_debug(
            f"Saved cache to {cache_dir.name}: "
            f"{len(cache.signatures)} signatures, params={cache.parameters}"
        )

    except CacheError:
        # Clean up temporary file on validation failure
        tmp_file.unlink(missing_ok=True)
        raise
    except (OSError, IOError) as e:
        # Clean up temporary file on I/O error
        tmp_file.unlink(missing_ok=True)
        raise CacheError(f"Failed to save cache: {e}") from e


def create_empty_cache(
    dll: str,
    func: str,
    arch: str,
    min_length: int,
    max_length: int,
) -> SignatureCache:
    """
    Create a new empty cache with specified parameters.

    Args:
        dll: DLL name
        func: Function name
        arch: Architecture
        min_length: Minimum signature length
        max_length: Maximum signature length

    Returns:
        Empty SignatureCache initialized with current timestamp
    """
    return SignatureCache(
        dll_name=dll,
        func_name=func,
        arch=arch,
        schema_version=CACHE_SCHEMA_VERSION,
        timestamp=datetime.now().isoformat(),
        parameters=CacheParameters(min_length=min_length, max_length=max_length),
    )


def clear_cache(
    dll: str | None = None, func: str | None = None, arch: str | None = None
) -> int:
    """
    Clear cached signatures.

    Args:
        dll: If specified, only clear caches for this DLL
        func: If specified, only clear caches for this function
        arch: If specified, only clear caches for this architecture

    Returns:
        Number of cache files deleted

    Examples:
        clear_cache()  # Clear all caches
        clear_cache(arch="x64")  # Clear all x64 caches
        clear_cache(dll="ntdll", arch="x64")  # Clear ntdll x64 caches
    """
    if not SIGNATURE_CACHE_DIR.exists():
        return 0

    deleted = 0

    # If arch specified, only look in that directory
    if arch:
        arch_dirs = [SIGNATURE_CACHE_DIR / arch]
    else:
        # Look in all architecture directories
        arch_dirs = [d for d in SIGNATURE_CACHE_DIR.iterdir() if d.is_dir()]

    for arch_dir in arch_dirs:
        if not arch_dir.exists():
            continue

        for cache_dir in arch_dir.iterdir():
            if not cache_dir.is_dir():
                continue

            cache_file = cache_dir / "signatures.json"
            if not cache_file.exists():
                continue

            # If dll/func specified, check if this cache matches
            if dll or func:
                try:
                    data = json.loads(cache_file.read_text(encoding="utf-8"))
                    if dll and data.get("dll_name", "").lower() != dll.lower():
                        continue
                    if func and data.get("func_name", "").lower() != func.lower():
                        continue
                except Exception:
                    # If we can't read it, delete it anyway
                    pass

            # Delete cache file
            try:
                cache_file.unlink()
                deleted += 1
                log_debug(f"Deleted cache: {cache_file}")
            except (OSError, IOError) as e:
                log_warning(f"Failed to delete cache {cache_file}: {e}")

    return deleted
