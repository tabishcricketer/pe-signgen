"""Winbindex data loading and parsing."""

from __future__ import annotations

import gzip
import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .constants import WINBINDEX_DATA_PATH
from .exceptions import WinbindexError
from .pe_parsing import match_architecture


@dataclass
class BuildChoice:
    """A selected build with its winbindex entry."""

    build: str
    entry: dict[str, Any]


def get_json_path(data_root: Path, dll_name: str) -> Path:
    """Get path to compressed JSON file for a DLL."""
    name = dll_name.lower()
    if not name.endswith(".dll"):
        name = f"{name}.dll"
    return data_root / f"{name}.json.gz"


def load_entries(data_root: Path, dll_name: str) -> list[dict[str, Any]]:
    """
    Load and parse winbindex entries for a DLL.

    Args:
        data_root: Path to winbindex data directory
        dll_name: DLL name to load

    Returns:
        List of entry dictionaries containing 'fileInfo'

    Raises:
        WinbindexError: If file not found or invalid format
    """
    json_path = get_json_path(data_root, dll_name)

    if not json_path.exists():
        raise WinbindexError(f"Winbindex data not found: {json_path}")

    try:
        data = gzip.decompress(json_path.read_bytes())
        obj = json.loads(data.decode("utf-8", errors="replace"))
    except Exception as e:
        raise WinbindexError(f"Failed to parse {json_path}: {e}") from e

    entries: list[dict[str, Any]] = []

    if isinstance(obj, dict):
        for value in obj.values():
            if isinstance(value, dict) and "fileInfo" in value:
                entries.append(value)
    elif isinstance(obj, list):
        entries = [e for e in obj if isinstance(e, dict) and "fileInfo" in e]
    else:
        raise WinbindexError(f"Unexpected JSON structure in {json_path}")

    if not entries:
        raise WinbindexError(f"No valid entries found in {json_path}")

    return entries


def extract_build_tags(entry: dict[str, Any]) -> list[str]:
    """
    Extract build version tags from a winbindex entry.

    Args:
        entry: Winbindex entry dictionary

    Returns:
        List of build strings (e.g., ["19041.1", "19041.2"])
    """
    builds: set[str] = set()

    # Try windowsVersions structure
    windows_versions = entry.get("windowsVersions") or {}
    if isinstance(windows_versions, dict):
        for kb_map in windows_versions.values():
            if not isinstance(kb_map, dict):
                continue
            for node in kb_map.values():
                if not isinstance(node, dict):
                    continue

                # Try updateInfo.releaseVersion
                update_info = node.get("updateInfo") or {}
                release_version = update_info.get("releaseVersion")
                if isinstance(release_version, str) and release_version.strip():
                    builds.add(release_version.strip())

                # Try assemblies
                assemblies = node.get("assemblies") or {}
                if isinstance(assemblies, dict):
                    for assembly in assemblies.values():
                        if not isinstance(assembly, dict):
                            continue
                        assembly_id = assembly.get("assemblyIdentity") or {}
                        if isinstance(assembly_id, dict):
                            version = assembly_id.get("version")
                            if isinstance(version, str):
                                match = re.search(r"(\d+\.\d+\.\d+\.\d+)", version)
                                if match:
                                    parts = match.group(1).split(".")
                                    builds.add(".".join(parts[-2:]))

    # Fallback to assemblyIdentity or fileInfo
    if not builds:
        for key in ("assemblyIdentity", "fileInfo"):
            container = entry.get(key) or {}
            if isinstance(container, dict):
                version = container.get("version")
                if isinstance(version, str):
                    match = re.search(r"(\d+\.\d+\.\d+\.\d+)", version)
                    if match:
                        parts = match.group(1).split(".")
                        builds.add(".".join(parts[-2:]))

    return sorted(builds) if builds else ["unknown"]


def _parse_datetime(value: Any) -> datetime:
    """Parse datetime from various formats."""
    if not value:
        return datetime.min
    if isinstance(value, list):
        value = value[0] if value else ""
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return datetime.min


def pick_one_per_build(entries: list[dict[str, Any]]) -> list[BuildChoice]:
    """
    Group entries by build and pick the best one for each.

    Selection criteria:
    1. Prefer signed binaries
    2. Newer signing date
    3. Higher version string

    Args:
        entries: List of winbindex entries

    Returns:
        List of BuildChoice, sorted by build version
    """
    from collections import defaultdict

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for entry in entries:
        for build in extract_build_tags(entry):
            grouped[build].append(entry)

    def sort_key(entry: dict[str, Any]) -> tuple:
        file_info = entry.get("fileInfo") or {}
        return (
            str(file_info.get("signingStatus", "")).lower() == "signed",
            _parse_datetime(file_info.get("signingDate")),
            str(file_info.get("version", "")),
        )

    choices: list[BuildChoice] = []
    for build, items in grouped.items():
        items.sort(key=sort_key, reverse=True)
        choices.append(BuildChoice(build=build, entry=items[0]))

    # Sort by build version
    def build_sort_key(choice: BuildChoice) -> tuple[int, int]:
        parts = choice.build.split(".")
        try:
            return (int(parts[0]), int(parts[1]) if len(parts) > 1 else 0)
        except (ValueError, IndexError):
            return (999999, 999999)

    choices.sort(key=build_sort_key)
    return choices


def filter_entries_by_arch(
    entries: list[dict[str, Any]],
    arch: str,
) -> list[dict[str, Any]]:
    """Filter entries to only those matching architecture."""
    return [e for e in entries if match_architecture(e, arch)]
