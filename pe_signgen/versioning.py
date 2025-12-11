"""Windows version parsing and filtering."""

from __future__ import annotations

from .constants import WINDOWS_VERSION_ALIASES


def parse_version(version_str: str) -> tuple[int, int] | None:
    """
    Parse a Windows version string.

    Accepts:
    - Friendly names: "win10", "windows11"
    - Build numbers: "19041", "22621.1234"

    Args:
        version_str: Version string to parse

    Returns:
        Tuple of (major, minor) or None if invalid
    """
    normalized = version_str.lower().strip()

    # Check friendly names
    if normalized in WINDOWS_VERSION_ALIASES:
        return WINDOWS_VERSION_ALIASES[normalized]

    # Try to parse as numeric version
    parts = normalized.split(".")
    try:
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0
        return (major, minor)
    except (ValueError, IndexError):
        return None


def filter_builds(
    builds: list[str],
    min_version: tuple[int, int] | None = None,
    max_version: tuple[int, int] | None = None,
) -> list[str]:
    """
    Filter build strings by version range.

    Args:
        builds: List of build strings (e.g., "19041.1234")
        min_version: Minimum version tuple (inclusive)
        max_version: Maximum version tuple (inclusive)

    Returns:
        Filtered list of builds
    """
    if min_version is None and max_version is None:
        return builds

    result: list[str] = []

    for build in builds:
        parts = build.split(".")
        try:
            version = (int(parts[0]), int(parts[1]) if len(parts) > 1 else 0)
        except (ValueError, IndexError):
            # Keep builds with unparseable versions
            result.append(build)
            continue

        if min_version and version < min_version:
            continue
        if max_version and version > max_version:
            continue

        result.append(build)

    return result


def get_version_cap_for_os(os_version: tuple[int, int]) -> tuple[int, int]:
    """
    Get the maximum version for a given OS.

    Windows 10 builds are < 22000
    Windows 11 builds are >= 22000

    Args:
        os_version: Minimum version tuple

    Returns:
        Maximum version tuple
    """
    if os_version[0] < 22000:
        # Windows 10 range
        return (21999, 99999)
    else:
        # Windows 11 and beyond
        return (99999, 99999)
