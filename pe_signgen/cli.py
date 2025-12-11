"""Command-line interface for pe-signgen.

This module provides the main CLI entry point and command implementations
for generating binary signatures and offsets from Windows PE files.
"""
from __future__ import annotations

import argparse
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

from .cache import (
    load_cache,
    save_cache,
    create_empty_cache,
    BuildSignature,
)
from .constants import (
    DEFAULT_MIN_SIGNATURE_LENGTH,
    DEFAULT_MAX_SIGNATURE_LENGTH,
)
from .exceptions import SymbolNotFoundError
from .formats import (
    write_wsig,
    write_woff,
    write_json,
    write_wsig_header,
    write_woff_header,
)
from .logging_config import setup_logging, log_info, log_error
from .models import SignatureJob, SignatureResult, OffsetJob, OffsetResult
from .pipeline import download_all
from .progress import ProgressBar
from .signatures import generate_signature, group_by_signature
from .symbols import find_function
from .versioning import parse_version, get_version_cap_for_os


def _signature_worker(job: SignatureJob) -> SignatureResult:
    """
    Worker function for signature generation.
    
    Args:
        job: SignatureJob containing all parameters
        
    Returns:
        SignatureResult with success or error information
    """
    build = job.dll_path.stem

    try:
        sig, length, matched, rva = generate_signature(
            str(job.dll_path),
            str(job.pdb_path),
            job.func_name,
            min_length=job.min_length,
            max_length=job.max_length,
        )
        return SignatureResult(
            build=build,
            signature=sig,
            length=length,
            matched_name=matched,
            rva=rva,
            error=None,
        )
    except SymbolNotFoundError:
        return SignatureResult(
            build=build,
            signature=None,
            length=None,
            matched_name=None,
            rva=None,
            error="Symbol not found",
        )
    except (OSError, IOError) as e:
        return SignatureResult(
            build=build,
            signature=None,
            length=None,
            matched_name=None,
            rva=None,
            error=f"File error: {str(e)[:80]}",
        )
    except Exception as e:
        return SignatureResult(
            build=build,
            signature=None,
            length=None,
            matched_name=None,
            rva=None,
            error=f"{type(e).__name__}: {str(e)[:80]}",
        )


def _offset_worker(job: OffsetJob) -> OffsetResult:
    """
    Worker function for offset generation.
    
    Args:
        job: OffsetJob containing all parameters
        
    Returns:
        OffsetResult with success or error information
    """
    build = job.dll_path.stem

    if not job.pdb_path.exists():
        return OffsetResult(
            build=build,
            rva=None,
            file_offset=None,
            matched_name=None,
            error="PDB not found",
        )

    try:
        file_off, rva, matched = find_function(
            str(job.dll_path),
            str(job.pdb_path),
            job.func_name,
        )
        return OffsetResult(
            build=build,
            rva=rva,
            file_offset=file_off,
            matched_name=matched,
            error=None,
        )
    except SymbolNotFoundError:
        return OffsetResult(
            build=build,
            rva=None,
            file_offset=None,
            matched_name=None,
            error="Symbol not found",
        )
    except (OSError, IOError) as e:
        return OffsetResult(
            build=build,
            rva=None,
            file_offset=None,
            matched_name=None,
            error=f"File error: {str(e)[:80]}",
        )
    except Exception as e:
        return OffsetResult(
            build=build,
            rva=None,
            file_offset=None,
            matched_name=None,
            error=f"{type(e).__name__}: {str(e)[:80]}",
        )


def cmd_signatures(
    dll_name: str,
    func_name: str,
    arch: str,
    *,
    output: Path | None,
    output_format: str,
    workers: int,
    show_progress: bool,
    use_cache: bool,
    min_len: int,
    max_len: int,
    min_version: tuple[int, int] | None,
    max_version: tuple[int, int] | None,
    update_git: bool,
) -> int:
    """Generate signatures for a function across multiple Windows builds."""

    # Download all builds first
    dll_dir, pdb_dir = download_all(
        dll_name,
        arch,
        workers=workers,
        show_progress=show_progress,
        update_git=update_git,
        min_version=min_version,
        max_version=max_version,
    )

    cache = None
    if use_cache:
        cache = load_cache(dll_name, func_name, arch, min_len, max_len)

    results: dict[str, tuple[str, int, str, int]] = {}
    errors: dict[str, str] = {}

    if cache:
        for build, sig in cache.signatures.items():
            results[build] = (sig.signature, sig.length, sig.matched_name, sig.rva)
        errors.update(cache.errors)
        log_info(f"Loaded {len(results)} cached signatures")

    dll_files = sorted(dll_dir.glob("*.dll"))
    to_compute: list[SignatureJob] = []

    for dll_path in dll_files:
        build = dll_path.stem

        if cache and (build in cache.signatures or build in cache.errors):
            continue

        # Apply version filter
        if min_version or max_version:
            try:
                parts = build.split(".")
                version = (int(parts[0]), int(parts[1]) if len(parts) > 1 else 0)
                if min_version and version < min_version:
                    continue
                if max_version and version > max_version:
                    continue
            except (ValueError, IndexError):
                pass

        pdb_path = pdb_dir / f"{build}.pdb"
        to_compute.append(SignatureJob(
            dll_path=dll_path,
            pdb_path=pdb_path,
            func_name=func_name,
            min_length=min_len,
            max_length=max_len,
        ))

    # Compute new signatures
    if to_compute:
        log_info(f"Computing {len(to_compute)} signatures...")
        
        worker_count = max(1, workers)
        
        with ProgressBar(len(to_compute), enabled=show_progress) as progress:
            with ProcessPoolExecutor(max_workers=worker_count) as executor:
                futures = [executor.submit(_signature_worker, job) for job in to_compute]

                for future in as_completed(futures):
                    result = future.result()

                    if result.success:
                        results[result.build] = result.as_tuple()
                        progress.update(success=True)
                    else:
                        errors[result.build] = result.error or "Unknown error"
                        progress.update(success=False, error=True)

    if use_cache:
        cache = cache or create_empty_cache(dll_name, func_name, arch, min_len, max_len)

        for build, (sig, length, matched, rva) in results.items():
            parts = build.split(".")
            try:
                major, minor = int(parts[0]), int(parts[1]) if len(parts) > 1 else 0
            except (ValueError, IndexError):
                major, minor = 0, 0

            cache.signatures[build] = BuildSignature(
                build=build,
                major=major,
                minor=minor,
                signature=sig,
                length=length,
                matched_name=matched,
                rva=rva,
            )

        cache.errors.update(errors)
        save_cache(cache)

    groups = group_by_signature(results)
    log_info(f"Found {len(groups)} unique signature(s) across {len(results)} builds")

    if output:
        if output_format == "json":
            write_json(dll_name, func_name, arch, results, groups, output)
        elif output_format == "binary":
            write_wsig(dll_name, func_name, arch, results, groups, output)
        elif output_format == "cheader":
            write_wsig_header(dll_name, func_name, arch, results, groups, output)
        elif output_format == "all":
            base = output.stem
            parent = output.parent
            write_wsig(dll_name, func_name, arch, results, groups, parent / f"{base}.wsig")
            write_json(dll_name, func_name, arch, results, groups, parent / f"{base}.json")
            write_wsig_header(dll_name, func_name, arch, results, groups, parent / f"{base}.h")
        log_info(f"Output written to {output}")
    else:
        for sig in sorted(groups.keys()):
            builds = groups[sig]
            print(f"\nSignature: {sig}")
            print(f"Builds ({len(builds)}): {', '.join(sorted(builds))}")

    if errors:
        log_info(f"{len(errors)} builds had errors")

    return 0


def cmd_offsets(
    dll_name: str,
    func_name: str,
    arch: str,
    *,
    output: Path | None,
    output_format: str,
    workers: int,
    show_progress: bool,
    min_version: tuple[int, int] | None,
    max_version: tuple[int, int] | None,
    update_git: bool,
) -> int:
    """Generate RVA and file offsets for a function across multiple Windows builds."""

    # Download all builds first
    dll_dir, pdb_dir = download_all(
        dll_name,
        arch,
        workers=workers,
        show_progress=show_progress,
        update_git=update_git,
        min_version=min_version,
        max_version=max_version,
    )

    # Find all DLLs
    dll_files = sorted(dll_dir.glob("*.dll"))
    jobs: list[OffsetJob] = []

    for dll_path in dll_files:
        build = dll_path.stem

        # Apply version filter
        if min_version or max_version:
            try:
                parts = build.split(".")
                version = (int(parts[0]), int(parts[1]) if len(parts) > 1 else 0)
                if min_version and version < min_version:
                    continue
                if max_version and version > max_version:
                    continue
            except (ValueError, IndexError):
                pass

        pdb_path = pdb_dir / f"{build}.pdb"
        jobs.append(OffsetJob(
            dll_path=dll_path,
            pdb_path=pdb_path,
            func_name=func_name,
        ))

    # Compute offsets
    results: dict[str, tuple[int, int, str]] = {}
    errors: dict[str, str] = {}

    log_info(f"Computing {len(jobs)} offsets...")
    
    # Use at least 1 worker
    worker_count = max(1, workers)
    
    with ProgressBar(len(jobs), enabled=show_progress) as progress:
        with ProcessPoolExecutor(max_workers=worker_count) as executor:
            futures = [executor.submit(_offset_worker, job) for job in jobs]

            for future in as_completed(futures):
                result = future.result()

                if result.success:
                    results[result.build] = result.as_tuple()
                    progress.update(success=True)
                else:
                    errors[result.build] = result.error or "Unknown error"
                    progress.update(success=False, error=True)

    # Output
    if output and output_format == "binary":
        write_woff(dll_name, func_name, arch, results, output)
        log_info(f"Output written to {output}")
    elif output and output_format == "cheader":
        write_woff_header(dll_name, func_name, arch, results, output)
        log_info(f"Output written to {output}")
    else:
        # Print to stdout
        for build in sorted(results.keys()):
            rva, file_off, matched = results[build]
            print(
                f"{build:20s} | RVA: 0x{rva:08x} | "
                f"File: 0x{file_off:08x} | {matched}"
            )

    if errors:
        log_info(f"{len(errors)} builds had errors")

    return 0


def main(argv: list[str] | None = None) -> int:
    """
    Main entry point for pe-signgen CLI.
    
    Generates binary signatures or offsets for Windows PE functions
    across multiple Windows versions using winbindex data and symbol servers.
    
    Args:
        argv: Command-line arguments (default: sys.argv[1:])
        
    Returns:
        Exit code (0 for success, non-zero for error)
    """
    parser = argparse.ArgumentParser(
        prog="pe-signgen",
        description="Generate function signatures for Windows PE files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate signatures for ntdll!LdrLoadDll (x64)
  pe-signgen --signature ntdll!LdrLoadDll

  # Generate signatures for wow64 kernel32!CreateFileW, save as binary
  pe-signgen --signature kernel32!CreateFileW --arch wow64 -o sigs.wsig --output-format binary

  # Generate offsets for ntdll!NtCreateFile
  pe-signgen --signature ntdll!NtCreateFile --offsets -o offsets.woff --output-format binary

  # Only process Windows 10 builds
  pe-signgen --signature ntdll!LdrLoadDll --os-version win10

  # Generate C header with signatures
  pe-signgen --signature ntdll!LdrLoadDll -o sigs.h --output-format cheader

  # Generate all output formats
  pe-signgen --signature ntdll!LdrLoadDll -o output --output-format all

  # Specify build version range
  pe-signgen --signature ntdll!LdrLoadDll --min-version 10.0 --max-version 11.0

For more information, visit: https://github.com/forentfraps/pe-signgen
        """,
    )

    # Required arguments
    parser.add_argument(
        "--signature",
        required=True,
        metavar="DLL!FUNC",
        help="Symbol specification in format DLL!FUNCTION (e.g., ntdll!LdrLoadDll)",
    )

    # Mode selection
    parser.add_argument(
        "--offsets",
        action="store_true",
        help="Generate RVA/file offsets instead of byte signatures",
    )

    # Architecture
    parser.add_argument(
        "--arch",
        default="x64",
        choices=["x64", "arm64", "wow64"],
        help="Target architecture (default: x64). Use 'wow64' for WoW64 32-bit binaries on 64-bit Windows",
    )

    # Output options
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        help="Output file path. Extension ignored for --output-format=all",
    )
    parser.add_argument(
        "--output-format",
        choices=["json", "binary", "all", "cheader"],
        default="json",
        help=(
            "Output format (default: json). "
            "Options: "
            "'json' = JSON file, "
            "'binary' = .wsig/.woff binary format, "
            "'cheader' = C header file, "
            "'all' = generate all formats with different extensions"
        ),
    )

    # Version filtering
    parser.add_argument(
        "--min-version",
        metavar="MAJOR.MINOR",
        help="Minimum Windows build version (e.g., 10.0 for Windows 10)",
    )
    parser.add_argument(
        "--max-version",
        metavar="MAJOR.MINOR",
        help="Maximum Windows build version (e.g., 11.0 for Windows 11)",
    )
    parser.add_argument(
        "--os-version",
        metavar="OS",
        help=(
            "Target Windows version (e.g., win10, win11, win8.1). "
            "Automatically sets appropriate min/max version range. "
            "Cannot be combined with --min-version or --max-version"
        ),
    )

    # Signature generation options
    parser.add_argument(
        "--min-length",
        type=int,
        default=DEFAULT_MIN_SIGNATURE_LENGTH,
        metavar="BYTES",
        help=f"Minimum signature length in bytes (default: {DEFAULT_MIN_SIGNATURE_LENGTH})",
    )
    parser.add_argument(
        "--max-length",
        type=int,
        default=DEFAULT_MAX_SIGNATURE_LENGTH,
        metavar="BYTES",
        help=f"Maximum signature length in bytes (default: {DEFAULT_MAX_SIGNATURE_LENGTH})",
    )

    # Cache options
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help=(
            "Disable signature caching. "
            "By default, computed signatures are cached to avoid recomputation. "
            "Note: Only signatures are cached, not offsets"
        ),
    )

    # Performance options
    parser.add_argument(
        "--workers",
        type=int,
        default=8,
        metavar="N",
        help="Number of parallel worker processes (default: 8)",
    )

    # Display options
    parser.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable progress bar display",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging output",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress all non-error output",
    )

    # Git options
    parser.add_argument(
        "--no-git-update",
        action="store_true",
        help=(
            "Skip updating the local winbindex repository. "
            "By default, the tool updates winbindex data before downloading files "
            "to ensure the latest build information is available"
        ),
    )

    args = parser.parse_args(argv)

    setup_logging(verbose=args.verbose, quiet=args.quiet)

    # Parse symbol specification
    if "!" not in args.signature:
        log_error("--signature must be in format DLL!FUNCTION (e.g., ntdll!LdrLoadDll)")
        return 1

    dll_name, func_name = args.signature.split("!", 1)

    # Parse version arguments
    min_version = None
    max_version = None

    if args.os_version:
        if args.min_version or args.max_version:
            log_error("--os-version cannot be combined with --min-version or --max-version")
            return 1
        
        os_ver = parse_version(args.os_version)
        if not os_ver:
            log_error(f"Invalid OS version: {args.os_version}")
            return 1
        min_version = os_ver
        max_version = get_version_cap_for_os(os_ver)
    else:
        if args.min_version:
            min_version = parse_version(args.min_version)
            if not min_version:
                log_error(f"Invalid min version: {args.min_version}")
                return 1
        if args.max_version:
            max_version = parse_version(args.max_version)
            if not max_version:
                log_error(f"Invalid max version: {args.max_version}")
                return 1

    if args.offsets:
        return cmd_offsets(
            dll_name,
            func_name,
            args.arch,
            output=args.output,
            output_format=args.output_format,
            workers=args.workers,
            show_progress=not args.no_progress,
            min_version=min_version,
            max_version=max_version,
            update_git=not args.no_git_update,
        )
    else:
        return cmd_signatures(
            dll_name,
            func_name,
            args.arch,
            output=args.output,
            output_format=args.output_format,
            workers=args.workers,
            show_progress=not args.no_progress,
            use_cache=not args.no_cache,
            min_len=args.min_length,
            max_len=args.max_length,
            min_version=min_version,
            max_version=max_version,
            update_git=not args.no_git_update,
        )


if __name__ == "__main__":
    sys.exit(main())
