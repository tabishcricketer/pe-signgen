"""Download pipeline for PE and PDB files."""
from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from .constants import (
    WINBINDEX_DATA_PATH,
    DLL_CACHE_DIR,
    PDB_CACHE_DIR,
)
from .exceptions import DownloadError
from .git import ensure_winbindex_data
from .http import download_file, file_exists_and_nonempty
from .logging_config import log_info, log_warning
from .models import DownloadJob, DownloadResult
from .pe_parsing import CodeViewRSDS, is_pe_complete, parse_codeview
from .progress import ProgressBar
from .symbol_server import get_pe_url_for_entry, compute_pdb_url
from .versioning import filter_builds
from .winbindex import (
    load_entries,
    filter_entries_by_arch,
    pick_one_per_build,
    BuildChoice,
)


def _download_build(job: DownloadJob) -> DownloadResult:
    """
    Download a single DLL+PDB pair.
    
    This function runs in a worker process.
    
    Args:
        job: DownloadJob specification
    
    Returns:
        DownloadResult with paths or error
    """
    dll_path = job.dll_dir / f"{job.build}.dll"
    pdb_path = job.pdb_dir / f"{job.build}.pdb"
    
    # Download DLL
    try:
        dll_url = get_pe_url_for_entry(job.dll_name, job.entry)
        
        if file_exists_and_nonempty(dll_path):
            # Verify existing file
            try:
                pe_data = dll_path.read_bytes()
                if not is_pe_complete(pe_data):
                    download_file(dll_url, dll_path)
            except (OSError, IOError):
                download_file(dll_url, dll_path)
        else:
            download_file(dll_url, dll_path)
    
    except (DownloadError, OSError, IOError) as e:
        return DownloadResult(
            build=job.build,
            dll_path=None,
            pdb_path=None,
            error=f"DLL download failed: {e}",
        )
    
    # Parse CodeView to get PDB URL
    try:
        pe_data = dll_path.read_bytes()
        codeview = parse_codeview(pe_data)
        
        if not isinstance(codeview, CodeViewRSDS):
            return DownloadResult(
                build=job.build,
                dll_path=dll_path,
                pdb_path=None,
                error="NB10 format not fully supported",
            )
        
        pdb_url = compute_pdb_url(codeview.pdb_name, codeview.guid, codeview.age)
    
    except (OSError, IOError) as e:
        return DownloadResult(
            build=job.build,
            dll_path=dll_path,
            pdb_path=None,
            error=f"File read error: {e}",
        )
    except Exception as e:
        return DownloadResult(
            build=job.build,
            dll_path=dll_path,
            pdb_path=None,
            error=f"CodeView parse failed: {e}",
        )
    
    # Download PDB
    if file_exists_and_nonempty(pdb_path):
        return DownloadResult(
            build=job.build,
            dll_path=dll_path,
            pdb_path=pdb_path,
            error=None,
        )
    
    try:
        download_file(pdb_url, pdb_path)
        return DownloadResult(
            build=job.build,
            dll_path=dll_path,
            pdb_path=pdb_path,
            error=None,
        )
    
    except (DownloadError, OSError, IOError) as e:
        return DownloadResult(
            build=job.build,
            dll_path=dll_path,
            pdb_path=None,
            error=f"PDB download failed: {e}",
        )


def download_all(
    dll_name: str,
    arch: str,
    *,
    data_root: Path | None = None,
    dll_dir: Path | None = None,
    pdb_dir: Path | None = None,
    workers: int = 8,
    show_progress: bool = True,
    update_git: bool = True,
    min_version: tuple[int, int] | None = None,
    max_version: tuple[int, int] | None = None,
) -> tuple[Path, Path]:
    """
    Download DLL and PDB files for all matching builds.
    
    Files are organized by architecture:
    - dlls/ntdll/x64/10240.16384.dll
    - dlls/ntdll/wow64/14393.0.dll
    - pdbs/ntdll/x64/10240.16384.pdb
    - pdbs/ntdll/wow64/14393.0.pdb
    
    Args:
        dll_name: DLL name (with or without extension)
        arch: Architecture (x64, x86, arm64, wow64)
        data_root: Winbindex data directory (auto-detected if None)
        dll_dir: Output directory for DLLs (overrides default)
        pdb_dir: Output directory for PDBs (overrides default)
        workers: Number of parallel workers
        show_progress: Whether to show progress bar
        update_git: Whether to update winbindex repo
        min_version: Minimum build version
        max_version: Maximum build version
        
    Returns:
        Tuple of (dll_dir, pdb_dir)
    """
    # Ensure winbindex data is available
    if data_root is None:
        data_root = ensure_winbindex_data(force_update=update_git)
    elif update_git:
        ensure_winbindex_data(force_update=True)
    
    # Set up output directories with architecture subdirectories
    dll_stem = Path(dll_name).stem.lower()
    if dll_dir is None:
        dll_dir = DLL_CACHE_DIR / dll_stem / arch
    if pdb_dir is None:
        pdb_dir = PDB_CACHE_DIR / dll_stem / arch
    
    dll_dir.mkdir(parents=True, exist_ok=True)
    pdb_dir.mkdir(parents=True, exist_ok=True)
    
    # Load and filter entries
    entries = load_entries(data_root, dll_name)
    entries = filter_entries_by_arch(entries, arch)
    
    if not entries:
        log_warning(f"No entries found for {dll_name} ({arch})")
        return dll_dir, pdb_dir
    
    # Pick one entry per build
    picks = pick_one_per_build(entries)
    
    # Filter by version
    if min_version or max_version:
        wanted_builds = set(filter_builds(
            [p.build for p in picks],
            min_version,
            max_version
        ))
        picks = [p for p in picks if p.build in wanted_builds]
    
    if not picks:
        log_warning("No builds match the version filter")
        return dll_dir, pdb_dir
    
    log_info(f"Processing {len(picks)} builds...")
    
    # Download in parallel
    with ProgressBar(len(picks), enabled=show_progress) as progress:
        with ProcessPoolExecutor(max_workers=max(1, workers)) as executor:
            jobs = [
                DownloadJob(
                    dll_name=dll_name,
                    build=pick.build,
                    entry=pick.entry,
                    dll_dir=dll_dir,
                    pdb_dir=pdb_dir,
                )
                for pick in picks
            ]
            
            futures = [executor.submit(_download_build, job) for job in jobs]
            
            for future in as_completed(futures):
                result = future.result()
                
                success = result.dll_path is not None
                has_error = result.error is not None
                progress.update(success=success, error=has_error)
    
    log_info(f"DLLs: {dll_dir}")
    log_info(f"PDBs: {pdb_dir}")
    
    return dll_dir, pdb_dir
