"""Git operations for managing winbindex data."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from .constants import (
    WINBINDEX_REPO,
    WINBINDEX_BRANCH,
    WINBINDEX_LOCAL,
    WINBINDEX_DATA_PATH,
    GIT_TIMEOUT_SECONDS,
)
from .exceptions import GitError
from .logging_config import log_info, log_warning


def _run_git(
    args: list[str],
    cwd: Path | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess:
    """
    Run a git command with timeout.
    
    Args:
        args: Git command arguments (without 'git' prefix)
        cwd: Working directory
        check: Whether to raise on non-zero exit
        
    Returns:
        CompletedProcess result
        
    Raises:
        GitError: If command fails and check=True
    """
    cmd = ["git"] + args
    
    try:
        result = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
            check=False,
        )
        
        if check and result.returncode != 0:
            raise GitError(
                f"Git command failed: {' '.join(cmd)}\n"
                f"stderr: {result.stderr.strip()}"
            )
        
        return result
    
    except subprocess.TimeoutExpired as e:
        raise GitError(f"Git command timed out after {GIT_TIMEOUT_SECONDS}s") from e
    except FileNotFoundError:
        raise GitError(
            "Git not found. Please install git:\n"
        )


def is_git_available() -> bool:
    """Check if git is available."""
    try:
        result = subprocess.run(
            ["git", "--version"],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def is_repo(path: Path) -> bool:
    """Check if path is a git repository."""
    return (path / ".git").is_dir()


def ensure_winbindex_data(force_update: bool = True) -> Path:
    """
    Ensure winbindex data is available and optionally up-to-date.
    
    Args:
        force_update: Whether to pull latest changes
        
    Returns:
        Path to the data directory
        
    Raises:
        GitError: If git operations fail
    """
    if not is_git_available():
        raise GitError("Git is not available")
    
    repo_path = WINBINDEX_LOCAL
    
    if not repo_path.exists() or not is_repo(repo_path):
        log_info(f"Cloning winbindex repository (this may take a few minutes)...")
        log_info(f"Repository: {WINBINDEX_REPO}")
        log_info(f"Destination: {repo_path}")
        
        # Remove any partial clone
        if repo_path.exists():
            shutil.rmtree(repo_path)
        
        _run_git([
            "clone",
            "--branch", WINBINDEX_BRANCH,
            "--single-branch",
            "--depth", "1",
            WINBINDEX_REPO,
            str(repo_path),
        ])
        
        log_info("Repository cloned successfully")
    else:
        log_info(f"Using existing repository at {repo_path}")
    
    # Ensure correct branch
    result = _run_git(["branch", "--show-current"], cwd=repo_path, check=False)
    current_branch = (result.stdout or "").strip()
    
    if current_branch != WINBINDEX_BRANCH:
        log_info(f"Switching to {WINBINDEX_BRANCH} branch...")
        _run_git(["checkout", WINBINDEX_BRANCH], cwd=repo_path)
    
    # Update if requested
    if force_update:
        try:
            result = _run_git(["pull"], cwd=repo_path, check=False)
            
            if result.returncode == 0:
                output = result.stdout.strip() or result.stderr.strip()
                if "Already up to date" in output:
                    log_info("Already up to date")
                else:
                    log_info("Repository updated")
            else:
                log_warning(f"git pull failed: {result.stderr.strip()}")
                log_warning("Continuing with existing data")
        except GitError as e:
            log_warning(f"Could not update: {e}")
            log_warning("Continuing with existing data")
    
    if not WINBINDEX_DATA_PATH.exists():
        raise GitError(
            f"Data directory not found: {WINBINDEX_DATA_PATH}\n"
            "The winbindex repository structure may have changed."
        )
    
    log_info(f"Winbindex data ready at {WINBINDEX_DATA_PATH}")
    return WINBINDEX_DATA_PATH
