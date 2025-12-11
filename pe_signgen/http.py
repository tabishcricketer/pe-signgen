"""HTTP utilities for pe-signgen."""
from __future__ import annotations

import os
import tempfile
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING

import requests

from .constants import (
    HTTP_TIMEOUT_SECONDS,
    HTTP_CHUNK_SIZE,
    MAX_DOWNLOAD_RETRIES,
)
from .exceptions import DownloadError

if TYPE_CHECKING:
    pass

# Thread-local storage for sessions
_thread_local = threading.local()


def get_session() -> requests.Session:
    """Get thread-local requests session."""
    session = getattr(_thread_local, "session", None)
    if session is None:
        session = requests.Session()
        _thread_local.session = session
    return session


def http_get(
    url: str,
    *,
    stream: bool = True,
    timeout: int = HTTP_TIMEOUT_SECONDS,
) -> requests.Response:
    """
    Make an HTTP GET request.
    
    Args:
        url: URL to fetch
        stream: Whether to stream the response
        timeout: Request timeout in seconds
        
    Returns:
        Response object
        
    Raises:
        DownloadError: If the request fails
    """
    try:
        response = get_session().get(url, stream=stream, timeout=timeout)
        response.raise_for_status()
        return response
    except requests.RequestException as e:
        raise DownloadError(f"Failed to fetch {url}: {e}") from e


def atomic_write(response: requests.Response, dest: Path) -> None:
    """
    Write response content to file atomically.
    
    Uses a temporary file and atomic rename to prevent partial writes.
    
    Args:
        response: HTTP response with content
        dest: Destination file path
        
    Raises:
        DownloadError: If write fails
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    
    try:
        with tempfile.NamedTemporaryFile(
            delete=False,
            dir=str(dest.parent),
            suffix=".tmp"
        ) as tmp:
            tmp_path = Path(tmp.name)
            try:
                for chunk in response.iter_content(chunk_size=HTTP_CHUNK_SIZE):
                    if chunk:
                        tmp.write(chunk)
                tmp.flush()
                os.fsync(tmp.fileno())
            except Exception as e:
                tmp_path.unlink(missing_ok=True)
                raise DownloadError(f"Write failed: {e}") from e
        
        # Atomic rename
        tmp_path.replace(dest)
    except OSError as e:
        raise DownloadError(f"Failed to write {dest}: {e}") from e


def download_file(
    url: str,
    dest: Path,
    *,
    retries: int = MAX_DOWNLOAD_RETRIES,
    expected_size: int | None = None,
) -> None:
    """
    Download a file with retry logic.
    
    Args:
        url: URL to download
        dest: Destination file path
        retries: Number of retry attempts
        expected_size: Expected file size (optional validation)
        
    Raises:
        DownloadError: If download fails after all retries
    """
    last_error: Exception | None = None
    
    for attempt in range(retries + 1):
        try:
            with http_get(url, stream=True) as response:
                content_length = response.headers.get("Content-Length")
                if content_length and content_length.isdigit():
                    expected = int(content_length)
                else:
                    expected = expected_size
                
                atomic_write(response, dest)
                
                # Validate size if known
                if expected is not None:
                    actual_size = dest.stat().st_size
                    if actual_size < expected:
                        raise DownloadError(
                            f"Truncated download: got {actual_size}, expected {expected}"
                        )
                return
                
        except Exception as e:
            last_error = e
            if attempt < retries:
                sleep_time = min(2 ** (attempt + 1), 10)
                time.sleep(sleep_time)
    
    raise DownloadError(f"Download failed after {retries + 1} attempts: {last_error}")


def file_exists_and_nonempty(path: Path) -> bool:
    """Check if a file exists and has content."""
    try:
        return path.exists() and path.stat().st_size > 0
    except OSError:
        return False
