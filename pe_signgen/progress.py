"""Progress bar for long-running operations using tqdm."""
from __future__ import annotations

import threading
from typing import Any

try:
    from tqdm import tqdm
    _HAS_TQDM = True
except ImportError:
    _HAS_TQDM = False


class ProgressBar:
    """
    Thread-safe progress bar wrapper using tqdm.
    
    Falls back to silent operation if tqdm is not available.
    """
    
    def __init__(self, total: int, enabled: bool = True):
        """
        Initialize progress bar.
        
        Args:
            total: Total number of items
            enabled: Whether to display progress
        """
        self.total = max(1, total)
        self.enabled = enabled and _HAS_TQDM
        self.done = 0
        self.success = 0
        self.errors = 0
        self._lock = threading.Lock()
        
        if self.enabled:
            self._pbar = tqdm(
                total=total,
                unit="item",
                ncols=100,
                bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}] {postfix}",
                leave=True,
                dynamic_ncols=True,
            )
            # Initialize postfix
            self._update_postfix()
        else:
            self._pbar = None
    
    def _update_postfix(self) -> None:
        """Update progress bar postfix with statistics."""
        if self._pbar is not None:
            # Format: [ok:5 err:2]
            self._pbar.set_postfix_str(
                f"[✓ {self.success} ✗ {self.errors}]",
                refresh=True
            )
    
    def update(self, success: bool = True, error: bool = False) -> None:
        """
        Update progress by one item.
        
        Args:
            success: Whether this item succeeded
            error: Whether this item had an error
        """
        with self._lock:
            self.done += 1
            if success:
                self.success += 1
            if error:
                self.errors += 1
            
            if self._pbar is not None:
                self._pbar.update(1)
                self._update_postfix()
    
    def finish(self) -> None:
        """Ensure progress bar is complete and closed."""
        if self._pbar is not None:
            # Update to total if not already there
            remaining = self.total - self._pbar.n
            if remaining > 0:
                self._pbar.update(remaining)
            
            self._pbar.close()
    
    def __enter__(self) -> ProgressBar:
        """Context manager entry."""
        return self
    
    def __exit__(self, *args: Any) -> None:
        """Context manager exit."""
        self.finish()


