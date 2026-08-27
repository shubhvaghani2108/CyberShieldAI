"""
CyberShieldAI - Nmap Path Resolver
====================================
Finds a working Nmap executable automatically, regardless of the
operating system the project is running on.

The original codebase hardcoded a single developer's personal
Windows path (E:\\Nmap\\nmap.exe). That breaks the project on every
other machine, including other Windows machines where Nmap was
installed to its default folder. This module replaces that with a
proper auto-detection routine:

  1. Look for "nmap" on the system PATH (works out of the box on
     Linux/macOS, and on Windows if the installer's "Add to PATH"
     option was used).
  2. Fall back to the common default install locations for Windows,
     macOS (Homebrew), and Linux.
  3. Raise a clear, actionable error if Nmap truly isn't installed,
     instead of a confusing "file not found" deep inside a scan.
"""

import os
import platform
import shutil

# Common install locations, checked only if "nmap" is not already on PATH.
_FALLBACK_PATHS = [
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
    "/usr/bin/nmap",
    "/usr/local/bin/nmap",
    "/opt/homebrew/bin/nmap",
    "/opt/local/bin/nmap",
]

_cached_path = None


def get_nmap_path():
    """
    Return a valid path to the Nmap executable.

    Raises:
        FileNotFoundError: if Nmap could not be located anywhere,
        with instructions on how to install it for the current OS.
    """
    global _cached_path

    if _cached_path:
        return _cached_path

    # 1) Check PATH first (works cross-platform).
    found = shutil.which("nmap")
    if found:
        _cached_path = found
        return _cached_path

    # 2) Check common fallback install locations.
    for candidate in _FALLBACK_PATHS:
        if os.path.isfile(candidate):
            _cached_path = candidate
            return _cached_path

    # 3) Nothing found - fail with a helpful, OS-specific message.
    system = platform.system()
    if system == "Windows":
        hint = (
            "Download and install Nmap from https://nmap.org/download.html "
            "and make sure to check 'Add Nmap to the system PATH' during "
            "installation."
        )
    elif system == "Darwin":
        hint = "Install it with Homebrew: brew install nmap"
    else:
        hint = (
            "Install it with your package manager, e.g. "
            "'sudo apt install nmap' (Debian/Ubuntu) or "
            "'sudo dnf install nmap' (Fedora)."
        )

    raise FileNotFoundError(
        "Nmap executable was not found on this system. " + hint
    )
