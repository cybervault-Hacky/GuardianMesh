"""Platform-aware path resolution, environment detection, and permission enforcement."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path


def is_termux() -> bool:
    """Check if GuardianMesh is running inside Termux on Android.

    Detection checks:
    1. TERMUX_VERSION environment variable
    2. PREFIX environment variable pointing to Termux app data
    3. Python executable residing in Termux prefix
    """
    if "TERMUX_VERSION" in os.environ:
        return True
    prefix = os.environ.get("PREFIX", "")
    if "com.termux" in prefix:
        return True
    return "com.termux" in sys.executable


def is_android() -> bool:
    """Check if GuardianMesh is running on an Android platform."""
    if is_termux():
        return True
    return bool("ANDROID_ROOT" in os.environ or "ANDROID_DATA" in os.environ)


def is_linux() -> bool:
    """Check if the current platform is Linux."""
    return sys.platform.startswith("linux")


def is_root() -> bool:
    """Check if the current process is running with root/superuser privileges."""
    try:
        if hasattr(os, "geteuid"):
            return os.geteuid() == 0
    except (AttributeError, OSError):
        return False
    return False


def get_default_home_dir() -> Path:
    """Resolve the default GuardianMesh home directory.

    Priority:
    1. GUARDIANMESH_HOME environment variable
    2. ~/.guardianmesh (works identically on standard Linux and Termux user home)
    """
    env_home = os.environ.get("GUARDIANMESH_HOME")
    if env_home:
        return Path(env_home).expanduser().resolve()

    return (Path.home() / ".guardianmesh").resolve()


def ensure_directory(path: Path, mode: int = 0o700) -> Path:
    """Ensure that a directory exists and has strict permissions (default 0700).

    Args:
        path: Path of the directory to ensure.
        mode: Octal permission mode (default 0o700: user rwx only).

    Returns:
        The resolved directory Path.
    """
    resolved = path.expanduser().resolve()
    resolved.mkdir(parents=True, exist_ok=True)

    try:
        current_mode = stat.S_IMODE(resolved.stat().st_mode)
        if current_mode != mode:
            resolved.chmod(mode)
    except OSError:
        # Some emulated Android filesystems (e.g. sdcard/fuse) ignore chmod
        pass

    return resolved


def set_file_permissions(path: Path, mode: int = 0o600) -> bool:
    """Set strict permissions on a file (default 0600: user rw only).

    Args:
        path: File path.
        mode: Octal permission mode.

    Returns:
        True if permissions were successfully set, False otherwise.
    """
    try:
        path.chmod(mode)
        return True
    except OSError:
        return False


def check_file_permissions(path: Path, max_mode: int = 0o600) -> bool:
    """Verify that a file does not have permissions more permissive than max_mode.

    Checks that group and others do not have unwanted permissions.

    Args:
        path: File path to inspect.
        max_mode: Maximum acceptable mode (e.g., 0o600).

    Returns:
        True if file exists and permissions are secure, False otherwise.
    """
    if not path.is_file():
        return False

    try:
        file_mode = stat.S_IMODE(path.stat().st_mode)
        # Check group and other permission bits against max_mode
        unwanted_bits = (stat.S_IRWXG | stat.S_IRWXO) & ~max_mode
        return (file_mode & unwanted_bits) == 0
    except OSError:
        return False


def check_directory_permissions(path: Path, max_mode: int = 0o700) -> bool:
    """Verify that a directory does not allow group/other access beyond max_mode.

    Args:
        path: Directory path to inspect.
        max_mode: Maximum acceptable mode (e.g., 0o700).

    Returns:
        True if directory exists and permissions are secure, False otherwise.
    """
    if not path.is_dir():
        return False

    try:
        dir_mode = stat.S_IMODE(path.stat().st_mode)
        unwanted_bits = (stat.S_IRWXG | stat.S_IRWXO) & ~max_mode
        return (dir_mode & unwanted_bits) == 0
    except OSError:
        return False
