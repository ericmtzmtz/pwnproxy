"""Restrict the token file to the user who created it.

Two implementations behind one call:

* **POSIX**: ``0o600`` (read/write for the owner, nothing for anybody else).
* **Windows**: ``chmod`` cannot express that (``0o600`` only clears the write
  bit), so this module builds a *protected* DACL with exactly one ACE — GRANT
  ``FILE_ALL_ACCESS`` to the current user's SID — and applies it with
  ``SetNamedSecurityInfoW``. "Protected" means inheritance is switched off: the
  profile ACL would otherwise add ``Administrators``, ``SYSTEM`` and
  ``Authenticated Users`` to the file.

``icacls`` is not used on purpose: its output is localised (the machine this was
written on prints it in Spanish), so a test could only assert "it did not
crash". :func:`acl_ace_count` reads the DACL back with ``GetNamedSecurityInfoW``
and counts the entries, which is a real verification.

A permission problem never raises: :func:`restrict_to_current_user` logs a
warning with the path and the reason and returns ``False``. Refusing to start
the API because a domain policy rejected the DACL would be worse than the risk
it avoids (the token is already unreadable over the network).
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
import logging
import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

logger = logging.getLogger(__name__)

#: ``True`` on Windows, where the DACL branch runs.
IS_WINDOWS = sys.platform == "win32"

#: Mode applied on POSIX (owner read/write only).
POSIX_TOKEN_MODE = 0o600

# --- Windows constants (advapi32) ------------------------------------------
_TOKEN_QUERY = 0x0008
_TOKEN_USER_INFORMATION_CLASS = 1
_ERROR_INSUFFICIENT_BUFFER = 122
_FILE_ALL_ACCESS = 0x001F01FF
_GRANT_ACCESS = 1
_NO_INHERITANCE = 0
_NO_MULTIPLE_TRUSTEE = 0
_TRUSTEE_IS_SID = 0
_TRUSTEE_IS_USER = 1
_SE_FILE_OBJECT = 1
_DACL_SECURITY_INFORMATION = 0x00000004
_PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
_ACL_SIZE_INFORMATION_CLASS = 2


class _TrusteeW(ctypes.Structure):
    """``TRUSTEE_W`` — who an ACE applies to."""

    _fields_ = [
        ("pMultipleTrustee", ctypes.c_void_p),
        ("MultipleTrusteeOperation", ctypes.c_int),
        ("TrusteeForm", ctypes.c_int),
        ("TrusteeType", ctypes.c_int),
        ("ptstrName", ctypes.c_void_p),
    ]


class _ExplicitAccessW(ctypes.Structure):
    """``EXPLICIT_ACCESS_W`` — one ACE, the input of ``SetEntriesInAclW``."""

    _fields_ = [
        ("grfAccessPermissions", wintypes.DWORD),
        ("grfAccessMode", ctypes.c_int),
        ("grfInheritance", wintypes.DWORD),
        ("Trustee", _TrusteeW),
    ]


class _AclSizeInformation(ctypes.Structure):
    """``ACL_SIZE_INFORMATION`` — the first field is the ACE count."""

    _fields_ = [
        ("AceCount", wintypes.DWORD),
        ("AclBytesInUse", wintypes.DWORD),
        ("AclBytesFree", wintypes.DWORD),
    ]


__all__ = [
    "IS_WINDOWS",
    "POSIX_TOKEN_MODE",
    "acl_ace_count",
    "file_mode",
    "restrict_to_current_user",
]


def _win_api() -> Any:
    """Return ``advapi32``/``kernel32`` with their argtypes declared.

    Raises:
        OSError: on a platform without ``advapi32`` (i.e. not Windows).
    """
    if not IS_WINDOWS:
        raise OSError("the Windows DACL API is not available on this platform")

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.SetEntriesInAclW.argtypes = [
        wintypes.ULONG,
        ctypes.POINTER(_ExplicitAccessW),
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.SetEntriesInAclW.restype = wintypes.DWORD
    advapi32.SetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.GetAclInformation.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.c_int]
    advapi32.GetAclInformation.restype = wintypes.BOOL

    return SimpleNamespace(advapi32=advapi32, kernel32=kernel32)


def _check(code: int) -> None:
    """Raise ``OSError`` for a failed Win32 call (``0`` means success)."""
    if code != 0:
        raise ctypes.WinError(code)


def _current_user_sid() -> bytes:
    """Return the SID of the user running this process, as raw SID bytes."""
    api = _win_api()
    advapi32, kernel32 = api.advapi32, api.kernel32

    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)):
        _check(ctypes.get_last_error())
    try:
        needed = wintypes.DWORD(0)
        advapi32.GetTokenInformation(token, _TOKEN_USER_INFORMATION_CLASS, None, 0, ctypes.byref(needed))
        if ctypes.get_last_error() != _ERROR_INSUFFICIENT_BUFFER:
            _check(ctypes.get_last_error())
        buffer = ctypes.create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(
            token, _TOKEN_USER_INFORMATION_CLASS, buffer, needed, ctypes.byref(needed)
        ):
            _check(ctypes.get_last_error())
        # ``TOKEN_USER`` starts with ``SID_AND_ATTRIBUTES``, whose first field is the SID pointer.
        sid_pointer = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
        revision_and_count = ctypes.string_at(sid_pointer, 2)
        return ctypes.string_at(sid_pointer, 8 + 4 * revision_and_count[1])
    finally:
        kernel32.CloseHandle(token)


def _apply_windows_acl(path: Path) -> None:
    """Install a protected single-ACE DACL (current user, full access) on ``path``.

    Raises:
        OSError: one of the three Win32 calls failed; the message carries the code.
    """
    api = _win_api()
    advapi32, kernel32 = api.advapi32, api.kernel32

    sid = _current_user_sid()
    sid_buffer = ctypes.create_string_buffer(sid, len(sid))

    entry = _ExplicitAccessW()
    entry.grfAccessPermissions = _FILE_ALL_ACCESS
    entry.grfAccessMode = _GRANT_ACCESS
    entry.grfInheritance = _NO_INHERITANCE
    entry.Trustee.pMultipleTrustee = None
    entry.Trustee.MultipleTrusteeOperation = _NO_MULTIPLE_TRUSTEE
    entry.Trustee.TrusteeForm = _TRUSTEE_IS_SID
    entry.Trustee.TrusteeType = _TRUSTEE_IS_USER
    entry.Trustee.ptstrName = ctypes.cast(sid_buffer, ctypes.c_void_p)

    new_acl = ctypes.c_void_p()
    _check(advapi32.SetEntriesInAclW(1, ctypes.byref(entry), None, ctypes.byref(new_acl)))
    try:
        _check(
            advapi32.SetNamedSecurityInfoW(
                os.fspath(path),
                _SE_FILE_OBJECT,
                _DACL_SECURITY_INFORMATION | _PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                new_acl,
                None,
            )
        )
    finally:
        kernel32.LocalFree(new_acl)


def restrict_to_current_user(path: str | os.PathLike[str]) -> bool:
    """Make ``path`` readable only by the current user.

    Args:
        path: File to restrict (usually the API/MCP token file).

    Returns:
        ``True`` when the restriction was applied, ``False`` when the platform
        refused it. A failure is logged as a warning with the path and the
        reason: it never raises, because an unwritable DACL must not stop the
        API from starting.
    """
    target = Path(path)
    try:
        if IS_WINDOWS:
            _apply_windows_acl(target)
        else:
            os.chmod(target, POSIX_TOKEN_MODE)
    except OSError as exc:
        logger.warning("Could not restrict %s to the current user: %s", target, exc)
        return False
    return True


def acl_ace_count(path: str | os.PathLike[str]) -> int:
    """Return how many access-control entries the file's DACL has (Windows only).

    This is the verification hook for the Windows branch: a correctly restricted
    token file has exactly **one** ACE (the current user's). Inherited entries
    from ``Authenticated Users`` / ``Administrators`` would make it larger.

    Args:
        path: File to inspect.

    Returns:
        Number of ACEs in the DACL (``0`` when the file has no DACL at all).

    Raises:
        OSError: the file cannot be inspected, or this is not Windows.
    """
    api = _win_api()
    advapi32, kernel32 = api.advapi32, api.kernel32

    owner = ctypes.c_void_p()
    group = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    sacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    _check(
        advapi32.GetNamedSecurityInfoW(
            os.fspath(path),
            _SE_FILE_OBJECT,
            _DACL_SECURITY_INFORMATION,
            ctypes.byref(owner),
            ctypes.byref(group),
            ctypes.byref(dacl),
            ctypes.byref(sacl),
            ctypes.byref(descriptor),
        )
    )
    try:
        if not dacl:
            return 0
        info = _AclSizeInformation()
        if not advapi32.GetAclInformation(
            dacl, ctypes.byref(info), ctypes.sizeof(info), _ACL_SIZE_INFORMATION_CLASS
        ):
            _check(ctypes.get_last_error())
        return int(info.AceCount)
    finally:
        kernel32.LocalFree(descriptor)


def file_mode(path: str | os.PathLike[str]) -> int:
    """Return the POSIX permission bits of ``path`` (``stat.S_IMODE``).

    Args:
        path: File to inspect.

    Returns:
        The permission bits, e.g. ``0o600``. Meaningless on Windows, where the
        test uses :func:`acl_ace_count` instead.
    """
    return stat.S_IMODE(os.stat(path).st_mode)
