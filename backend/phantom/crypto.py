"""Local key material.

Everything sensitive is encrypted against a key that exists only on this
machine, in ``~/.phantom/local-hmac.key``, with 0600 permissions. Lose the key
and the data is unreadable, which is the point. Nothing here is escrowed.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from phantom.config import settings


def _ensure_key() -> bytes:
    path: Path = settings.key_file
    if path.exists():
        return path.read_bytes().strip()
    path.parent.mkdir(parents=True, exist_ok=True)
    key = base64.urlsafe_b64encode(os.urandom(32))
    path.write_bytes(key)
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return key


def _fernet() -> Fernet:
    return Fernet(_ensure_key())


def encrypt(value: str) -> str:
    return "enc:" + _fernet().encrypt(value.encode("utf-8")).decode("ascii")


def decrypt(value: str) -> str:
    if not value.startswith("enc:"):
        return value
    try:
        return _fernet().decrypt(value[4:].encode("ascii")).decode("utf-8")
    except InvalidToken:
        return "<unreadable: local key changed>"


def hmac_hex(value: str, *, domain: str = "generic") -> str:
    """Stable pseudonym. Same input plus same key gives the same token."""
    key = _ensure_key()
    return hmac.new(key, f"{domain}:{value}".encode("utf-8"), hashlib.sha256).hexdigest()


def receipt(payload: str) -> str:
    return hmac_hex(payload, domain="consent-receipt")
