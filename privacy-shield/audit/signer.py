"""Ed25519 signing and verification for Privacy-Shield audit exports.

The signer is intentionally small and uses only the ``cryptography``
dependency already required by Privacy-Shield. It produces detached
signatures over the canonical JSON serialisation of a ``ReportData``
object; the signature can be embedded into PDF reports and shipped as a
separate ``.sig`` file for CSV/JSON exports.
"""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


class AuditSignatureError(Exception):
    """Raised when a signing or verification operation cannot complete."""


Payload = Union[bytes, str]


def generate_signing_key() -> bytes:
    """Return a new Ed25519 private key serialised as PEM/PKCS8.

    The returned bytes contain **only** the private key; callers that also
    need the public key should call ``save_key_pair``.
    """
    key = Ed25519PrivateKey.generate()
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def save_key_pair(private_key_path: Path, public_key_path: Path) -> None:
    """Generate a fresh Ed25519 key pair and persist both halves as PEM.

    Parent directories are created if necessary. Files are written with
    chmod 600 / 644 respectively.
    """
    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_key_path.parent.mkdir(parents=True, exist_ok=True)
    public_key_path.parent.mkdir(parents=True, exist_ok=True)
    private_key_path.write_bytes(private_pem)
    public_key_path.write_bytes(public_pem)
    private_key_path.chmod(0o600)
    public_key_path.chmod(0o644)


def load_private_key(path: Path) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from a PEM file."""
    pem = path.read_bytes()
    try:
        key = serialization.load_pem_private_key(pem, password=None)
    except Exception as exc:
        raise AuditSignatureError(f"Cannot load private key from {path}: {exc}") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise AuditSignatureError(f"Key in {path} is not an Ed25519 private key")
    return key


def load_public_key(path: Path) -> Ed25519PublicKey:
    """Load an Ed25519 public key from a PEM file.

    Accepts either a public-key PEM or a private-key PEM (deriving the public
    key from the private half). This makes operator workflows convenient:
    the same private-key file used for signing can be passed to a verifier
    that only exposes a public-key parameter in a pinch.
    """
    pem = path.read_bytes()
    # Try public first.
    try:
        key = serialization.load_pem_public_key(pem)
        if isinstance(key, Ed25519PublicKey):
            return key
    except Exception:
        pass
    # Fall back to deriving public from private.
    try:
        private = serialization.load_pem_private_key(pem, password=None)
        if isinstance(private, Ed25519PrivateKey):
            return private.public_key()
    except Exception as exc:
        raise AuditSignatureError(f"Cannot load public key from {path}: {exc}") from exc
    raise AuditSignatureError(f"Key in {path} is not an Ed25519 key")


def sign(payload: Payload, private_key: Ed25519PrivateKey) -> bytes:
    """Return the raw 64-byte Ed25519 signature for ``payload``."""
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    return private_key.sign(payload)


def sign_b64(payload: Payload, private_key: Ed25519PrivateKey) -> str:
    """Return the Ed25519 signature as a URL-safe base64 string."""
    raw = sign(payload, private_key)
    return base64.b64encode(raw).decode("ascii")


def verify(payload: Payload, signature: bytes, public_key: Ed25519PublicKey) -> bool:
    """Verify ``signature`` over ``payload`` with ``public_key``.

    Returns ``False`` for an invalid signature; raises only for malformed
    payload/signature inputs.
    """
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    if not isinstance(signature, bytes):
        raise TypeError("signature must be bytes")
    try:
        public_key.verify(signature, payload)
        return True
    except InvalidSignature:
        return False


def verify_b64(payload: Payload, signature_b64: str, public_key: Ed25519PublicKey) -> bool:
    """Verify a base64-encoded Ed25519 signature."""
    try:
        signature = base64.b64decode(signature_b64)
    except Exception as exc:
        raise AuditSignatureError(f"Invalid base64 signature: {exc}") from exc
    return verify(payload, signature, public_key)
