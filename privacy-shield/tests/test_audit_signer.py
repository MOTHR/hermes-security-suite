"""Tests for the Privacy-Shield audit Ed25519 signer.

Covers key generation, PEM load, signing, verification, error paths and
edge cases. These tests run entirely in-memory and do not touch the live
pass store or filesystem outside ``tmp_path``.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from privacy_shield.audit.signer import (
    AuditSignatureError,
    generate_signing_key,
    load_private_key,
    load_public_key,
    save_key_pair,
    sign,
    sign_b64,
    verify,
    verify_b64,
)


class TestKeyGeneration:
    def test_generate_signing_key_returns_pem_bytes(self):
        pem = generate_signing_key()
        assert isinstance(pem, bytes)
        assert b"BEGIN PRIVATE KEY" in pem
        assert b"END PRIVATE KEY" in pem

    def test_generate_signing_key_is_ed25519(self):
        pem = generate_signing_key()
        # Load via cryptography directly to verify type.
        from cryptography.hazmat.primitives import serialization

        key = serialization.load_pem_private_key(pem, password=None)
        assert isinstance(key, Ed25519PrivateKey)

    def test_save_key_pair_creates_two_files(self, tmp_path: Path):
        private_path = tmp_path / "key.pem"
        public_path = tmp_path / "key.pub"
        save_key_pair(private_path, public_path)
        assert private_path.exists()
        assert public_path.exists()
        assert b"BEGIN PRIVATE KEY" in private_path.read_bytes()
        assert b"BEGIN PUBLIC KEY" in public_path.read_bytes()

    def test_private_key_file_has_chmod_600(self, tmp_path: Path):
        private_path = tmp_path / "key.pem"
        public_path = tmp_path / "key.pub"
        save_key_pair(private_path, public_path)
        assert private_path.stat().st_mode & 0o777 == 0o600

    def test_public_key_file_has_chmod_644(self, tmp_path: Path):
        private_path = tmp_path / "key.pem"
        public_path = tmp_path / "key.pub"
        save_key_pair(private_path, public_path)
        assert public_path.stat().st_mode & 0o777 == 0o644


class TestKeyLoading:
    def test_load_private_key_from_pem(self, tmp_path: Path):
        private_path = tmp_path / "key.pem"
        public_path = tmp_path / "key.pub"
        save_key_pair(private_path, public_path)
        key = load_private_key(private_path)
        assert isinstance(key, Ed25519PrivateKey)

    def test_load_public_key_from_public_pem(self, tmp_path: Path):
        private_path = tmp_path / "key.pem"
        public_path = tmp_path / "key.pub"
        save_key_pair(private_path, public_path)
        key = load_public_key(public_path)
        assert key.public_bytes  # public key object has public_bytes

    def test_load_public_key_derives_from_private_pem(self, tmp_path: Path):
        private_path = tmp_path / "key.pem"
        public_path = tmp_path / "key.pub"
        save_key_pair(private_path, public_path)
        pub_from_private = load_public_key(private_path)
        pub_from_public = load_public_key(public_path)
        assert (
            pub_from_private.public_bytes_raw()
            == pub_from_public.public_bytes_raw()
        )

    def test_load_private_key_fails_for_public_pem(self, tmp_path: Path):
        private_path = tmp_path / "key.pem"
        public_path = tmp_path / "key.pub"
        save_key_pair(private_path, public_path)
        with pytest.raises(AuditSignatureError):
            load_private_key(public_path)

    def test_load_public_key_fails_for_random_bytes(self, tmp_path: Path):
        garbage = tmp_path / "garbage.pem"
        garbage.write_bytes(b"not a key")
        with pytest.raises(AuditSignatureError):
            load_public_key(garbage)

    def test_load_private_key_fails_for_missing_file(self, tmp_path: Path):
        with pytest.raises((AuditSignatureError, FileNotFoundError)):
            load_private_key(tmp_path / "missing.pem")


class TestSignVerify:
    def test_sign_returns_64_bytes(self, tmp_path: Path):
        private_path = tmp_path / "key.pem"
        public_path = tmp_path / "key.pub"
        save_key_pair(private_path, public_path)
        private = load_private_key(private_path)
        signature = sign(b"hello", private)
        assert len(signature) == 64

    def test_sign_b64_returns_ascii_string(self, tmp_path: Path):
        private_path = tmp_path / "key.pem"
        public_path = tmp_path / "key.pub"
        save_key_pair(private_path, public_path)
        private = load_private_key(private_path)
        sig = sign_b64("hello", private)
        assert isinstance(sig, str)
        assert sig.strip() == sig  # no newlines

    def test_verify_valid_signature(self, tmp_path: Path):
        private_path = tmp_path / "key.pem"
        public_path = tmp_path / "key.pub"
        save_key_pair(private_path, public_path)
        private = load_private_key(private_path)
        public = load_public_key(public_path)
        msg = b"audit payload"
        sig = sign(msg, private)
        assert verify(msg, sig, public) is True

    def test_verify_b64_valid_signature(self, tmp_path: Path):
        private_path = tmp_path / "key.pem"
        public_path = tmp_path / "key.pub"
        save_key_pair(private_path, public_path)
        private = load_private_key(private_path)
        public = load_public_key(public_path)
        sig_b64 = sign_b64("audit payload", private)
        assert verify_b64("audit payload", sig_b64, public) is True

    def test_verify_fails_on_tampered_message(self, tmp_path: Path):
        private_path = tmp_path / "key.pem"
        public_path = tmp_path / "key.pub"
        save_key_pair(private_path, public_path)
        private = load_private_key(private_path)
        public = load_public_key(public_path)
        sig = sign(b"original", private)
        assert verify(b"tampered", sig, public) is False

    def test_verify_fails_on_wrong_public_key(self, tmp_path: Path):
        private_path = tmp_path / "key.pem"
        wrong_private = tmp_path / "wrong.pem"
        wrong_public = tmp_path / "wrong.pub"
        save_key_pair(private_path, tmp_path / "key.pub")
        save_key_pair(wrong_private, wrong_public)
        private = load_private_key(private_path)
        public = load_public_key(wrong_public)
        sig = sign(b"msg", private)
        assert verify(b"msg", sig, public) is False

    def test_verify_fails_on_random_signature(self, tmp_path: Path):
        private_path = tmp_path / "key.pem"
        public_path = tmp_path / "key.pub"
        save_key_pair(private_path, public_path)
        public = load_public_key(public_path)
        assert verify(b"msg", b"\x00" * 64, public) is False

    def test_verify_b64_fails_on_invalid_base64(self, tmp_path: Path):
        public_path = tmp_path / "key.pub"
        save_key_pair(tmp_path / "key.pem", public_path)
        public = load_public_key(public_path)
        with pytest.raises(AuditSignatureError):
            verify_b64(b"msg", "not-valid-base64!!!", public)

    def test_sign_and_verify_unicode_payload(self, tmp_path: Path):
        private_path = tmp_path / "key.pem"
        public_path = tmp_path / "key.pub"
        save_key_pair(private_path, public_path)
        private = load_private_key(private_path)
        public = load_public_key(public_path)
        msg = "Unicode: äöü € 🛡️"
        sig = sign_b64(msg, private)
        assert verify_b64(msg, sig, public) is True

    def test_sign_accepts_bytes_or_str(self, tmp_path: Path):
        private_path = tmp_path / "key.pem"
        public_path = tmp_path / "key.pub"
        save_key_pair(private_path, public_path)
        private = load_private_key(private_path)
        public = load_public_key(public_path)
        sig_bytes = sign(b"bytes", private)
        sig_str = sign("str", private)
        assert verify(b"bytes", sig_bytes, public)
        assert verify("str", sig_str, public)

    def test_verify_rejects_non_bytes_signature(self, tmp_path: Path):
        public_path = tmp_path / "key.pub"
        save_key_pair(tmp_path / "key.pem", public_path)
        public = load_public_key(public_path)
        with pytest.raises(TypeError):
            verify(b"msg", "string-sig", public)  # type: ignore[arg-type]

    @pytest.mark.parametrize("payload", ["", "a", "x" * 10_000])
    def test_sign_verify_various_lengths(self, payload: str, tmp_path: Path):
        private_path = tmp_path / "key.pem"
        public_path = tmp_path / "key.pub"
        save_key_pair(private_path, public_path)
        private = load_private_key(private_path)
        public = load_public_key(public_path)
        sig = sign_b64(payload, private)
        assert verify_b64(payload, sig, public) is True


class TestSignatureDeterminism:
    def test_same_key_same_message_signatures_verify(self, tmp_path: Path):
        # Ed25519 may use deterministic or randomized signatures depending on
        # the backend; the essential property is that both verify.
        private_path = tmp_path / "key.pem"
        public_path = tmp_path / "key.pub"
        save_key_pair(private_path, public_path)
        private = load_private_key(private_path)
        public = load_public_key(public_path)
        sig1 = sign(b"m", private)
        sig2 = sign(b"m", private)
        assert verify(b"m", sig1, public)
        assert verify(b"m", sig2, public)
        # They are not identical only if the implementation is randomized.
        # We do not assert inequality because some cryptography backends are
        # deterministic.
    def test_save_key_pair_overwrites_existing(self, tmp_path: Path):
        private_path = tmp_path / "key.pem"
        public_path = tmp_path / "key.pub"
        save_key_pair(private_path, public_path)
        first_pub = public_path.read_bytes()
        save_key_pair(private_path, public_path)
        second_pub = public_path.read_bytes()
        assert first_pub != second_pub

    def test_save_key_pair_creates_parent_directories(self, tmp_path: Path):
        private_path = tmp_path / "deep" / "nested" / "key.pem"
        public_path = tmp_path / "deep" / "nested" / "key.pub"
        save_key_pair(private_path, public_path)
        assert private_path.exists()
