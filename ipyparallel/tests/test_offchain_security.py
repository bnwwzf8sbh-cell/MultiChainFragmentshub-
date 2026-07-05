"""Tests for ipyparallel.offchain.security — HashSuite and Secp256k1Suite."""

import hashlib
import importlib.util
import sys

import pytest


# ---------------------------------------------------------------------------
# Import the security module directly (avoids ipyparallel's heavy __init__)
# ---------------------------------------------------------------------------

def _load_security():
    spec = importlib.util.spec_from_file_location(
        "ipyparallel.offchain.security",
        "ipyparallel/offchain/security.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_sec = _load_security()
HashSuite = _sec.HashSuite
Secp256k1Suite = _sec.Secp256k1Suite


# ---------------------------------------------------------------------------
# HashSuite — SHA-1
# ---------------------------------------------------------------------------


class TestHashSuiteSHA1:
    def test_known_digest_hello(self):
        # RFC-3174 test vector
        assert HashSuite.sha1(b"hello") == "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"

    def test_empty_string(self):
        assert HashSuite.sha1(b"") == "da39a3ee5e6b4b0d3255bfef95601890afd80709"

    def test_raw_returns_bytes(self):
        result = HashSuite.sha1(b"hello", raw=True)
        assert isinstance(result, bytes)
        assert len(result) == 20

    def test_hex_returns_str(self):
        result = HashSuite.sha1(b"hello")
        assert isinstance(result, str)
        assert len(result) == 40

    def test_different_inputs_differ(self):
        assert HashSuite.sha1(b"a") != HashSuite.sha1(b"b")


# ---------------------------------------------------------------------------
# HashSuite — SHA-256
# ---------------------------------------------------------------------------


class TestHashSuiteSHA256:
    # NIST test vector
    _HELLO = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

    def test_known_digest_hello(self):
        assert HashSuite.sha256(b"hello") == self._HELLO

    def test_empty_string(self):
        assert (
            HashSuite.sha256(b"")
            == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )

    def test_raw_vs_hex_consistent(self):
        raw = HashSuite.sha256(b"hello", raw=True)
        assert raw == bytes.fromhex(self._HELLO)

    def test_raw_length(self):
        assert len(HashSuite.sha256(b"x" * 1000, raw=True)) == 32

    def test_hex_length(self):
        assert len(HashSuite.sha256(b"x")) == 64

    def test_matches_stdlib(self):
        data = b"MultiChainFragmentshub"
        assert HashSuite.sha256(data) == hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# HashSuite — SHA-512
# ---------------------------------------------------------------------------


class TestHashSuiteSHA512:
    def test_known_digest_hello(self):
        # Known SHA-512 of "hello"
        expected = hashlib.sha512(b"hello").hexdigest()
        assert HashSuite.sha512(b"hello") == expected

    def test_raw_length(self):
        assert len(HashSuite.sha512(b"x", raw=True)) == 64

    def test_hex_length(self):
        assert len(HashSuite.sha512(b"x")) == 128

    def test_different_from_sha256(self):
        assert HashSuite.sha512(b"hello") != HashSuite.sha256(b"hello")


# ---------------------------------------------------------------------------
# HashSuite — streaming hasher
# ---------------------------------------------------------------------------


class TestHashSuiteHasher:
    def test_sha256_streaming_matches_oneshot(self):
        h = HashSuite.hasher("sha256")
        h.update(b"hello")
        assert h.hexdigest() == HashSuite.sha256(b"hello")

    def test_sha512_streaming_matches_oneshot(self):
        h = HashSuite.hasher("sha512")
        h.update(b"hello")
        assert h.hexdigest() == HashSuite.sha512(b"hello")

    def test_unknown_algorithm_raises(self):
        with pytest.raises(ValueError, match="Unsupported"):
            HashSuite.hasher("md5")

    def test_multi_update(self):
        h1 = HashSuite.hasher("sha256")
        h1.update(b"hel")
        h1.update(b"lo")
        assert h1.hexdigest() == HashSuite.sha256(b"hello")


# ---------------------------------------------------------------------------
# HashSuite — HMAC helpers
# ---------------------------------------------------------------------------


class TestHashSuiteHMAC:
    def test_hmac_sha256_length(self):
        assert len(HashSuite.hmac_sha256(b"key", b"data")) == 32

    def test_hmac_sha512_length(self):
        assert len(HashSuite.hmac_sha512(b"key", b"data")) == 64

    def test_hmac_sha256_known_vector(self):
        import hmac as _hmac

        key, data = b"secret", b"hello"
        expected = _hmac.new(key, data, hashlib.sha256).digest()
        assert HashSuite.hmac_sha256(key, data) == expected

    def test_different_keys_differ(self):
        assert HashSuite.hmac_sha256(b"k1", b"d") != HashSuite.hmac_sha256(b"k2", b"d")


# ---------------------------------------------------------------------------
# Secp256k1Suite — key generation and export
# ---------------------------------------------------------------------------


class TestSecp256k1SuiteKeys:
    def test_generate_produces_valid_address(self):
        suite = Secp256k1Suite.generate()
        addr = suite.ethereum_address()
        assert addr.startswith("0x")
        assert len(addr) == 42

    def test_private_key_bytes_length(self):
        suite = Secp256k1Suite.generate()
        assert len(suite.private_key_bytes()) == 32

    def test_private_key_hex_format(self):
        suite = Secp256k1Suite.generate()
        h = suite.private_key_hex()
        assert h.startswith("0x")
        assert len(h) == 66  # 0x + 64 hex chars

    def test_from_private_key_hex_roundtrip(self):
        suite = Secp256k1Suite.generate()
        suite2 = Secp256k1Suite.from_private_key_hex(suite.private_key_hex())
        assert suite2.ethereum_address() == suite.ethereum_address()

    def test_from_private_key_bytes_roundtrip(self):
        suite = Secp256k1Suite.generate()
        suite2 = Secp256k1Suite.from_private_key_bytes(suite.private_key_bytes())
        assert suite2.ethereum_address() == suite.ethereum_address()

    def test_uncompressed_pubkey_length(self):
        suite = Secp256k1Suite.generate()
        assert len(suite.public_key_uncompressed()) == 65
        assert suite.public_key_uncompressed()[0:1] == b"\x04"

    def test_compressed_pubkey_length(self):
        suite = Secp256k1Suite.generate()
        assert len(suite.public_key_compressed()) == 33
        assert suite.public_key_compressed()[0:1] in (b"\x02", b"\x03")

    def test_invalid_private_key_length_raises(self):
        with pytest.raises(ValueError):
            Secp256k1Suite(b"\x00" * 31)

    def test_deterministic_address(self):
        """Same private key always yields the same address."""
        key = b"\x01" * 32
        assert Secp256k1Suite(key).ethereum_address() == Secp256k1Suite(key).ethereum_address()


# ---------------------------------------------------------------------------
# Secp256k1Suite — signing and verification (secp256k1 / Vyper-compatible)
# ---------------------------------------------------------------------------


class TestSecp256k1SuiteSign:
    def setup_method(self):
        self.suite = Secp256k1Suite.generate()
        self.msg = b"MultiChainFragmentshub security test"

    def test_sign_returns_dict_with_expected_keys(self):
        sig = self.suite.sign(self.msg)
        assert {"r", "s", "v", "signature_hex", "message_hash_hex"}.issubset(sig)

    def test_v_is_27_or_28(self):
        for _ in range(10):
            suite = Secp256k1Suite.generate()
            sig = suite.sign(self.msg)
            assert sig["v"] in (27, 28)

    def test_signature_hex_is_65_bytes(self):
        sig = self.suite.sign(self.msg)
        raw = bytes.fromhex(sig["signature_hex"].removeprefix("0x"))
        assert len(raw) == 65

    def test_verify_correct_sig(self):
        sig = self.suite.sign(self.msg)
        assert self.suite.verify(self.msg, sig)

    def test_verify_wrong_message_fails(self):
        sig = self.suite.sign(self.msg)
        assert not self.suite.verify(b"different message", sig)

    def test_verify_wrong_key_fails(self):
        sig = self.suite.sign(self.msg)
        other = Secp256k1Suite.generate()
        assert not other.verify(self.msg, sig)

    def test_low_s_normalisation(self):
        """s must be in the lower half of the curve order (EIP-2)."""
        n_half = _sec._SECP256K1_N // 2
        for _ in range(20):
            suite = Secp256k1Suite.generate()
            sig = suite.sign(self.msg)
            assert sig["s"] <= n_half, f"s not normalised: {sig['s']}"


# ---------------------------------------------------------------------------
# Secp256k1Suite — address recovery (Vyper ecrecover compatible)
# ---------------------------------------------------------------------------


class TestSecp256k1SuiteRecover:
    def setup_method(self):
        self.suite = Secp256k1Suite.generate()
        self.msg = b"MultiChainFragmentshub recovery test"
        self.sig = self.suite.sign(self.msg)
        self.addr = self.suite.ethereum_address()

    def test_recover_returns_correct_address(self):
        recovered = Secp256k1Suite.recover_address(self.msg, self.sig)
        assert recovered.lower() == self.addr.lower()

    def test_recover_via_signature_hex(self):
        sig2 = {"signature_hex": self.sig["signature_hex"]}
        recovered = Secp256k1Suite.recover_address(self.msg, sig2)
        assert recovered.lower() == self.addr.lower()

    def test_recover_wrong_message_gives_different_address(self):
        recovered = Secp256k1Suite.recover_address(b"wrong message", self.sig)
        # Could be any address but must not equal ours
        assert recovered.lower() != self.addr.lower()

    def test_recover_multiple_key_pairs(self):
        for _ in range(5):
            suite = Secp256k1Suite.generate()
            msg = b"msg-" + suite.private_key_bytes()[:4]
            sig = suite.sign(msg)
            recovered = Secp256k1Suite.recover_address(msg, sig)
            assert recovered.lower() == suite.ethereum_address().lower()

    def test_recover_invalid_signature_hex_length_raises(self):
        with pytest.raises(ValueError, match="65 bytes"):
            Secp256k1Suite.recover_address(self.msg, {"signature_hex": "0x" + "ab" * 64})

    def test_recover_from_hash(self):
        msg_hash = bytes.fromhex(self.sig["message_hash_hex"].removeprefix("0x"))
        recovered = Secp256k1Suite.recover_address_from_hash(msg_hash, self.sig)
        assert recovered.lower() == self.addr.lower()

    def test_signature_missing_keys_raises(self):
        with pytest.raises(KeyError):
            Secp256k1Suite.recover_address(self.msg, {"r": 1})  # missing s, v


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


class TestInternalHelpers:
    def test_keccak256_known_vector(self):
        # keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
        result = _sec._keccak256(b"")
        assert result.hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"

    def test_eip55_checksum(self):
        # EIP-55 test vector from the EIP
        addr = "0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359"
        expected = "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
        assert _sec._eip55_checksum(addr) == expected

    def test_ec_scalar_mult_generator(self):
        G = (_sec._SECP256K1_Gx, _sec._SECP256K1_Gy)
        # 1 * G == G
        assert _sec._ec_scalar_mult(1, G) == G

    def test_ec_point_add_identity(self):
        G = (_sec._SECP256K1_Gx, _sec._SECP256K1_Gy)
        assert _sec._ec_point_add(None, G) == G
        assert _sec._ec_point_add(G, None) == G
