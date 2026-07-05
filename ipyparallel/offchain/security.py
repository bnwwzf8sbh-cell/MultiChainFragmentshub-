"""
Security utilities for the MultiChainFragmentshub off-chain layer
=================================================================

This module provides two classes:

:class:`HashSuite`
    Thin wrappers around Python's :mod:`hashlib` exposing SHA-1, SHA-256,
    and SHA-512 digests with both one-shot and streaming interfaces.

:class:`Secp256k1Suite`
    ECDSA key-management and signing/verification on the **secp256k1** curve,
    wire-compatible with Ethereum/Vyper's ``ecrecover`` precompile (EIP-191
    personal-sign prefix).  Requires the ``cryptography`` package.

Usage::

    from ipyparallel.offchain.security import HashSuite, Secp256k1Suite

    # --- hashing ---
    hs = HashSuite()
    print(hs.sha256(b"hello"))          # hex digest
    print(hs.sha256(b"hello", raw=True))  # raw bytes

    # --- secp256k1 / Vyper-compatible signing ---
    suite = Secp256k1Suite.generate()
    sig = suite.sign(b"my message")
    assert suite.verify(b"my message", sig)

    address = suite.ethereum_address()
    recovered = Secp256k1Suite.recover_address(b"my message", sig)
    assert recovered == address
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import struct
from typing import Optional

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Lazy import guard for the optional `cryptography` dependency
# ---------------------------------------------------------------------------

def _require_cryptography():
    try:
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import (
            decode_dss_signature,
            encode_dss_signature,
            Prehashed,
        )
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.backends import default_backend
        return (
            ec,
            decode_dss_signature,
            encode_dss_signature,
            hashes,
            serialization,
            default_backend,
            Prehashed,
        )
    except ImportError as exc:
        raise ImportError(
            "The 'cryptography' package is required for Secp256k1Suite. "
            "Install it with:  pip install cryptography"
        ) from exc


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# EIP-191 personal-sign prefix (Ethereum / Vyper ecrecover)
_ETH_PREFIX = b"\x19Ethereum Signed Message:\n32"

# secp256k1 order n
_SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# secp256k1 field prime p
_SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F


# ---------------------------------------------------------------------------
# HashSuite
# ---------------------------------------------------------------------------


class HashSuite:
    """One-shot and streaming hash helpers for SHA-1, SHA-256, and SHA-512.

    .. warning::
        **SHA-1 is cryptographically broken** and included only for
        compatibility with legacy protocols (e.g. Git object IDs, older
        TLS handshakes).  Use SHA-256 or SHA-512 for new security-critical
        code.
    """

    # ------------------------------------------------------------------
    # One-shot digests
    # ------------------------------------------------------------------

    @staticmethod
    def sha1(data: bytes, *, raw: bool = False) -> str | bytes:
        """Return the SHA-1 digest of *data*.

        Parameters
        ----------
        data:  Bytes to hash.
        raw:   When *True* return raw bytes; otherwise return a lowercase
               hex string.

        .. warning:: SHA-1 is broken against collision attacks.
        """
        digest = hashlib.sha1(data).digest()
        return digest if raw else digest.hex()

    @staticmethod
    def sha256(data: bytes, *, raw: bool = False) -> str | bytes:
        """Return the SHA-256 digest of *data*.

        Parameters
        ----------
        data:  Bytes to hash.
        raw:   When *True* return raw bytes; otherwise return a lowercase
               hex string.
        """
        digest = hashlib.sha256(data).digest()
        return digest if raw else digest.hex()

    @staticmethod
    def sha512(data: bytes, *, raw: bool = False) -> str | bytes:
        """Return the SHA-512 digest of *data*.

        Parameters
        ----------
        data:  Bytes to hash.
        raw:   When *True* return raw bytes; otherwise return a lowercase
               hex string.
        """
        digest = hashlib.sha512(data).digest()
        return digest if raw else digest.hex()

    # ------------------------------------------------------------------
    # Streaming interface
    # ------------------------------------------------------------------

    @staticmethod
    def hasher(algorithm: str = "sha256") -> "hashlib._Hash":
        """Return a fresh :mod:`hashlib` hash object for *algorithm*.

        Parameters
        ----------
        algorithm:
            One of ``"sha1"``, ``"sha256"``, ``"sha512"``.
        """
        algo = algorithm.lower()
        if algo not in ("sha1", "sha256", "sha512"):
            raise ValueError(
                f"Unsupported algorithm {algorithm!r}. "
                "Choose from: 'sha1', 'sha256', 'sha512'."
            )
        return hashlib.new(algo)

    # ------------------------------------------------------------------
    # HMAC helpers
    # ------------------------------------------------------------------

    @staticmethod
    def hmac_sha256(key: bytes, data: bytes) -> bytes:
        """Return HMAC-SHA-256(*key*, *data*) as raw bytes."""
        return hmac.new(key, data, hashlib.sha256).digest()

    @staticmethod
    def hmac_sha512(key: bytes, data: bytes) -> bytes:
        """Return HMAC-SHA-512(*key*, *data*) as raw bytes."""
        return hmac.new(key, data, hashlib.sha512).digest()

    # ------------------------------------------------------------------
    # Fragment-hashing helper (used by FragmentProcessor)
    # ------------------------------------------------------------------

    @staticmethod
    def fragment_checksum(data: bytes) -> str:
        """Return a truncated hex SHA-256 checksum (16 chars) of *data*."""
        return hashlib.sha256(data).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Secp256k1Suite
# ---------------------------------------------------------------------------


class Secp256k1Suite:
    """ECDSA signing and verification on the secp256k1 curve.

    Wire-compatible with Ethereum / Vyper's ``ecrecover`` precompile using
    the EIP-191 personal-sign message prefix.

    Parameters
    ----------
    private_key_bytes:
        32-byte big-endian private key scalar.  Generate one with
        :meth:`generate` or load one with :meth:`from_private_key_bytes`.
    """

    def __init__(self, private_key_bytes: bytes) -> None:
        if len(private_key_bytes) != 32:
            raise ValueError("Private key must be exactly 32 bytes.")
        ec, _, _, _, _, backend, _ = _require_cryptography()
        self._ec = ec
        self._backend = backend
        self._private_key = ec.derive_private_key(
            int.from_bytes(private_key_bytes, "big"),
            ec.SECP256K1(),
            backend(),
        )
        self._private_key_bytes = private_key_bytes

    # ------------------------------------------------------------------
    # Constructors
    # ------------------------------------------------------------------

    @classmethod
    def generate(cls) -> "Secp256k1Suite":
        """Generate a new random secp256k1 key pair."""
        ec, _, _, _, _, backend, _ = _require_cryptography()
        raw_key = ec.generate_private_key(ec.SECP256K1(), backend())
        key_int = raw_key.private_numbers().private_value
        return cls(key_int.to_bytes(32, "big"))

    @classmethod
    def from_private_key_bytes(cls, key_bytes: bytes) -> "Secp256k1Suite":
        """Load a suite from a 32-byte big-endian private key."""
        return cls(key_bytes)

    @classmethod
    def from_private_key_hex(cls, hex_str: str) -> "Secp256k1Suite":
        """Load a suite from a 64-char hex private key string."""
        return cls(bytes.fromhex(hex_str.removeprefix("0x")))

    # ------------------------------------------------------------------
    # Key export
    # ------------------------------------------------------------------

    def private_key_bytes(self) -> bytes:
        """Return the raw 32-byte private key."""
        return self._private_key_bytes

    def private_key_hex(self) -> str:
        """Return the private key as a 0x-prefixed hex string."""
        return "0x" + self._private_key_bytes.hex()

    def public_key_uncompressed(self) -> bytes:
        """Return the 65-byte uncompressed public key (04 || X || Y)."""
        _, _, _, _, serialization, _, _ = _require_cryptography()
        return self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )

    def public_key_compressed(self) -> bytes:
        """Return the 33-byte compressed public key (02/03 || X)."""
        _, _, _, _, serialization, _, _ = _require_cryptography()
        return self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint,
        )

    def ethereum_address(self) -> str:
        """Return the EIP-55 checksummed Ethereum address derived from this key.

        The address is ``keccak256(uncompressed_pubkey[1:])[12:]``, formatted
        as a 0x-prefixed 40-char hex string with EIP-55 checksum.
        """
        pub = self.public_key_uncompressed()[1:]  # drop 04 prefix
        addr_bytes = _keccak256(pub)[12:]
        return _eip55_checksum("0x" + addr_bytes.hex())

    # ------------------------------------------------------------------
    # Signing
    # ------------------------------------------------------------------

    def sign(self, message: bytes) -> dict:
        """Sign *message* with EIP-191 personal-sign prefix.

        The message is prefixed as ``\\x19Ethereum Signed Message:\\n32``
        followed by the SHA-256 hash of *message*, making signatures
        verifiable by Vyper's ``ecrecover`` precompile.

        Returns a dict with keys:

        ``r`` (int), ``s`` (int), ``v`` (int)
            ECDSA signature components.  *v* is 27 or 28 (Ethereum convention).
        ``signature_hex`` (str)
            65-byte ``r || s || v`` packed as a 0x-prefixed hex string.
        ``message_hash_hex`` (str)
            Hex of the prefixed message hash that was signed.
        """
        ec, decode_dss_signature, _, hashes, _, backend, Prehashed = _require_cryptography()

        msg_hash = _eth_prefixed_hash(message)

        # Sign the 32-byte hash directly (Prehashed)
        der_sig = self._private_key.sign(msg_hash, ec.ECDSA(Prehashed(hashes.SHA256())))
        r, s = decode_dss_signature(der_sig)

        # Low-s normalisation (EIP-2)
        if s > _SECP256K1_N // 2:
            s = _SECP256K1_N - s

        # Recover v (27 or 28)
        v = _recover_v(msg_hash, r, s, self.public_key_uncompressed())

        sig_bytes = (
            r.to_bytes(32, "big")
            + s.to_bytes(32, "big")
            + bytes([v])
        )
        return {
            "r": r,
            "s": s,
            "v": v,
            "signature_hex": "0x" + sig_bytes.hex(),
            "message_hash_hex": "0x" + msg_hash.hex(),
        }

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify(self, message: bytes, sig: dict) -> bool:
        """Verify *sig* (as returned by :meth:`sign`) against *message*.

        Returns *True* iff the signature is valid for this key pair.
        """
        try:
            recovered = self.recover_address(message, sig)
            return recovered.lower() == self.ethereum_address().lower()
        except Exception as exc:
            log.debug("Signature verification failed: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Address recovery (Vyper ecrecover compatible)
    # ------------------------------------------------------------------

    @staticmethod
    def recover_address(message: bytes, sig: dict) -> str:
        """Recover the Ethereum address that produced *sig* for *message*.

        Compatible with Vyper's built-in ``ecrecover`` and Solidity's
        ``ecrecover`` precompile.

        Parameters
        ----------
        message:
            Original (un-prefixed) message bytes.
        sig:
            Dict with keys ``r``, ``s``, ``v`` **or** ``signature_hex``
            (65-byte ``r || s || v`` hex string).

        Returns the 0x-prefixed EIP-55 checksummed Ethereum address.
        """
        r, s, v = _parse_signature(sig)
        msg_hash = _eth_prefixed_hash(message)
        pub_bytes = _secp256k1_recover(msg_hash, r, s, v)
        addr_bytes = _keccak256(pub_bytes[1:])[12:]
        return _eip55_checksum("0x" + addr_bytes.hex())

    @staticmethod
    def recover_address_from_hash(msg_hash: bytes, sig: dict) -> str:
        """Like :meth:`recover_address` but accepts a pre-computed message hash.

        Use this when you already hold the 32-byte EIP-191 prefixed hash
        (e.g. received from the on-chain hub contract).
        """
        r, s, v = _parse_signature(sig)
        pub_bytes = _secp256k1_recover(msg_hash, r, s, v)
        addr_bytes = _keccak256(pub_bytes[1:])[12:]
        return _eip55_checksum("0x" + addr_bytes.hex())


# ---------------------------------------------------------------------------
# Internal cryptographic helpers
# ---------------------------------------------------------------------------


def _eth_prefixed_hash(message: bytes) -> bytes:
    """Return keccak256(EIP-191 prefix || sha256(message)).

    The SHA-256 of the message is used as the 32-byte body so that the
    total prefixed payload is always 60 bytes regardless of message length,
    matching the most common Vyper/Solidity signing pattern.
    """
    body = hashlib.sha256(message).digest()
    return _keccak256(_ETH_PREFIX + body)


def _keccak256(data: bytes) -> bytes:
    """Return Keccak-256 of *data* using hashlib (Python 3.6+)."""
    h = hashlib.new("sha3_256")
    # Python's sha3_256 is SHA-3 (NIST), not Keccak-256.
    # We use the pure-Python Keccak implementation below.
    return _keccak256_pure(data)


def _keccak256_pure(data: bytes) -> bytes:
    """Pure-Python Keccak-256 (the pre-standardisation variant used by Ethereum)."""
    # Keccak-256 parameters
    rate = 1088  # bits
    capacity = 512  # bits
    output_length = 256  # bits
    return _keccak(data, rate, capacity, output_length, b'\x01')


def _keccak(message: bytes, rate_bits: int, capacity_bits: int,
             output_bits: int, delimited_suffix: bytes) -> bytes:
    """Keccak sponge function (as used by Ethereum for addresses/hashes)."""
    rate_bytes = rate_bits // 8
    output_bytes = output_bits // 8

    # Padding
    msg = bytearray(message)
    msg += delimited_suffix
    if len(msg) % rate_bytes == 0:
        msg[-1] ^= 0x80
    else:
        while len(msg) % rate_bytes != rate_bytes - 1:
            msg += b'\x00'
        msg += bytes([0x80])

    # State: 5×5 lane array of 64-bit words
    state = [[0] * 5 for _ in range(5)]

    # Absorb
    block_count = len(msg) // rate_bytes
    for block_idx in range(block_count):
        block = msg[block_idx * rate_bytes:(block_idx + 1) * rate_bytes]
        for i in range(rate_bytes // 8):
            x, y = i % 5, i // 5
            word = struct.unpack_from('<Q', block, i * 8)[0]
            state[x][y] ^= word
        state = _keccak_f(state)

    # Squeeze
    output = bytearray()
    while len(output) < output_bytes:
        for y in range(5):
            for x in range(5):
                if len(output) >= output_bytes:
                    break
                output += struct.pack('<Q', state[x][y])
        if len(output) < output_bytes:
            state = _keccak_f(state)

    return bytes(output[:output_bytes])


# Keccak-f[1600] round constants
_KECCAK_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

_KECCAK_RHO = [
    [0,  36,  3, 41, 18],
    [1,  44, 10, 45,  2],
    [62,  6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39,  8, 14],
]

def _rot64(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF


def _keccak_f(state):
    for rc in _KECCAK_RC:
        # Theta
        C = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4]
             for x in range(5)]
        D = [C[(x - 1) % 5] ^ _rot64(C[(x + 1) % 5], 1) for x in range(5)]
        state = [[state[x][y] ^ D[x] for y in range(5)] for x in range(5)]

        # Rho + Pi
        B = [[0] * 5 for _ in range(5)]
        for y in range(5):
            for x in range(5):
                B[y][(2 * x + 3 * y) % 5] = _rot64(state[x][y], _KECCAK_RHO[x][y])

        # Chi
        state = [
            [B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y]) for y in range(5)]
            for x in range(5)
        ]

        # Iota
        state[0][0] ^= rc

    return state


# ---------------------------------------------------------------------------
# secp256k1 curve parameters
# ---------------------------------------------------------------------------

_SECP256K1_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_SECP256K1_Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def _ec_point_add(P1, P2):
    """Add two secp256k1 affine points (or None for point-at-infinity)."""
    if P1 is None:
        return P2
    if P2 is None:
        return P1
    x1, y1 = P1
    x2, y2 = P2
    p = _SECP256K1_P
    if x1 == x2:
        if y1 != y2:
            return None  # point at infinity
        # Point doubling
        m = (3 * x1 * x1 * pow(2 * y1, p - 2, p)) % p
    else:
        m = ((y2 - y1) * pow(x2 - x1, p - 2, p)) % p
    x3 = (m * m - x1 - x2) % p
    y3 = (m * (x1 - x3) - y1) % p
    return (x3, y3)


def _ec_scalar_mult(k, point):
    """Scalar multiplication k * point on secp256k1."""
    result = None
    addend = point
    while k:
        if k & 1:
            result = _ec_point_add(result, addend)
        addend = _ec_point_add(addend, addend)
        k >>= 1
    return result


def _ec_recover_pubkey(msg_hash: bytes, r: int, s: int, recovery_id: int):
    """Return the secp256k1 public-key point (x, y) from an ECDSA signature.

    Implements the standard ECDSA recovery formula:
        Q = r^{-1} * (s * R  -  e * G)
    where R is the ephemeral-key point reconstructed from *r* and
    *recovery_id* (0 or 1).
    """
    p = _SECP256K1_P
    n = _SECP256K1_N
    G = (_SECP256K1_Gx, _SECP256K1_Gy)

    e = int.from_bytes(msg_hash, "big")

    # Reconstruct the ephemeral public-key point R
    x = r + (recovery_id >> 1) * n  # usually just r (recovery_id >> 1 == 0)
    if x >= p:
        raise ValueError("r value out of range.")
    y_sq = (pow(x, 3, p) + 7) % p
    y = pow(y_sq, (p + 1) // 4, p)
    if y % 2 != recovery_id % 2:
        y = p - y
    R = (x, y)

    # Q = r^{-1} * (s * R  -  e * G)
    r_inv = pow(r, n - 2, n)
    neg_e = n - (e % n)
    sR = _ec_scalar_mult(s % n, R)
    neg_eG = _ec_scalar_mult(neg_e, G)
    Q = _ec_scalar_mult(r_inv, _ec_point_add(sR, neg_eG))
    return Q


def _secp256k1_recover(msg_hash: bytes, r: int, s: int, v: int) -> bytes:
    """Recover the 65-byte uncompressed public key from an ECDSA signature.

    *v* must be 27 or 28 (Ethereum convention) or 0 or 1.
    """
    recovery_id = (v - 27) if v in (27, 28) else int(v)
    if recovery_id not in (0, 1):
        raise ValueError(f"Invalid v value: {v!r}. Expected 27, 28, 0, or 1.")

    Q = _ec_recover_pubkey(msg_hash, r, s, recovery_id)
    if Q is None:
        raise ValueError("Recovered point is the point at infinity.")
    qx, qy = Q
    return b'\x04' + qx.to_bytes(32, 'big') + qy.to_bytes(32, 'big')


def _recover_v(msg_hash: bytes, r: int, s: int, public_key_uncompressed: bytes) -> int:
    """Determine the recovery parameter *v* (27 or 28) for a signature."""
    for recovery_id in (0, 1):
        try:
            candidate = _secp256k1_recover(msg_hash, r, s, recovery_id)
            if candidate == public_key_uncompressed:
                return 27 + recovery_id
        except ValueError:
            continue
    raise ValueError("Could not determine v for signature.")




def _parse_signature(sig: dict) -> tuple[int, int, int]:
    """Extract (r, s, v) from a signature dict or ``signature_hex``."""
    if "r" in sig and "s" in sig and "v" in sig:
        return int(sig["r"]), int(sig["s"]), int(sig["v"])
    if "signature_hex" in sig:
        raw = bytes.fromhex(sig["signature_hex"].removeprefix("0x"))
        if len(raw) != 65:
            raise ValueError(
                f"signature_hex must encode 65 bytes (r||s||v), got {len(raw)}."
            )
        r = int.from_bytes(raw[:32], "big")
        s = int.from_bytes(raw[32:64], "big")
        v = raw[64]
        return r, s, v
    raise KeyError("Signature dict must contain 'r'/'s'/'v' or 'signature_hex'.")


def _eip55_checksum(address: str) -> str:
    """Apply EIP-55 mixed-case checksum encoding to a 0x-prefixed address."""
    addr = address.removeprefix("0x").lower()
    addr_hash = _keccak256(addr.encode("ascii")).hex()
    checksummed = "".join(
        c.upper() if int(addr_hash[i], 16) >= 8 else c
        for i, c in enumerate(addr)
    )
    return "0x" + checksummed
