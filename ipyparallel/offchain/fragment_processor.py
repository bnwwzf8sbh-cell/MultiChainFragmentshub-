"""
FragmentProcessor
=================

Handles assembly and disassembly of cross-chain data fragments for the
MultiChainFragmentshub off-chain layer.

Fragments are pieces of data that originate on one chain, are submitted to
the hub contract, and need to be reassembled off-chain before the result is
written back on-chain (or forwarded to another chain).

Usage::

    import ipyparallel as ipp
    from ipyparallel.offchain import FragmentProcessor

    rc = ipp.Client()
    fp = FragmentProcessor(client=rc, timeout=30.0)

    # Process a single raw fragment payload dict
    result = fp.process({"id": "frag-1", "data": b"...", "index": 0, "total": 3})

    # Once all parts have arrived, assemble them
    assembled = fp.assemble("frag-1")
"""

from __future__ import annotations

import hashlib
import logging
import time
from typing import Any, Optional

log = logging.getLogger(__name__)


class FragmentProcessor:
    """Assembles and disassembles cross-chain data fragments.

    Parameters
    ----------
    client:
        An :class:`ipyparallel.Client` instance.  When *None* fragments are
        processed in-process (useful for testing).
    timeout:
        Seconds to wait for all fragment parts before raising
        :exc:`TimeoutError`.  Default is ``30.0``.
    """

    def __init__(self, client=None, timeout: float = 30.0) -> None:
        self._client = client
        self.timeout: float = timeout
        # Keyed by fragment_id → list of (index, data) pairs
        self._pending: dict[str, list[tuple[int, bytes]]] = {}
        # Keyed by fragment_id → total expected parts
        self._totals: dict[str, int] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def process(self, payload: dict) -> dict:
        """Process a raw fragment *payload* and return a status dict.

        Expected *payload* keys:

        ``id`` (str)
            Unique identifier shared by all parts of the same fragment.
        ``data`` (bytes or hex str)
            Raw fragment data for this part.
        ``index`` (int)
            Zero-based index of this part within the fragment.
        ``total`` (int)
            Total number of parts that make up this fragment.

        Returns a dict with keys ``fragment_id``, ``received``, ``total``,
        and ``complete`` (bool).
        """
        fragment_id: str = str(payload["id"])
        raw_data: bytes = self._coerce_bytes(payload["data"])
        index: int = int(payload["index"])
        total: int = int(payload["total"])

        if fragment_id not in self._pending:
            self._pending[fragment_id] = []
            self._totals[fragment_id] = total

        parts = self._pending[fragment_id]
        # Avoid duplicates
        existing_indices = {p[0] for p in parts}
        if index not in existing_indices:
            parts.append((index, raw_data))
            log.debug(
                "Fragment %r: stored part %d/%d", fragment_id, index + 1, total
            )

        received = len(parts)
        complete = received == total
        return {
            "fragment_id": fragment_id,
            "received": received,
            "total": total,
            "complete": complete,
        }

    def assemble(self, fragment_id: str) -> bytes:
        """Assemble all received parts for *fragment_id* into a single bytestring.

        Blocks (up to :attr:`timeout` seconds) until all parts have arrived.

        Raises
        ------
        TimeoutError
            If all parts do not arrive within *timeout* seconds.
        KeyError
            If *fragment_id* has never been seen.
        """
        if fragment_id not in self._pending:
            raise KeyError(f"Unknown fragment_id: {fragment_id!r}")

        deadline = time.monotonic() + self.timeout
        while True:
            parts = self._pending[fragment_id]
            total = self._totals[fragment_id]
            if len(parts) == total:
                break
            if time.monotonic() > deadline:
                raise TimeoutError(
                    f"Fragment {fragment_id!r}: timed out waiting for parts "
                    f"({len(parts)}/{total} received after {self.timeout}s)."
                )
            time.sleep(0.1)

        # Sort by index and concatenate
        sorted_parts = sorted(parts, key=lambda p: p[0])
        assembled = b"".join(data for _, data in sorted_parts)

        # Dispatch heavy processing to the cluster if available
        if self._client is not None:
            assembled = self._offload_processing(fragment_id, assembled)

        # Clean up
        del self._pending[fragment_id]
        del self._totals[fragment_id]

        log.info(
            "Fragment %r assembled: %d bytes (sha256=%s)",
            fragment_id,
            len(assembled),
            hashlib.sha256(assembled).hexdigest()[:16],
        )
        return assembled

    def disassemble(self, data: bytes, fragment_id: str, part_size: int = 32768) -> list[dict]:
        """Split *data* into fragment parts ready to be submitted on-chain.

        Parameters
        ----------
        data:
            Raw bytes to split.
        fragment_id:
            Identifier shared by all produced parts.
        part_size:
            Maximum bytes per part (default 32 KiB).

        Returns a list of payload dicts suitable for :meth:`process`.
        """
        parts = [data[i:i + part_size] for i in range(0, len(data), part_size)]
        total = len(parts)
        payloads = [
            {"id": fragment_id, "data": part, "index": idx, "total": total}
            for idx, part in enumerate(parts)
        ]
        log.debug("Disassembled %d bytes into %d parts (id=%r).", len(data), total, fragment_id)
        return payloads

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _offload_processing(self, fragment_id: str, data: bytes) -> bytes:
        """Dispatch *data* to the cluster for processing; return the result.

        This is a passthrough stub — subclass and override to add real
        off-chain computation (e.g. ZK proof generation, heavy decoding).
        """
        try:
            view = self._client[:]
            ar = view.apply_async(lambda d: d, data)
            return ar.get(timeout=self.timeout)
        except Exception as exc:
            log.warning(
                "Cluster offload failed for fragment %r (%s); using local result.",
                fragment_id,
                exc,
            )
            return data

    @staticmethod
    def _coerce_bytes(value: Any) -> bytes:
        """Accept bytes, bytearray, or a hex string and return bytes."""
        if isinstance(value, (bytes, bytearray)):
            return bytes(value)
        if isinstance(value, str):
            return bytes.fromhex(value.removeprefix("0x"))
        raise TypeError(f"Cannot coerce {type(value).__name__!r} to bytes.")
