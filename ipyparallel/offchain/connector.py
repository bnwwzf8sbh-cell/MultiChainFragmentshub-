"""
HubConnector
============

Connects to a MultiChainFragmentshub hub contract via an EVM-compatible
JSON-RPC endpoint, polls for ``FragmentSubmitted`` and ``MessageDispatched``
events, and dispatches the corresponding work to the ipyparallel cluster.

Configuration (environment variables or keyword arguments):

``MCF_RPC_URL``
    RPC endpoint URL for the hub chain.
``MCF_HUB_ADDRESS``
    Deployed hub contract address (0x-prefixed hex string).
``MCF_CLUSTER_PROFILE``
    ipyparallel profile name (default: ``"default"``).
``MCF_POLL_INTERVAL``
    Seconds between RPC polls (default: ``"2"``).
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any, Callable, Optional

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SENTINEL = object()


def _env(key: str, default: Any = _SENTINEL) -> str:
    """Return an environment variable or *default*; raise if neither is set."""
    value = os.environ.get(key)
    if value is not None:
        return value
    if default is not _SENTINEL:
        return default
    raise RuntimeError(
        f"Required environment variable {key!r} is not set and no default was provided."
    )


# ---------------------------------------------------------------------------
# HubConnector
# ---------------------------------------------------------------------------


class HubConnector:
    """Listens for on-chain MultiChainFragmentshub events and dispatches
    off-chain tasks to an ipyparallel cluster.

    Parameters
    ----------
    rpc_url:
        JSON-RPC endpoint URL.  Falls back to the ``MCF_RPC_URL`` environment
        variable if not provided.
    hub_address:
        Deployed hub contract address.  Falls back to ``MCF_HUB_ADDRESS``.
    client:
        An already-connected :class:`ipyparallel.Client` instance.  When
        *None* the connector will create its own client using *cluster_profile*.
    cluster_profile:
        ipyparallel profile name used when *client* is *None*.  Falls back to
        ``MCF_CLUSTER_PROFILE`` (default ``"default"``).
    poll_interval:
        Seconds between RPC polls.  Falls back to ``MCF_POLL_INTERVAL``
        (default ``2.0``).
    max_retries:
        Maximum number of consecutive RPC failures before giving up.
    """

    def __init__(
        self,
        rpc_url: Optional[str] = None,
        hub_address: Optional[str] = None,
        client=None,
        cluster_profile: Optional[str] = None,
        poll_interval: Optional[float] = None,
        max_retries: int = 5,
    ) -> None:
        self.rpc_url: str = rpc_url or _env("MCF_RPC_URL")
        self.hub_address: str = hub_address or _env("MCF_HUB_ADDRESS")
        self.cluster_profile: str = cluster_profile or _env(
            "MCF_CLUSTER_PROFILE", "default"
        )
        self.poll_interval: float = float(
            poll_interval if poll_interval is not None else _env("MCF_POLL_INTERVAL", "2")
        )
        self.max_retries: int = max_retries

        # Lazily import ipyparallel so the module can be imported even when
        # ipyparallel is not fully installed.
        self._client = client
        self._owns_client = client is None

        self._running = False
        self._fragment_handlers: list[Callable] = []
        self._message_handlers: list[Callable] = []

        # Track the last processed block to avoid re-processing events.
        self._last_block: int = 0

    # ------------------------------------------------------------------
    # Handler registration
    # ------------------------------------------------------------------

    def on_fragment_event(self, handler: Callable[[dict], Any]) -> None:
        """Register *handler* to be called for every ``FragmentSubmitted`` event.

        The handler receives a single ``dict`` with the decoded event fields.
        """
        self._fragment_handlers.append(handler)

    def on_message_event(self, handler: Callable[[dict], Any]) -> None:
        """Register *handler* to be called for every ``MessageDispatched`` event.

        The handler receives a single ``dict`` with the decoded event fields.
        """
        self._message_handlers.append(handler)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the synchronous event-polling loop (blocking).

        Use :meth:`start_async` from an async context instead.
        """
        self._running = True
        self._ensure_client()
        log.info(
            "HubConnector started (rpc=%s, hub=%s, poll_interval=%.1fs)",
            self.rpc_url,
            self.hub_address,
            self.poll_interval,
        )
        retries = 0
        while self._running:
            try:
                self._poll_once()
                retries = 0
            except Exception as exc:
                retries += 1
                log.error(
                    "RPC poll error (attempt %d/%d): %s", retries, self.max_retries, exc
                )
                if retries >= self.max_retries:
                    log.critical("Max retries exceeded — stopping HubConnector.")
                    self.stop()
                    raise
            time.sleep(self.poll_interval)

    async def start_async(self) -> None:
        """Start the event-polling loop as an async coroutine."""
        self._running = True
        self._ensure_client()
        log.info(
            "HubConnector started (async, rpc=%s, hub=%s)", self.rpc_url, self.hub_address
        )
        retries = 0
        while self._running:
            try:
                await asyncio.get_event_loop().run_in_executor(None, self._poll_once)
                retries = 0
            except Exception as exc:
                retries += 1
                log.error("RPC poll error (attempt %d/%d): %s", retries, self.max_retries, exc)
                if retries >= self.max_retries:
                    log.critical("Max retries exceeded — stopping HubConnector.")
                    self.stop()
                    raise
            await asyncio.sleep(self.poll_interval)

    def stop(self) -> None:
        """Gracefully stop the event-polling loop."""
        self._running = False
        if self._owns_client and self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None
        log.info("HubConnector stopped.")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ensure_client(self) -> None:
        """Initialise the ipyparallel client if not already done."""
        if self._client is not None:
            return
        try:
            import ipyparallel as ipp

            self._client = ipp.Client(profile=self.cluster_profile)
            log.info("Connected to ipyparallel cluster (profile=%r).", self.cluster_profile)
        except Exception as exc:
            log.warning(
                "Could not connect to ipyparallel cluster (%s). "
                "Off-chain tasks will run in-process.",
                exc,
            )

    def _poll_once(self) -> None:
        """Fetch new events from the RPC endpoint and dispatch them."""
        events = self._fetch_events()
        for event in events:
            etype = event.get("event")
            if etype == "FragmentSubmitted":
                self._dispatch(event, self._fragment_handlers)
            elif etype == "MessageDispatched":
                self._dispatch(event, self._message_handlers)
            else:
                log.debug("Ignored unknown event type: %s", etype)

    def _fetch_events(self) -> list[dict]:
        """Return new hub contract events since the last polled block.

        This is a *stub* implementation that returns an empty list.  Replace
        (or subclass and override) this method with a real web3 / RPC call
        appropriate for your chain.

        Example using ``web3.py``::

            from web3 import Web3
            w3 = Web3(Web3.HTTPProvider(self.rpc_url))
            contract = w3.eth.contract(address=self.hub_address, abi=HUB_ABI)
            current_block = w3.eth.block_number
            raw = contract.events.FragmentSubmitted.get_logs(
                from_block=self._last_block + 1,
                to_block=current_block,
            )
            self._last_block = current_block
            return [dict(event="FragmentSubmitted", **r["args"]) for r in raw]
        """
        return []

    @staticmethod
    def _dispatch(event: dict, handlers: list[Callable]) -> None:
        """Call each registered *handler* with *event*."""
        for handler in handlers:
            try:
                handler(event)
            except Exception as exc:
                log.error("Handler %r raised: %s", handler, exc)
