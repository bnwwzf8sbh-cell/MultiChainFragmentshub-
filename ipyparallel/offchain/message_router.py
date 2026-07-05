"""
MessageRouter
=============

Routes cross-chain messages between source and destination chains for the
MultiChainFragmentshub off-chain layer.

The router receives a decoded ``MessageDispatched`` event from the hub contract
(via :class:`~ipyparallel.offchain.connector.HubConnector`), determines the
target chain, and forwards the message using the registered chain endpoint.

Usage::

    import ipyparallel as ipp
    from ipyparallel.offchain import MessageRouter

    rc = ipp.Client()
    router = MessageRouter(
        chains={
            "chain-a": "https://rpc.chain-a.example.com",
            "chain-b": "https://rpc.chain-b.example.com",
        },
        client=rc,
    )

    # Route a decoded MessageDispatched event dict
    router.route({
        "source_chain": "chain-a",
        "dest_chain": "chain-b",
        "message_id": "msg-001",
        "payload": b"...",
    })
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Optional

log = logging.getLogger(__name__)


class MessageRouter:
    """Routes cross-chain messages between registered chain endpoints.

    Parameters
    ----------
    chains:
        Mapping of chain name → RPC URL.  At least one chain must be
        provided for meaningful routing.
    client:
        An :class:`ipyparallel.Client` instance used to distribute
        routing work across the cluster.  When *None* routing runs
        in-process.
    """

    def __init__(self, chains: dict[str, str], client=None) -> None:
        if not chains:
            raise ValueError("At least one chain endpoint must be provided.")
        self.chains: dict[str, str] = dict(chains)
        self._client = client
        self._middleware: list[Callable[[dict], dict]] = []
        self._result_handlers: list[Callable[[dict], Any]] = []

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def add_chain(self, name: str, rpc_url: str) -> None:
        """Register a new chain endpoint.

        Parameters
        ----------
        name:
            Logical chain identifier (e.g. ``"chain-a"``).
        rpc_url:
            JSON-RPC URL for the chain.
        """
        self.chains[name] = rpc_url
        log.info("Registered chain %r → %s", name, rpc_url)

    def add_middleware(self, fn: Callable[[dict], dict]) -> None:
        """Append a middleware function to the processing pipeline.

        Each middleware receives the message dict and must return a
        (possibly modified) dict.  Middlewares are applied in order.
        """
        self._middleware.append(fn)

    def on_result(self, handler: Callable[[dict], Any]) -> None:
        """Register a callback to be called after a message is forwarded."""
        self._result_handlers.append(handler)

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------

    def route(self, message: dict) -> dict:
        """Route *message* to its destination chain.

        Parameters
        ----------
        message:
            A decoded event dict.  Expected keys:

            ``dest_chain`` (str)
                Name of the destination chain (must be registered).
            ``message_id`` (str)
                Unique message identifier.
            ``payload`` (bytes or hex str)
                Message payload.
            ``source_chain`` (str, optional)
                Name of the originating chain.

        Returns the (possibly middleware-transformed) message dict augmented
        with a ``"status"`` key (``"forwarded"`` or ``"dropped"``).
        """
        # Apply middleware pipeline
        msg = dict(message)
        for mw in self._middleware:
            try:
                msg = mw(msg)
                if msg is None:
                    log.warning("Middleware returned None; dropping message.")
                    return {**message, "status": "dropped"}
            except Exception as exc:
                log.error("Middleware %r raised: %s — dropping message.", mw, exc)
                return {**message, "status": "dropped"}

        dest = msg.get("dest_chain")
        if not dest:
            log.error("Message %r has no dest_chain; dropping.", msg.get("message_id"))
            return {**msg, "status": "dropped"}

        if dest not in self.chains:
            log.error(
                "Unknown destination chain %r for message %r; dropping.",
                dest,
                msg.get("message_id"),
            )
            return {**msg, "status": "dropped"}

        rpc_url = self.chains[dest]

        if self._client is not None:
            self._forward_via_cluster(msg, dest, rpc_url)
        else:
            self._forward_local(msg, dest, rpc_url)

        result = {**msg, "status": "forwarded"}
        for handler in self._result_handlers:
            try:
                handler(result)
            except Exception as exc:
                log.error("Result handler %r raised: %s", handler, exc)

        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _forward_local(self, message: dict, dest: str, rpc_url: str) -> None:
        """Forward *message* to *dest* in-process (stub implementation).

        Override or subclass to add real on-chain transaction submission,
        e.g. using ``web3.py``::

            from web3 import Web3
            w3 = Web3(Web3.HTTPProvider(rpc_url))
            contract = w3.eth.contract(address=HUB_ADDRESS, abi=HUB_ABI)
            tx = contract.functions.receiveMessage(
                message["message_id"],
                message["payload"],
            ).build_transaction({...})
            signed = w3.eth.account.sign_transaction(tx, private_key=PRIVATE_KEY)
            w3.eth.send_raw_transaction(signed.rawTransaction)
        """
        log.info(
            "Forwarding message %r to chain %r (%s) [local stub].",
            message.get("message_id"),
            dest,
            rpc_url,
        )

    def _forward_via_cluster(self, message: dict, dest: str, rpc_url: str) -> None:
        """Forward *message* using the ipyparallel cluster."""
        try:
            view = self._client.load_balanced_view()
            ar = view.apply_async(
                _remote_forward,
                message,
                dest,
                rpc_url,
            )
            ar.get(timeout=30)
            log.info(
                "Forwarded message %r to chain %r via cluster.",
                message.get("message_id"),
                dest,
            )
        except Exception as exc:
            log.warning(
                "Cluster forwarding failed for message %r (%s); falling back to local stub.",
                message.get("message_id"),
                exc,
            )
            self._forward_local(message, dest, rpc_url)


# ---------------------------------------------------------------------------
# Remote function (executed on ipyparallel engines)
# ---------------------------------------------------------------------------


def _remote_forward(message: dict, dest: str, rpc_url: str) -> None:
    """Engine-side stub for forwarding a message to an on-chain endpoint.

    Replace the body of this function with a real ``web3.py`` call
    to submit the message transaction to the destination chain.
    """
    import logging as _logging

    _log = _logging.getLogger(__name__)
    _log.info("Engine forwarding message %r to %r (%s).", message.get("message_id"), dest, rpc_url)
