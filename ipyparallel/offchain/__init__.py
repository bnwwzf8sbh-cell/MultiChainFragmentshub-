"""
ipyparallel.offchain
====================

Off-chain integration layer for the MultiChainFragmentshub project.

This package bridges on-chain hub contract events with the ipyparallel
parallel-compute cluster.  The three primary entry points are:

- :class:`HubConnector`      – listens for on-chain events and dispatches tasks
- :class:`FragmentProcessor` – assembles/disassembles cross-chain fragments
- :class:`MessageRouter`     – routes cross-chain messages between networks

Quick example::

    import ipyparallel as ipp
    from ipyparallel.offchain import HubConnector

    rc = ipp.Client()
    conn = HubConnector(
        rpc_url="https://rpc.your-chain.example.com",
        hub_address="0xYourHubContractAddress",
        client=rc,
    )
    conn.start()
"""

from .connector import HubConnector
from .fragment_processor import FragmentProcessor
from .message_router import MessageRouter
from .security import HashSuite, Secp256k1Suite

__all__ = [
    "HubConnector",
    "FragmentProcessor",
    "MessageRouter",
    "HashSuite",
    "Secp256k1Suite",
]
