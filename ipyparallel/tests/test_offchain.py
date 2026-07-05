"""Tests for ipyparallel.offchain modules."""

import pytest

from ipyparallel.offchain import FragmentProcessor, HubConnector, MessageRouter


# ---------------------------------------------------------------------------
# HubConnector
# ---------------------------------------------------------------------------


class TestHubConnector:
    def test_init_explicit_args(self):
        conn = HubConnector(
            rpc_url="http://localhost:8545",
            hub_address="0x0000000000000000000000000000000000000001",
        )
        assert conn.rpc_url == "http://localhost:8545"
        assert conn.hub_address == "0x0000000000000000000000000000000000000001"
        assert conn.poll_interval == 2.0

    def test_missing_required_args_raises(self, monkeypatch):
        monkeypatch.delenv("MCF_RPC_URL", raising=False)
        monkeypatch.delenv("MCF_HUB_ADDRESS", raising=False)
        with pytest.raises(RuntimeError, match="MCF_RPC_URL"):
            HubConnector()

    def test_env_var_fallback(self, monkeypatch):
        monkeypatch.setenv("MCF_RPC_URL", "http://env-rpc:8545")
        monkeypatch.setenv("MCF_HUB_ADDRESS", "0xABCD")
        conn = HubConnector()
        assert conn.rpc_url == "http://env-rpc:8545"
        assert conn.hub_address == "0xABCD"

    def test_on_fragment_event_registers_handler(self):
        conn = HubConnector(
            rpc_url="http://localhost:8545",
            hub_address="0x1",
        )
        handler = lambda e: None  # noqa: E731
        conn.on_fragment_event(handler)
        assert handler in conn._fragment_handlers

    def test_on_message_event_registers_handler(self):
        conn = HubConnector(
            rpc_url="http://localhost:8545",
            hub_address="0x1",
        )
        handler = lambda e: None  # noqa: E731
        conn.on_message_event(handler)
        assert handler in conn._message_handlers

    def test_dispatch_calls_handlers(self):
        conn = HubConnector(rpc_url="http://localhost:8545", hub_address="0x1")
        received = []
        conn.on_fragment_event(received.append)
        event = {"event": "FragmentSubmitted", "id": "f1"}
        conn._dispatch(event, conn._fragment_handlers)
        assert received == [event]

    def test_stop_sets_running_false(self):
        conn = HubConnector(rpc_url="http://localhost:8545", hub_address="0x1")
        conn._running = True
        conn.stop()
        assert not conn._running


# ---------------------------------------------------------------------------
# FragmentProcessor
# ---------------------------------------------------------------------------


class TestFragmentProcessor:
    def test_process_single_part(self):
        fp = FragmentProcessor()
        status = fp.process({"id": "f1", "data": b"hello", "index": 0, "total": 1})
        assert status["complete"] is True
        assert status["received"] == 1

    def test_process_multiple_parts(self):
        fp = FragmentProcessor()
        fp.process({"id": "f2", "data": b"AAA", "index": 0, "total": 2})
        status = fp.process({"id": "f2", "data": b"BBB", "index": 1, "total": 2})
        assert status["complete"] is True

    def test_assemble_single_part(self):
        fp = FragmentProcessor()
        fp.process({"id": "f3", "data": b"hello world", "index": 0, "total": 1})
        result = fp.assemble("f3")
        assert result == b"hello world"

    def test_assemble_multiple_parts_ordered(self):
        fp = FragmentProcessor()
        fp.process({"id": "f4", "data": b"world", "index": 1, "total": 2})
        fp.process({"id": "f4", "data": b"hello ", "index": 0, "total": 2})
        result = fp.assemble("f4")
        assert result == b"hello world"

    def test_assemble_unknown_id_raises(self):
        fp = FragmentProcessor()
        with pytest.raises(KeyError):
            fp.assemble("nonexistent")

    def test_assemble_timeout(self):
        fp = FragmentProcessor(timeout=0.1)
        fp.process({"id": "f5", "data": b"only-one", "index": 0, "total": 2})
        with pytest.raises(TimeoutError):
            fp.assemble("f5")

    def test_disassemble_and_reassemble(self):
        fp = FragmentProcessor()
        data = b"x" * 100
        parts = fp.disassemble(data, "f6", part_size=30)
        assert len(parts) == 4  # ceil(100/30) = 4
        for part in parts:
            fp.process(part)
        result = fp.assemble("f6")
        assert result == data

    def test_coerce_bytes_from_hex(self):
        result = FragmentProcessor._coerce_bytes("0xdeadbeef")
        assert result == bytes.fromhex("deadbeef")

    def test_coerce_bytes_invalid_type(self):
        with pytest.raises(TypeError):
            FragmentProcessor._coerce_bytes(12345)

    def test_duplicate_parts_ignored(self):
        fp = FragmentProcessor()
        fp.process({"id": "f7", "data": b"A", "index": 0, "total": 2})
        fp.process({"id": "f7", "data": b"A", "index": 0, "total": 2})  # duplicate
        fp.process({"id": "f7", "data": b"B", "index": 1, "total": 2})
        result = fp.assemble("f7")
        assert result == b"AB"


# ---------------------------------------------------------------------------
# MessageRouter
# ---------------------------------------------------------------------------


class TestMessageRouter:
    _chains = {"chain-a": "http://rpc-a:8545", "chain-b": "http://rpc-b:8545"}

    def test_init_requires_chains(self):
        with pytest.raises(ValueError):
            MessageRouter(chains={})

    def test_route_known_dest(self):
        router = MessageRouter(chains=self._chains)
        result = router.route(
            {"message_id": "m1", "dest_chain": "chain-b", "payload": b"data"}
        )
        assert result["status"] == "forwarded"

    def test_route_unknown_dest_drops(self):
        router = MessageRouter(chains=self._chains)
        result = router.route(
            {"message_id": "m2", "dest_chain": "unknown-chain", "payload": b"data"}
        )
        assert result["status"] == "dropped"

    def test_route_missing_dest_drops(self):
        router = MessageRouter(chains=self._chains)
        result = router.route({"message_id": "m3", "payload": b"data"})
        assert result["status"] == "dropped"

    def test_add_chain(self):
        router = MessageRouter(chains=self._chains)
        router.add_chain("chain-c", "http://rpc-c:8545")
        assert "chain-c" in router.chains

    def test_middleware_applied(self):
        router = MessageRouter(chains=self._chains)
        touched = []

        def mw(msg):
            touched.append(msg["message_id"])
            return msg

        router.add_middleware(mw)
        router.route({"message_id": "m4", "dest_chain": "chain-a", "payload": b""})
        assert "m4" in touched

    def test_middleware_returning_none_drops_message(self):
        router = MessageRouter(chains=self._chains)
        router.add_middleware(lambda msg: None)
        result = router.route({"message_id": "m5", "dest_chain": "chain-a", "payload": b""})
        assert result["status"] == "dropped"

    def test_on_result_handler_called(self):
        router = MessageRouter(chains=self._chains)
        results = []
        router.on_result(results.append)
        router.route({"message_id": "m6", "dest_chain": "chain-b", "payload": b""})
        assert len(results) == 1
        assert results[0]["status"] == "forwarded"
