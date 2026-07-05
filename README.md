# MultiChainFragmentshub — Off-Chain Parallel Compute Layer

> **Navigation guide** — everything you need to understand, run, and extend this repository as the off-chain module powering the [MultiChainFragmentshub](https://github.com/bnwwzf8sbh-cell/MultiChainFragmentshub-) project.

---

## Table of Contents

1. [What This Repository Is](#what-this-repository-is)
2. [Architecture Overview](#architecture-overview)
3. [Directory Map](#directory-map)
4. [Off-Chain Module (`ipyparallel/offchain/`)](#off-chain-module)
5. [Quick-Start](#quick-start)
6. [Connecting to MultiChainFragmentshub](#connecting-to-multichainfragmentshub)
7. [Running the Cluster](#running-the-cluster)
8. [Configuration Reference](#configuration-reference)
9. [Development Workflow](#development-workflow)
10. [Testing](#testing)
11. [Contributing](#contributing)

---

## What This Repository Is

This repository is the **off-chain parallel compute layer** for the MultiChainFragmentshub project. It provides:

| Component | Role |
|-----------|------|
| **Cluster orchestrator** | Spins up distributed worker engines that execute off-chain logic |
| **Off-chain connector** | Translates on-chain events into parallelisable off-chain tasks and routes results back |
| **Fragment processor** | Assembles/disassembles cross-chain data fragments for off-chain processing |
| **Message router** | Routes cross-chain messages between chains and off-chain workers |
| **Serialization layer** | Encodes/decodes data safely between the on-chain ABI and Python objects |

The underlying engine is `ipyparallel` (IPython Parallel) — a battle-tested framework for controlling clusters of Python processes over ZeroMQ, built on the Jupyter protocol.

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                    MultiChainFragmentshub (on-chain)             │
│         Chain A ──────────── Hub Contract ──────────── Chain B   │
└──────────────────────────┬───────────────────────────────────────┘
                           │  events / RPC calls
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│               Off-Chain Layer  (this repository)                 │
│                                                                   │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │  ipyparallel/offchain/                                       │ │
│  │   ├── connector.py       ← hub event listener & result sink  │ │
│  │   ├── fragment_processor.py  ← fragment assembly logic       │ │
│  │   └── message_router.py  ← cross-chain message dispatch      │ │
│  └──────────────────────────────┬──────────────────────────────┘ │
│                                  │ tasks                          │
│  ┌───────────────────────────────▼──────────────────────────────┐ │
│  │  ipyparallel cluster                                          │ │
│  │   ipcontroller  ◄──── ipengine × N  (parallel workers)       │ │
│  └──────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

---

## Directory Map

```
MultiChainFragmentshub-/
├── ipyparallel/               # Core parallel-compute library
│   ├── offchain/              # ★ MultiChainFragmentshub integration
│   │   ├── __init__.py
│   │   ├── connector.py       # HubConnector — listens to on-chain events
│   │   ├── fragment_processor.py  # FragmentProcessor — assembles fragments
│   │   └── message_router.py  # MessageRouter — routes cross-chain messages
│   ├── cluster/               # Cluster lifecycle (start / stop / list)
│   ├── client/                # Python client API (Client, View, AsyncResult)
│   ├── controller/            # Hub & scheduler processes
│   ├── engine/                # Worker engine processes
│   ├── serialize/             # Safe serialization (canning, code utils)
│   └── apps/                  # CLI entry points (ipcluster, ipcontroller, ipengine)
├── docs/                      # Sphinx documentation source
├── examples/                  # Jupyter notebook examples
├── ci/                        # CI/CD configuration
├── pyproject.toml             # Project metadata and tool config
└── README.md                  # ← you are here
```

---

## Off-Chain Module

Located at `ipyparallel/offchain/`, this is the primary integration surface between MultiChainFragmentshub and the parallel compute layer.

### `connector.py` — `HubConnector`

Connects to an on-chain MultiChainFragmentshub hub contract, listens for fragment and message events, and dispatches work to the ipyparallel cluster.

```python
from ipyparallel.offchain import HubConnector

conn = HubConnector(
    rpc_url="https://rpc.chain-a.example.com",
    hub_address="0xYourHubContractAddress",
    cluster_profile="default",
)
conn.start()          # blocking; use conn.start_async() in async contexts
```

Key methods:

| Method | Description |
|--------|-------------|
| `start()` | Start the event-polling loop (blocking) |
| `start_async()` | Start as an async coroutine |
| `stop()` | Gracefully shut down |
| `on_fragment_event(handler)` | Register a callback for fragment events |
| `on_message_event(handler)` | Register a callback for message events |

### `fragment_processor.py` — `FragmentProcessor`

Handles assembly and disassembly of cross-chain data fragments.

```python
from ipyparallel.offchain import FragmentProcessor

fp = FragmentProcessor(client=rc)          # rc = ipyparallel Client
result = fp.process(fragment_payload)
assembled = fp.assemble(fragment_id)
```

### `message_router.py` — `MessageRouter`

Routes cross-chain messages between source and destination chains via the off-chain cluster.

```python
from ipyparallel.offchain import MessageRouter

router = MessageRouter(
    chains={"chain-a": "https://rpc.chain-a.example.com",
            "chain-b": "https://rpc.chain-b.example.com"},
    client=rc,
)
router.route(message)
```

---

## Quick-Start

### 1. Install

```bash
pip install -e ".[offchain]"
```

### 2. Start a local cluster

```bash
ipcluster start --n=4
```

### 3. Connect the off-chain layer

```python
import ipyparallel as ipp
from ipyparallel.offchain import HubConnector

# Connect to the running cluster
rc = ipp.Client()

# Connect to MultiChainFragmentshub
conn = HubConnector(
    rpc_url="https://rpc.your-chain.example.com",
    hub_address="0xYourHubContractAddress",
    client=rc,
)
conn.start()
```

---

## Connecting to MultiChainFragmentshub

The off-chain layer integrates with MultiChainFragmentshub through the `HubConnector`. It expects:

1. **An EVM-compatible RPC endpoint** for each chain you want to monitor.
2. **The hub contract address** deployed by the MultiChainFragmentshub project.
3. **A running ipyparallel cluster** (see [Running the Cluster](#running-the-cluster)).

Configuration can be passed directly to `HubConnector` or via a profile config file at `~/.ipython/profile_<name>/ipython_config.py`.

### Environment variables

| Variable | Description |
|----------|-------------|
| `MCF_RPC_URL` | Default RPC URL for the hub chain |
| `MCF_HUB_ADDRESS` | Hub contract address |
| `MCF_CLUSTER_PROFILE` | ipyparallel profile name (default: `default`) |
| `MCF_POLL_INTERVAL` | Event polling interval in seconds (default: `2`) |

---

## Running the Cluster

### Local (development)

```bash
ipcluster start --n=4
```

### Using the Python API

```python
import ipyparallel as ipp

async with ipp.Cluster(n=4) as rc:
    # rc is a connected Client
    ...
```

### With a profile

```bash
ipcluster start --profile=multichainfragmentshub --n=8
```

Profiles live at `~/.ipython/profile_<name>/`.

---

## Configuration Reference

`ipyparallel` uses [traitlets](https://traitlets.readthedocs.io/) for configuration. The most relevant settings for off-chain use:

| Setting | Default | Description |
|---------|---------|-------------|
| `Cluster.n` | `1` | Number of engine workers |
| `Cluster.profile` | `"default"` | Profile name |
| `HubConnector.poll_interval` | `2.0` | Seconds between RPC polls |
| `HubConnector.max_retries` | `5` | Max RPC reconnect retries |
| `FragmentProcessor.timeout` | `30.0` | Assembly timeout in seconds |

---

## Development Workflow

```bash
# Clone and install in editable mode with dev extras
git clone https://github.com/bnwwzf8sbh-cell/MultiChainFragmentshub-
cd MultiChainFragmentshub-
pip install -e ".[test,offchain]"

# Lint
ruff check ipyparallel/
ruff format --check ipyparallel/

# Run tests
pytest ipyparallel/tests/
```

---

## Testing

```bash
pytest ipyparallel/tests/
pytest ipyparallel/tests/test_offchain.py   # off-chain module tests only
```

Tests require a running ipyparallel cluster **or** the `pytest-ipyparallel` fixtures which spin one up automatically.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
Pull requests targeting `main` should:
- Pass `ruff` linting
- Include tests for new off-chain functionality
- Update this README if the architecture changes
