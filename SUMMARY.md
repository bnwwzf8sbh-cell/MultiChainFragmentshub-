# Repository Summary: `MultiChainFragmentshub-`

## Purpose

This repository is the **off-chain parallel compute layer** for the MultiChainFragmentshub project. It is built on top of a fork of **`ipyparallel`** (IPython Parallel) — a framework for controlling clusters of Python worker processes over ZeroMQ using the Jupyter protocol — and extends it to bridge on-chain blockchain events with distributed off-chain computation.

## Architecture

- **On-chain side**: A hub contract connecting multiple chains (Chain A ↔ Hub ↔ Chain B) emits events and RPC calls.
- **Off-chain side (this repo)**: The custom `ipyparallel/offchain/` package listens for those events, converts them into parallelisable tasks, executes them across an `ipyparallel` cluster (`ipcontroller` + N `ipengine` workers), and routes results back on-chain.

## Key Custom Module: `ipyparallel/offchain/`

| File | Role |
|------|------|
| `connector.py` | `HubConnector` — listens for hub contract events, dispatches tasks to the cluster, sinks results back |
| `fragment_processor.py` | `FragmentProcessor` — assembles/disassembles cross-chain data fragments |
| `message_router.py` | `MessageRouter` — dispatches cross-chain messages between networks and workers |
| `security.py` | `HashSuite` (SHA-1/SHA-256/SHA-512) and `Secp256k1Suite` (secp256k1 / Vyper-compatible signing) |

## Rest of the Codebase (standard ipyparallel)

- `ipyparallel/` — cluster orchestration: `apps/`, `client/`, `cluster/`, `controller/`, `engine/`, `serialize/`, plus tests
- `lab/` + `package.json`, `tsconfig.json`, `yarn.lock` — TypeScript/JupyterLab extension frontend
- `docs/` — Sphinx docs (with `examples/` symlinked in)
- `benchmarks/`, `ci/`, `.binder/` — ASV benchmarks, CI configs, Binder setup
- Python packaging via `pyproject.toml` / `hatch_build.py`; linting via ESLint, Prettier, and pre-commit hooks

## In Short

A standard `ipyparallel` distribution augmented with a bespoke `offchain` package (connector, fragment processor, message router, and crypto/security suite) that serves as the parallel off-chain execution engine for a multi-chain hub contract system.
