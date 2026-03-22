# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-03-22

### Added
- **`little-canary serve` CLI command** — persistent HTTP server mode for low-latency detection (~75ms vs 300-1200ms cold-start). Keeps the `SecurityPipeline` warm in memory.
- **REST API endpoints** — `POST /check` (analyze text) and `GET /health` (pipeline status).
- **`little_canary.server` module** — `run_server()` and `create_server()` functions for programmatic use and embedding.
- **`little_canary.cli` module** — CLI dispatcher with `serve` subcommand (extensible for future commands).
- **Console script entry point** — `pip install little-canary` now provides the `little-canary` command.

### Changed
- Bumped version to 0.3.0.

## [0.2.3] - 2026-03-08

### Added
- `AuditLogger` — JSONL audit logging for every pipeline check. Writes `canary-audit.jsonl` (all checks) and `canary-alerts.jsonl` (blocked/flagged only). Input is stored as SHA-256 hash only, never raw text.
- `CanaryGuard` — trust-aware wrapper around `SecurityPipeline`. Three trust tiers: TRUSTED (owner, advisory-only, never blocked), KNOWN (flagged, not passed), UNKNOWN (blocked). Override mechanism with rate limiting (5/hr).
- Callback hooks on `SecurityPipeline`: `on_block`, `on_flag`, `on_pass` — exception-safe, never crash the pipeline.
- `audit_log_dir` parameter on `SecurityPipeline` for automatic per-check logging.

## [0.2.2] - 2026-03-02

### Changed
- Updated project URLs for PyPI backlinks

## [0.2.1] - 2026-03-02

### Fixed
- Standardized package metadata (author: Hermes Labs, email: lpcisystems@gmail.com)
- Added PyPI version badge to README
- Removed internal product branding from examples and benchmarks
- Updated benchmark results in README (TensorTrust 99.0%)

## [0.2.0] - 2026-02-25

### Added
- **TensorTrust benchmark** — 99.0% detection rate on 400 real-world prompt injection attacks (Claude Opus as production LLM)
- **Multi-model benchmark support** — tested canary pipeline across multiple models; 94.8% detection with 3B local model
- **Multi-model comparison view** on [littlecanary.ai](https://littlecanary.ai) website
- **PyPI publishing** — `pip install little-canary` now available

## [0.1.0] - 2026-02-21

Initial open source release.

### Added
- **Structural filter** — regex + decode-then-recheck for base64, hex, ROT13, reverse-encoded payloads
- **Canary probe** — sacrificial LLM behavioral analysis with temperature-0 deterministic output
- **Behavioral analyzer** — dual-strategy detection (reaction patterns + output patterns)
- **LLM judge** (experimental) — optional second model to classify canary output
- **Three deployment modes** — block, advisory, full
- **Advisory system** — security prefix for production LLM system prompts
- **Benchmark suite** — 180-prompt test suite (160 adversarial, 9 categories) + 40 false positive prompts
- **Dashboard** — live browser dashboard for red team testing
- **Full pipeline test** — end-to-end with production LLM compliance measurement
- **Integration examples** — chatbot, email agent, generic
- **OSS documentation** — README, CLAUDE.md, CONTRIBUTING, CODE_OF_CONDUCT, SECURITY, issue templates

### Security
- Tightened `requests` dependency to `>=2.32.2` (CVE-2024-35195)
- Dashboard server binds to localhost only (`127.0.0.1`)
- Licensed under Apache 2.0 (patent grant for AI tooling)

### Benchmarks
- 98% effective detection (full pipeline: canary + production LLM)
- 37% standalone block rate (canary + structural filter alone)
- 0% false positive rate on realistic chatbot traffic (0/40)
- ~250ms latency per check
