# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-02-21

Initial open source release.

### Added
- **Structural filter** — regex + decode-then-recheck for base64, hex, ROT13, reverse-encoded payloads
- **Canary probe** — sacrificial LLM behavioral analysis with temperature-0 deterministic output
- **Behavioral analyzer** — dual-strategy detection (reaction patterns + output patterns)
- **LLM judge** (experimental) — optional second model to classify canary output
- **Three deployment modes** — block, advisory, full
- **Advisory system** — security prefix for production LLM system prompts
- **Benchmark suite** — 240-prompt test suite (220 adversarial, 12 categories) + 40 false positive prompts
- **Dashboard** — live browser dashboard for red team testing
- **Full pipeline test** — end-to-end with production LLM compliance measurement
- **Integration examples** — chatbot, email agent, generic
- **OSS documentation** — README, CLAUDE.md, CONTRIBUTING, CODE_OF_CONDUCT, SECURITY, issue templates

### Security
- Tightened `requests` dependency to `>=2.32.2` (CVE-2024-35195)
- Dashboard server binds to localhost only (`127.0.0.1`)
- License changed from MIT to Apache 2.0 (patent grant for AI tooling)

### Benchmarks
- 63.6% effective detection (canary + gemma3:27b production LLM)
- 36.8% standalone block rate
- 0% false positive rate on Hermes chatbot traffic
- 159% improvement over production LLM alone
