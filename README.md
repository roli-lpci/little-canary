# Canary-LLM

**Sacrificial LLM instances as behavioral probes for prompt injection detection**

<!-- Uncomment badges below when published to PyPI / enrolled in OpenSSF -->
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![CI](https://github.com/roli-lpci/little-canary/actions/workflows/ci.yml/badge.svg)](https://github.com/roli-lpci/little-canary/actions)
<!-- [![PyPI](https://img.shields.io/pypi/v/little-canary.svg)](https://pypi.org/project/little-canary/) -->
<!-- [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/roli-lpci/little-canary/badge)](https://scorecard.dev/viewer/?uri=github.com/roli-lpci/little-canary) -->

Canary-LLM is a security layer that uses a small, sacrificial language model to detect prompt injection attacks before they reach your production LLM. Instead of classifying inputs, the canary **gets compromised by them** — and the behavioral residue reveals the attack.

## The Idea

Every existing prompt injection defense treats the LLM as a classifier: "Is this input malicious?" Canary-LLM flips this. It feeds raw user input to a small, sandboxed model and watches what happens. A compromised canary — one that adopts a new persona, leaks its instructions, or agrees to bypass safety — is a strong signal that the input is adversarial.

```
User Input --> Structural Filter (1ms) --> Canary Probe (250ms) --> Your LLM
                   |                            |
              Known patterns              Behavioral analysis
              (regex + encoding)          (did the canary get owned?)
```

## Hardware Requirements

Designed to run on consumer hardware. Tested on a MacBook Air M4 with 16GB RAM.

- **Minimum:** Any machine that can run Ollama with a 1.5B parameter model
- **Recommended:** Apple Silicon Mac or Linux with 8GB+ RAM
- **Canary model:** ~1GB disk, ~1.5GB RAM at inference
- **Latency:** ~250ms per check (canary probe)

## Three Deployment Modes

| Mode | Behavior | Best For |
|------|----------|----------|
| `block` | Hard-blocks detected attacks | Customer chatbots, zero-tolerance systems |
| `advisory` | Never blocks, flags for production LLM | Zero-downtime systems, monitoring |
| `full` | Blocks obvious attacks, flags ambiguous ones | Agents, email processors, hybrid workflows |

## Quick Start

### 1. Install Ollama and pull a canary model

```bash
# macOS / Linux
curl -fsSL https://ollama.com/install.sh | sh
ollama serve &          # start the Ollama server (if not already running)
ollama pull qwen2.5:1.5b
```

### 2. Install Canary-LLM

```bash
pip install .
```

Or from source:

```bash
git clone https://github.com/roli-lpci/little-canary.git
cd little-canary
pip install .
```

### 3. Add three lines to your app

```python
from little_canary import SecurityPipeline

pipeline = SecurityPipeline(canary_model="qwen2.5:1.5b", mode="full")
verdict = pipeline.check(user_input)

if not verdict.safe:
    return "Sorry, I couldn't process that request."

# Prepend advisory to your existing system prompt
system = verdict.advisory.to_system_prefix() + "\n" + your_system_prompt
response = your_llm(system=system, messages=[{"role": "user", "content": user_input}])
```

That's it. Your LLM, your app, your logic. The canary adds a security layer in front.

## How It Works

### Architecture

**Layer 1: Structural Filter** (~1ms)
Regex-based detection of known attack patterns, plus decode-then-recheck for base64, hex, ROT13, and reverse-encoded payloads.

**Layer 2: Canary Probe** (~250ms)
Feeds raw input to a small sacrificial LLM (qwen2.5:1.5b by default). Temperature=0 for deterministic output. The canary's response is analyzed for signs of compromise: persona adoption, instruction compliance, system prompt leakage, refusal collapse.

**Analysis Layer** (pluggable)
- Default: regex-based `BehavioralAnalyzer` — fast, zero dependencies
- Experimental: `LLMJudge` — a second model classifies the canary's output as SAFE/UNSAFE

**Advisory System**
Suspicious inputs that aren't hard-blocked generate a `SecurityAdvisory` prepended to your production LLM's system prompt, warning it about detected signals.

### Why a Sacrificial Model?

Existing tools classify inputs. Canary-LLM observes what attacks *do* to a model and reads the aftermath:

- **Llama Guard** is a safety classifier that evaluates content against safety categories. Canary-LLM detects behavioral compromise, not content safety violations.
- **Prompt Guard** is a fine-tuned classifier trained to detect injection patterns in input text. Canary-LLM uses actual LLM behavioral response rather than input-side classification.
- **NeMo Guardrails** is a dialogue management framework using rules and LLM calls to control flow. Canary-LLM works with any LLM stack, no framework required.

The canary is deliberately small and weak. It gets compromised by attacks that your production LLM might resist. That's the point — a compromised canary is a strong signal.

> [!NOTE]
> **Fail-open design:** If Ollama is unavailable, the pipeline passes all inputs through. Use `pipeline.health_check()` at startup to verify connectivity. This is a deliberate availability-over-security tradeoff documented in the architecture.

## Benchmark Results

Tested against a 240-prompt test suite (220 adversarial + 20 safe inputs) across 12 attack categories:

| Metric | Value |
|--------|-------|
| **Effective detection rate** | **63.6%** (full pipeline with production LLM) |
| **Standalone block rate** | 36.8% (canary alone) |
| **False positive rate** | **0/20** Hermes chatbot, **4/20** Clawdbot email agent* |
| **Improvement over LLM alone** | **+159%** |
| **Latency** | ~250ms (canary probe) |

*Clawdbot false positives occur on emails quoting attack strings in security articles — content that would be quarantine-reviewed in production regardless. See `benchmarks/` for full data.

**Detection by category:**

| Category | Effective Rate | Attacks |
|----------|---------------|---------|
| Role escalation | 90% | 20 |
| Canary mismatch | 80% | 20 |
| Benign wrapper | 70% | 20 |
| Multi-step trap | 70% | 20 |
| Canary divergence | 70% | 20 |
| Classic injection | 65% | 20 |
| Tool trigger | 65% | 20 |
| Context stuffing | 50% | 20 |
| Encoding/obfuscation | 40% | 20 |
| Canary outage | 40% | 20 |

> [!WARNING]
> **Self-generated test suite.** These prompts were created for this project, not drawn from established adversarial benchmarks. Validate against TensorTrust, Garak, or HarmBench before comparing to other tools.

## Integration Examples

### Customer Chatbot (Block Mode)

```python
from little_canary import SecurityPipeline

pipeline = SecurityPipeline(canary_model="qwen2.5:1.5b", mode="block")

def handle_message(user_input):
    verdict = pipeline.check(user_input)
    if not verdict.safe:
        return "I'm sorry, I couldn't process that. Could you rephrase?"
    return call_your_llm(user_input)
```

### Email Agent (Full Mode)

```python
from little_canary import SecurityPipeline

pipeline = SecurityPipeline(canary_model="qwen2.5:1.5b", mode="full")

def process_email(email_body, sender):
    verdict = pipeline.check(email_body)
    if not verdict.safe:
        quarantine(email_body, sender, verdict.summary)
        return
    system = verdict.advisory.to_system_prefix() + "\n" + agent_prompt
    agent.process(system=system, content=email_body)
```

See `examples/` for complete integration code.

## Running the Benchmarks

```bash
# Red team suite (240 prompts, live dashboard)
cd benchmarks
python3 red_team_runner.py --canary qwen2.5:1.5b
# Dashboard at http://localhost:8899

# False positive test (40 realistic prompts)
python3 run_fp_test.py

# Full pipeline test (canary + production LLM)
python3 full_pipeline_test.py --canary qwen2.5:1.5b --production gemma3:27b --attacks-only
```

## Project Structure

```
little-canary/
├── little_canary/                 # Core package (pip install .)
│   ├── __init__.py
│   ├── py.typed                   # PEP 561 type marker
│   ├── structural_filter.py       # Layer 1: regex + encoding detection
│   ├── canary.py                  # Layer 2: sacrificial LLM probe
│   ├── analyzer.py                # Behavioral analysis (regex-based)
│   ├── judge.py                   # LLM judge (experimental, replaces regex)
│   └── pipeline.py                # Orchestration + three deployment modes
├── tests/                         # Unit tests (pytest, 157 tests, 98%+ coverage)
│   ├── conftest.py                # Shared fixtures
│   ├── test_structural_filter.py
│   ├── test_analyzer.py
│   ├── test_canary.py
│   ├── test_judge.py
│   └── test_pipeline.py
├── examples/                      # Integration examples
│   ├── generic_example.py
│   ├── hermes_example.py          # Customer chatbot
│   └── clawdbot_example.py        # Email agent with quarantine
├── benchmarks/                    # Test suites and dashboard
│   ├── prompts.json               # 240 test prompts (12 categories)
│   ├── prompts_fp_realistic.json  # 40 realistic false positive prompts
│   ├── red_team_runner.py         # Browser dashboard for red teaming
│   ├── run_fp_test.py             # Terminal FP test
│   ├── full_pipeline_test.py      # End-to-end with production LLM
│   └── dashboard.html
├── .github/
│   ├── workflows/ci.yml           # CI: pytest + ruff + coverage (Python 3.8-3.12)
│   ├── dependabot.yml             # Automated dependency updates
│   ├── ISSUE_TEMPLATE/
│   └── PULL_REQUEST_TEMPLATE.md
├── README.md
├── CLAUDE.md                      # Agent-optimized documentation
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── SECURITY.md
├── CHANGELOG.md
├── LICENSE                        # Apache 2.0
├── pyproject.toml
└── requirements.txt
```

## Troubleshooting

**"Cannot connect to Ollama"**
- Ensure Ollama is running: `ollama serve` (or check with `pgrep ollama`)
- Verify the URL matches your setup: default is `http://localhost:11434`
- Test connectivity: `curl http://localhost:11434/api/tags`

**"Model not found"**
- Pull the model first: `ollama pull qwen2.5:1.5b`
- List available models: `ollama list`
- The model name must match exactly (e.g., `qwen2.5:1.5b`, not `qwen2.5`)

**Pipeline passes everything through (fail-open behavior)**
- This is by design. If Ollama is unavailable, all inputs pass through unscreened.
- Use `pipeline.health_check()` at startup to verify the canary model is reachable.
- Monitor the `canary_available` field in health check output.

**High false positive rate**
- Use `mode="full"` instead of `mode="block"` to flag ambiguous inputs as advisories rather than hard-blocking.
- The advisory system prepends security context to your production LLM instead of blocking.
- Check `benchmarks/run_fp_test.py` against your traffic patterns.

**Slow response times**
- Canary probe latency depends on the model size and hardware. The default qwen2.5:1.5b targets ~250ms.
- Set a lower `canary_timeout` to fail fast: `SecurityPipeline(canary_timeout=5.0)`
- Use `enable_structural_filter=True, enable_canary=False` for structural-only mode (~1ms, no LLM required).

## Limitations

- **Self-generated test suite.** The 240 prompts were generated for this project. Results should be validated against standard benchmarks.
- **Single canary model tested.** Benchmarked with qwen2.5:1.5b. Other models may perform differently.
- **Regex-based behavioral analysis.** The default analyzer uses regex patterns. The experimental `LLMJudge` is included for higher accuracy.
- **No production deployment data.** All results are from controlled testing.
- **Ollama-only.** Currently requires Ollama for local inference. No abstraction layer for other backends yet.

## Roadmap

- [ ] Benchmark against TensorTrust, Garak, and HarmBench attack suites
- [ ] LLM judge to replace regex analyzer (higher accuracy)
- [ ] Backend abstraction layer (vLLM, llama.cpp, OpenAI-compatible APIs)
- [ ] Fine-tuned canary model (increased susceptibility = stronger signal)
- [ ] Multi-canary ensemble for higher detection rates
- [ ] Agent integration SDK (MCP, LangChain, CrewAI)

## LPCI Framework

Canary-LLM is part of the **Layered Proactive Contextual Integrity (LPCI)** framework — a broader approach to AI agent security that treats integrity as a layered, contextual property rather than a binary state. The canary architecture implements the "proactive probe" layer of LPCI: instead of waiting for attacks to succeed, it proactively tests inputs against a sacrificial model to detect adversarial intent before it reaches production systems.

## Citation

```bibtex
@software{little_canary,
  author = {Bosch, Rolando},
  title = {Canary-LLM: Sacrificial LLM Instances as Behavioral Probes for Prompt Injection Detection},
  year = {2026},
  url = {https://github.com/roli-lpci/little-canary}
}
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and contribution guidelines.

## Author

**Rolando Bosch** — [LPCI Innovations](https://lpci.io) / Hermes Autonomous Lab

## License

Apache 2.0 — see [LICENSE](LICENSE) for details.
