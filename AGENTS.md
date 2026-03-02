# AGENTS.md

## Commands

- `pip install -e ".[dev]"` -- Install with dev dependencies
- `pytest` -- Run all 157 tests (no network required)
- `pytest tests/test_pipeline.py -v` -- Run single test module
- `pytest --cov=little_canary --cov-report=term-missing` -- Run with coverage (80% threshold)
- `ruff check little_canary/` -- Lint
- `ruff check little_canary/ --fix` -- Lint with auto-fix
- `mypy little_canary/` -- Type check
- `python -m build` -- Build wheel and sdist

## Testing

- Framework: `pytest` with `pytest-cov`
- Config: `pyproject.toml` under `[tool.pytest.ini_options]`
- Test location: `tests/` directory, one file per source module
- All tests run offline -- no Ollama or network required
- Tests mock HTTP calls via monkeypatching `requests.post`
- Marker `@pytest.mark.slow` for tests needing network mocks
- Coverage floor: 80% (`fail_under = 80` in pyproject.toml)

Run benchmarks (requires Ollama running locally):
```bash
cd benchmarks && python3 run_fp_test.py                                    # false positive test
cd benchmarks && python3 red_team_runner.py --canary qwen2.5:1.5b         # adversarial dashboard
cd benchmarks && python3 full_pipeline_test.py --canary qwen2.5:1.5b      # end-to-end
```

## Project Structure

```
little_canary/               # Installable package
  __init__.py                # Public exports: SecurityPipeline, CanaryProbe, etc.
  structural_filter.py       # Layer 1: regex + decode-then-recheck (base64, hex, ROT13)
  canary.py                  # Layer 2: sacrificial LLM probe via Ollama /api/chat
  analyzer.py                # Behavioral analysis of canary response (regex strategies)
  judge.py                   # Experimental LLM-based judge (replaces analyzer)
  pipeline.py                # Orchestrator: wires layers, mode logic (block/advisory/full)
tests/                       # Unit tests (157 tests, all offline)
examples/                    # Integration examples
benchmarks/                  # TensorTrust red team, false positive tests, dashboard
```

Pipeline flow: `SecurityPipeline.check(input)` -> structural filter (regex, ~1ms) -> canary probe (Ollama, ~250ms) -> behavioral analysis -> verdict.

## Code Style

- Python 3.8+ compatibility required (no walrus `:=`, no `match`, no `X | Y` unions)
- Dataclasses for all structured data (no Pydantic, no TypedDict)
- Type hints on all public method signatures
- `logging.getLogger(__name__)` in every module
- Private methods prefixed with `_`
- Line length: 120 (ruff config)
- Linter: ruff with `E, F, W, I, UP, B, SIM` rules

Good:
```python
@dataclass
class CanaryResult:
    response: str
    latency_ms: float
    model: str
    blocked: bool = False
    reason: str = ""
```

Bad:
```python
# No raw dicts for structured data
result = {"response": resp, "latency": t, "model": m}

# No Python 3.10+ syntax
def check(self, text: str | None = None) -> bool:  # use Optional[str]
```

Detection patterns are tuples of `(regex_pattern, description_string)`:
```python
# Good: add to _build_patterns() in structural_filter.py
raw_patterns = [
    (r"\bignore\s+(all\s+)?(previous|prior|above)\b", "instruction override attempt"),
]
```

## Git Workflow

- Branch from `main`
- Conventional commits: `feat:`, `fix:`, `test:`, `docs:`, `chore:`
- Run `pytest` and `ruff check` before pushing
- Do not modify `benchmarks/prompts.json` or `benchmarks/prompts_fp_realistic.json` without re-running benchmarks

## Boundaries

**Always:**
- Run `pytest` after modifying source files
- Keep `requests` as the only runtime dependency
- Maintain Python 3.8 compatibility
- Use dataclasses for new data structures
- Preserve fail-open behavior (errors return `should_block=False`)

**Ask first:**
- Adding new runtime dependencies
- Changing the Ollama API contract (`/api/chat` format)
- Modifying benchmark prompt datasets
- Changing the mode logic in `pipeline.py`
- Altering the public API surface (`__all__` in `__init__.py`)

**Never:**
- Break Python 3.8 compatibility
- Add blocking behavior to error paths (fail-open is deliberate)
- Include raw user input in `PipelineVerdict.to_dict()` output
- Commit API keys or model credentials
- Delete or skip failing tests without understanding root cause
