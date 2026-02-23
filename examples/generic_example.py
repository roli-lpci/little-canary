"""
generic_example.py — Little Canary integration for any LLM application

Three lines to add security scanning to any LLM app.

Requirements:
  - pip install requests
  - Ollama running: ollama serve
  - A small model pulled: ollama pull qwen2.5:1.5b
"""

from little_canary import SecurityPipeline

# ── Setup (once) ──
pipeline = SecurityPipeline(
    canary_model="qwen2.5:1.5b",   # any small Ollama model
    mode="full",                     # block obvious, flag ambiguous
    # mode="block",                  # hard block everything detected
    # mode="advisory",               # never block, always flag
)

# ── Check input (every request) ──
user_input = "Hello, can you help me with my project?"
verdict = pipeline.check(user_input)

if not verdict.safe:
    print(f"Blocked: {verdict.summary}")
else:
    # Optional: check for advisory flags
    if verdict.advisory and verdict.advisory.flagged:
        # Prepend advisory to your system prompt
        advisory_prefix = verdict.advisory.to_system_prefix()
        print(f"Flagged (severity: {verdict.advisory.severity})")
        print(f"Advisory: {advisory_prefix}")
        # system_prompt = advisory_prefix + "\n\n" + your_system_prompt
    else:
        print("Clean — process normally")
        # system_prompt = your_system_prompt

    # Send to your production LLM
    # response = your_llm(system_prompt, user_input)


# ── Health check ──
print("\nPipeline health:", pipeline.health_check())
