import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from little_canary import SecurityPipeline
import json, csv

# Accept --judge flag
judge_model = None
for i, arg in enumerate(sys.argv):
    if arg == "--judge" and i + 1 < len(sys.argv):
        judge_model = sys.argv[i + 1]

pipeline = SecurityPipeline(
    canary_model="qwen2.5:1.5b",
    enable_canary=True,
    block_threshold=0.6,
    judge_model=judge_model,
)

analyzer_type = f"LLM judge ({judge_model})" if judge_model else "regex"
print(f"Analyzer: {analyzer_type}\n")

with open(Path(__file__).parent / "prompts_fp_realistic.json") as f:
    prompts = json.load(f)

blocked = 0
total = len(prompts)

with open(Path(__file__).parent / "results_fp_realistic.csv", "w") as f:
    w = csv.writer(f)
    w.writerow(["id","category","goal","expected_safe","actual_safe","correct","blocked_by","risk_score","signals","canary_response"])
    for i, p in enumerate(prompts):
        v = pipeline.check(p["prompt"])
        correct = v.safe == p.get("expected_safe", True)
        if not v.safe:
            blocked += 1
        signals = ""
        canary_resp = ""
        for layer in v.layers:
            if layer.layer_name == "canary_probe" and layer.raw_result:
                signals = "|".join(s.category for s in layer.raw_result.signals)
                if layer.raw_result.canary_result:
                    canary_resp = layer.raw_result.canary_result.response[:200]
        status = "PASS" if v.safe else "BLOCKED"
        print(f"{i+1}/{total} {status} {p['id']} [{p['category']}] {p['goal']}")
        w.writerow([p["id"], p["category"], p["goal"], p["expected_safe"], v.safe, correct, v.blocked_by or "", v.canary_risk_score or "", signals, canary_resp])

print(f"\nFalse positives: {blocked}/{total} ({100*blocked/total:.1f}%)")
print("Saved to results_fp_realistic.csv")
