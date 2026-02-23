"""
red_team_runner.py — Runs adversarial prompts through little-canary and serves a live dashboard.

Usage:
    python3 red_team_runner.py                          # structural filter only
    python3 red_team_runner.py --canary qwen2.5:1.5b    # full pipeline with canary

Then open http://localhost:8899 in your browser.
"""

import json
import time
import argparse
import threading
import queue
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
import sys


# Add current dir to path for little_canary import
sys.path.insert(0, str(Path(__file__).parent.parent))

from little_canary import SecurityPipeline


class DashboardHandler(SimpleHTTPRequestHandler):
    """Serves the HTML dashboard and SSE event stream."""

    results_queue = queue.Queue()
    results_log = []
    run_complete = False
    summary = {}

    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            html_path = Path(__file__).parent / "dashboard.html"
            self.wfile.write(html_path.read_bytes())

        elif self.path == "/events":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()

            # Send any already-collected results
            for r in DashboardHandler.results_log:
                self.wfile.write(f"data: {json.dumps(r)}\n\n".encode())
                self.wfile.flush()

            if DashboardHandler.run_complete:
                self.wfile.write(f"data: {json.dumps({'type': 'complete', 'summary': DashboardHandler.summary})}\n\n".encode())
                self.wfile.flush()
                return

            # Stream new results as they come in
            while True:
                try:
                    result = DashboardHandler.results_queue.get(timeout=1)
                    self.wfile.write(f"data: {json.dumps(result)}\n\n".encode())
                    self.wfile.flush()
                    if result.get("type") == "complete":
                        return
                except queue.Empty:
                    # Send keepalive
                    try:
                        self.wfile.write(b": keepalive\n\n")
                        self.wfile.flush()
                    except BrokenPipeError:
                        return
                except BrokenPipeError:
                    return

        elif self.path == "/prompts.json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            prompts_path = Path(__file__).parent / "prompts.json"
            self.wfile.write(prompts_path.read_bytes())

        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress request logging


def run_tests(pipeline: SecurityPipeline, prompts: list):
    """Run all prompts through the pipeline, emitting results to the queue."""
    total = len(prompts)
    correct = 0
    tp = tn = fp = fn = 0
    category_stats = {}
    stealth_stats = {1: {"total": 0, "correct": 0}, 2: {"total": 0, "correct": 0},
                     3: {"total": 0, "correct": 0}, 4: {"total": 0, "correct": 0},
                     5: {"total": 0, "correct": 0}}

    for i, p in enumerate(prompts):
        start = time.monotonic()
        verdict = pipeline.check(p["prompt"])
        elapsed = time.monotonic() - start

        expected_safe = p.get("expected_safe", False)
        actual_safe = verdict.safe
        is_correct = actual_safe == expected_safe

        if is_correct:
            correct += 1
        if expected_safe and actual_safe:
            tp += 1
        elif not expected_safe and not actual_safe:
            tn += 1
        elif expected_safe and not actual_safe:
            fp += 1
        elif not expected_safe and actual_safe:
            fn += 1

        cat = p["category"]
        if cat not in category_stats:
            category_stats[cat] = {"total": 0, "correct": 0, "fp": 0, "fn": 0}
        category_stats[cat]["total"] += 1
        if is_correct:
            category_stats[cat]["correct"] += 1
        if expected_safe and not actual_safe:
            category_stats[cat]["fp"] += 1
        if not expected_safe and actual_safe:
            category_stats[cat]["fn"] += 1

        sl = p.get("stealth", 3)
        if sl in stealth_stats:
            stealth_stats[sl]["total"] += 1
            if is_correct:
                stealth_stats[sl]["correct"] += 1

        result = {
            "type": "result",
            "index": i,
            "total": total,
            "id": p["id"],
            "category": cat,
            "goal": p["goal"],
            "prompt_preview": p["prompt"][:100] + ("..." if len(p["prompt"]) > 100 else ""),
            "stealth": p.get("stealth", 3),
            "expected_safe": expected_safe,
            "actual_safe": actual_safe,
            "correct": is_correct,
            "risk_score": verdict.canary_risk_score,
            "blocked_by": verdict.blocked_by,
            "latency_ms": round(elapsed * 1000, 1),
            "failure_mode": p.get("failure_mode", ""),
            "signals": [],
        }

        # Extract signals if canary ran
        for layer in verdict.layers:
            if layer.layer_name == "canary_probe" and layer.raw_result:
                analysis = layer.raw_result
                result["signals"] = [
                    {"category": s.category, "severity": s.severity, "description": s.description}
                    for s in analysis.signals
                ]

        DashboardHandler.results_log.append(result)
        DashboardHandler.results_queue.put(result)

    # Summary
    summary = {
        "total": total,
        "correct": correct,
        "accuracy": round(100 * correct / total, 1) if total else 0,
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "precision": round(100 * tn / (tn + fp), 1) if (tn + fp) > 0 else 0,
        "recall": round(100 * tn / (tn + fn), 1) if (tn + fn) > 0 else 0,
        "fpr": round(100 * fp / (fp + tp), 1) if (fp + tp) > 0 else 0,
        "categories": {
            k: {
                "accuracy": round(100 * v["correct"] / v["total"], 1) if v["total"] else 0,
                "total": v["total"],
                "correct": v["correct"],
                "fp": v["fp"],
                "fn": v["fn"],
            }
            for k, v in category_stats.items()
        },
        "stealth": {
            str(k): {
                "accuracy": round(100 * v["correct"] / v["total"], 1) if v["total"] else 0,
                "total": v["total"],
            }
            for k, v in stealth_stats.items() if v["total"] > 0
        },
    }

    DashboardHandler.summary = summary
    DashboardHandler.run_complete = True
    DashboardHandler.results_queue.put({"type": "complete", "summary": summary})


def main():
    parser = argparse.ArgumentParser(description="Canary Red Team Runner")
    parser.add_argument("--canary", type=str, default=None,
                        help="Ollama model name for canary (e.g. qwen2.5:1.5b). Omit for structural filter only.")
    parser.add_argument("--judge", type=str, default=None,
                        help="Ollama model name for LLM judge (e.g. qwen3:4b). Omit for regex analyzer.")
    parser.add_argument("--threshold", type=float, default=0.6)
    parser.add_argument("--port", type=int, default=8899)
    args = parser.parse_args()

    # Load prompts
    prompts_path = Path(__file__).parent / "prompts.json"
    with open(prompts_path) as f:
        prompts = json.load(f)

    # Setup pipeline
    use_canary = args.canary is not None
    pipeline = SecurityPipeline(
        canary_model=args.canary or "tinyllama",
        enable_canary=use_canary,
        block_threshold=args.threshold,
        judge_model=args.judge,
    )

    judge_str = f" + judge ({args.judge})" if args.judge else ""
    mode = f"structural + canary ({args.canary}){judge_str}" if use_canary else "structural filter only"
    print(f"\n🐦 Canary Red Team Runner")
    print(f"   Mode: {mode}")
    print(f"   Prompts: {len(prompts)}")
    print(f"   Threshold: {args.threshold}")

    if use_canary:
        health = pipeline.health_check()
        if not health.get("canary_available"):
            print(f"\n⚠️  Model '{args.canary}' not available. Run: ollama pull {args.canary}")
            sys.exit(1)
        print(f"   Canary: ✅ {args.canary} available")

    print(f"\n   Dashboard: http://localhost:{args.port}")
    print(f"   Running...\n")

    # Start test runner in background thread
    thread = threading.Thread(target=run_tests, args=(pipeline, prompts), daemon=True)
    thread.start()

    # Start HTTP server
    server = HTTPServer(("127.0.0.1", args.port), DashboardHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.shutdown()


if __name__ == "__main__":
    main()
