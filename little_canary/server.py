"""
little_canary.server — Persistent HTTP server for Little Canary

Keeps the SecurityPipeline warm in memory for low-latency prompt injection
detection. Typical latency ~75ms vs 300-1200ms for cold-start per-call mode.

Endpoints:
    GET  /health  — Pipeline health check (canary availability, mode)
    POST /check   — Analyze text for prompt injection
                    Body: {"text": "..."}
                    Response: SecurityAdvisory dict + {safe, skipped} fields

Usage:
    from little_canary.server import run_server
    run_server(port=18421, mode="advisory", canary_model="qwen2.5:1.5b")
"""

import json
import logging
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional

from .pipeline import SecurityPipeline

logger = logging.getLogger("little_canary.server")

# Module-level reference so the handler class can access it.
_pipeline: Optional[SecurityPipeline] = None


class _CanaryHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the canary detection server."""

    def log_message(self, fmt, *args):
        # Suppress default stderr logging; we use the stdlib logger instead.
        pass

    # -- GET /health --------------------------------------------------------

    def do_GET(self):
        if self.path == "/health":
            health = _pipeline.health_check() if _pipeline else {"error": "not initialized"}
            self._json_response(200, health)
        else:
            self.send_response(404)
            self.end_headers()

    # -- POST /check --------------------------------------------------------

    def do_POST(self):
        if self.path != "/check":
            self.send_response(404)
            self.end_headers()
            return

        try:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length))
            text = body.get("text", "")

            if not text or len(text) < 6:
                self._json_response(200, {"safe": True, "skipped": True})
                return

            verdict = _pipeline.check(text[:4000])
            self._json_response(200, verdict.to_dict())

        except Exception as exc:
            logger.error("Check error: %s", exc)
            self._json_response(500, {"error": str(exc)})

    # -- helpers ------------------------------------------------------------

    def _json_response(self, code: int, payload: dict):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode())


def create_server(
    port: int = 18421,
    mode: str = "advisory",
    canary_model: str = "qwen2.5:1.5b",
) -> HTTPServer:
    """Create and return an HTTPServer (without starting it).

    Useful for tests that need to control the server lifecycle.
    """
    global _pipeline

    _pipeline = SecurityPipeline(
        canary_model=canary_model,
        mode=mode,
    )
    return HTTPServer(("127.0.0.1", port), _CanaryHandler)


def run_server(
    port: int = 18421,
    mode: str = "advisory",
    canary_model: str = "qwen2.5:1.5b",
) -> None:
    """Start the Little Canary HTTP detection server (blocking).

    Parameters
    ----------
    port : int
        TCP port to bind on localhost (default 18421).
    mode : str
        Pipeline mode — ``block``, ``advisory``, or ``full``.
    canary_model : str
        Ollama model tag for the sacrificial canary probe.
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    server = create_server(port=port, mode=mode, canary_model=canary_model)

    health = _pipeline.health_check()
    logger.info("🐤 Little Canary server starting...")
    logger.info("   Mode: %s", mode)
    logger.info("   Model: %s", canary_model)
    logger.info("   Available: %s", health.get("canary_available", "unknown"))
    logger.info("   Port: %s", port)
    logger.info("🐤 Canary server ready on http://127.0.0.1:%d", port)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("🐤 Shutting down...")
        server.shutdown()
