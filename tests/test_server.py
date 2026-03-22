"""Tests for the Little Canary HTTP server."""

import json
import threading
from http.client import HTTPConnection
from unittest.mock import MagicMock

import pytest


@pytest.fixture()
def canary_server():
    """Spin up the canary HTTP server on a random port with a mocked pipeline."""
    from http.server import HTTPServer

    import little_canary.server as server_mod
    from little_canary.server import _CanaryHandler

    # Create a lightweight mock pipeline so we don't need Ollama running.
    mock_pipeline = MagicMock()
    mock_pipeline.health_check.return_value = {
        "canary_available": True,
        "mode": "advisory",
    }

    # Mock verdict object returned by pipeline.check()
    mock_verdict = MagicMock()
    mock_verdict.to_dict.return_value = {
        "safe": True,
        "blocked": False,
        "reasons": [],
    }
    mock_pipeline.check.return_value = mock_verdict

    # Inject mock pipeline
    original_pipeline = server_mod._pipeline
    server_mod._pipeline = mock_pipeline

    # Bind to port 0 → OS picks a free port
    httpd = HTTPServer(("127.0.0.1", 0), _CanaryHandler)
    port = httpd.server_address[1]

    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()

    yield port, mock_pipeline

    httpd.shutdown()
    server_mod._pipeline = original_pipeline


class TestHealthEndpoint:
    def test_health_returns_200(self, canary_server):
        port, _ = canary_server
        conn = HTTPConnection("127.0.0.1", port)
        conn.request("GET", "/health")
        resp = conn.getresponse()

        assert resp.status == 200
        body = json.loads(resp.read())
        assert body["canary_available"] is True
        assert body["mode"] == "advisory"

    def test_unknown_path_returns_404(self, canary_server):
        port, _ = canary_server
        conn = HTTPConnection("127.0.0.1", port)
        conn.request("GET", "/nonexistent")
        resp = conn.getresponse()

        assert resp.status == 404


class TestCheckEndpoint:
    def test_check_benign_text(self, canary_server):
        port, mock_pipeline = canary_server
        conn = HTTPConnection("127.0.0.1", port)
        payload = json.dumps({"text": "What is the weather today?"})
        conn.request("POST", "/check", body=payload, headers={"Content-Type": "application/json"})
        resp = conn.getresponse()

        assert resp.status == 200
        body = json.loads(resp.read())
        assert body["safe"] is True
        mock_pipeline.check.assert_called_once_with("What is the weather today?")

    def test_check_short_text_skipped(self, canary_server):
        port, mock_pipeline = canary_server
        conn = HTTPConnection("127.0.0.1", port)
        payload = json.dumps({"text": "hi"})
        conn.request("POST", "/check", body=payload, headers={"Content-Type": "application/json"})
        resp = conn.getresponse()

        assert resp.status == 200
        body = json.loads(resp.read())
        assert body["safe"] is True
        assert body["skipped"] is True
        mock_pipeline.check.assert_not_called()

    def test_check_empty_text_skipped(self, canary_server):
        port, _ = canary_server
        conn = HTTPConnection("127.0.0.1", port)
        payload = json.dumps({"text": ""})
        conn.request("POST", "/check", body=payload, headers={"Content-Type": "application/json"})
        resp = conn.getresponse()

        assert resp.status == 200
        body = json.loads(resp.read())
        assert body["safe"] is True
        assert body["skipped"] is True

    def test_check_wrong_path_returns_404(self, canary_server):
        port, _ = canary_server
        conn = HTTPConnection("127.0.0.1", port)
        payload = json.dumps({"text": "test"})
        conn.request("POST", "/wrong", body=payload, headers={"Content-Type": "application/json"})
        resp = conn.getresponse()

        assert resp.status == 404

    def test_check_truncates_long_text(self, canary_server):
        port, mock_pipeline = canary_server
        conn = HTTPConnection("127.0.0.1", port)
        long_text = "A" * 5000
        payload = json.dumps({"text": long_text})
        conn.request("POST", "/check", body=payload, headers={"Content-Type": "application/json"})
        resp = conn.getresponse()

        assert resp.status == 200
        # Verify the text was truncated to 4000 chars
        call_args = mock_pipeline.check.call_args[0][0]
        assert len(call_args) == 4000

    def test_check_error_returns_500(self, canary_server):
        port, mock_pipeline = canary_server
        mock_pipeline.check.side_effect = RuntimeError("canary exploded")

        conn = HTTPConnection("127.0.0.1", port)
        payload = json.dumps({"text": "trigger an error here"})
        conn.request("POST", "/check", body=payload, headers={"Content-Type": "application/json"})
        resp = conn.getresponse()

        assert resp.status == 500
        body = json.loads(resp.read())
        assert "canary exploded" in body["error"]
