import contextlib
import io
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest.mock import patch

from group_vault.client import CoordinatorClient, CoordinatorError
from group_vault.daemon import run_daemon
from group_vault.mock_coordinator import MockHandler
from group_vault.types import parse_pending


class TestPolling(unittest.TestCase):
    server: ThreadingHTTPServer
    thread: threading.Thread
    url: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), MockHandler)
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def test_http_round_trip_and_filter(self) -> None:
        client = CoordinatorClient(self.url)
        requests = client.pending_requests("1")
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0].message, b"Week 3 mock request")
        self.assertEqual(client.pending_requests("outsider"), [])

    def test_http_error(self) -> None:
        with self.assertRaisesRegex(CoordinatorError, "HTTP 404"):
            CoordinatorClient(self.url + "/unknown").pending_requests("1")

    def test_invalid_payloads(self) -> None:
        with self.assertRaises(ValueError):
            parse_pending({"api_version": "demo-v1", "requests": [{}]})
        with self.assertRaises(ValueError):
            parse_pending({"api_version": "unknown", "requests": []})

    def test_once(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(run_daemon(self.url, "1", once=True), 0)
        self.assertIn("demo-request-001", output.getvalue())
        self.assertNotIn("Week 3 mock request", output.getvalue())

    def test_retry_then_deduplicate_and_stop(self) -> None:
        requests = CoordinatorClient(self.url).pending_requests("1")
        output = io.StringIO()
        with (
            patch(
                "group_vault.daemon.CoordinatorClient.pending_requests",
                side_effect=[CoordinatorError("offline"), requests, requests],
            ) as poll,
            patch("group_vault.daemon.time.sleep", side_effect=[None, None, KeyboardInterrupt]),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(run_daemon(self.url, "1"), 0)
        self.assertEqual(poll.call_count, 3)
        self.assertEqual(output.getvalue().count("[request]"), 1)
        self.assertIn("[connected]", output.getvalue())
        self.assertIn("[stopped]", output.getvalue())

    def test_once_failure_exit_code(self) -> None:
        with (
            patch(
                "group_vault.daemon.CoordinatorClient.pending_requests",
                side_effect=CoordinatorError("offline"),
            ),
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(run_daemon(self.url, "1", once=True), 1)


if __name__ == "__main__":
    unittest.main()
