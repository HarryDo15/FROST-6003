import contextlib
import io
import unittest
from unittest.mock import patch

from group_vault.daemon import LocalRequest, authorize, run_daemon
from group_vault.prompt import timed_approval
from group_vault.types import SignatureRequest
from group_vault.vault_cli import _build_parser, main


def request(identifier: str = "demo-1") -> SignatureRequest:
    return SignatureRequest(identifier, "demo-vault", ("1",), b"demo")


class TestDeadlineInput(unittest.TestCase):
    def test_default_rejection_and_yes(self) -> None:
        for answer, expected in (("", "rejected"), ("n", "rejected"), ("y", "approved")):
            with (
                self.subTest(answer=answer),
                patch("group_vault.prompt.os.name", "posix"),
                patch("group_vault.prompt.sys.stdin.isatty", return_value=True),
                patch("group_vault.prompt._posix_line", return_value=answer),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(timed_approval(300, clock=lambda: 0), expected)

    def test_timeout_or_late_yes_expires(self) -> None:
        for answer in (None, "y"):
            values = iter([0.0, 301.0])
            with (
                self.subTest(answer=answer),
                patch("group_vault.prompt.os.name", "posix"),
                patch("group_vault.prompt.sys.stdin.isatty", return_value=True),
                patch("group_vault.prompt._posix_line", return_value=answer),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(timed_approval(300, clock=values.__next__), "expired")

    def test_non_terminal_does_not_read(self) -> None:
        with (
            patch("group_vault.prompt.sys.stdin.isatty", return_value=False),
            patch("group_vault.prompt._posix_line") as read,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(timed_approval(300, clock=lambda: 0), "rejected")
        read.assert_not_called()


class TestLifecycle(unittest.TestCase):
    def test_auto_approve_skips_input_but_not_expiry(self) -> None:
        entry = LocalRequest(request(), 300)
        with (
            patch("group_vault.daemon.time.monotonic", return_value=0),
            patch("group_vault.daemon.timed_approval") as prompt,
            patch("group_vault.daemon.show_status"),
        ):
            self.assertEqual(authorize(entry, True), "approved")
        prompt.assert_not_called()
        with (
            patch("group_vault.daemon.time.monotonic", return_value=301),
            patch("group_vault.daemon.show_status"),
        ):
            self.assertEqual(authorize(entry, True), "expired")

    def test_whole_batch_receives_deadlines_before_first_prompt(self) -> None:
        clock = [0.0]

        def slow_answer(deadline: float) -> str:
            clock[0] = 301.0
            return "approved"

        with (
            patch("group_vault.daemon.time.monotonic", side_effect=lambda: clock[0]),
            patch(
                "group_vault.daemon.CoordinatorClient.pending_requests",
                return_value=[request("first"), request("second")],
            ),
            patch("group_vault.daemon.timed_approval", side_effect=slow_answer) as prompt,
            patch("group_vault.daemon.show_status") as status,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(run_daemon("http://localhost", "1", once=True, interactive=True), 1)
        self.assertEqual(prompt.call_count, 1)
        self.assertEqual(sum(call.args[0] == "EXPIRED" for call in status.call_args_list), 2)

    def test_polling_does_not_reset_deadline(self) -> None:
        with (
            patch("group_vault.daemon.time.monotonic", side_effect=[0, 0, 301, 301]),
            patch(
                "group_vault.daemon.CoordinatorClient.pending_requests", return_value=[request()]
            ),
            patch("group_vault.daemon.time.sleep", side_effect=[None, KeyboardInterrupt]),
            patch("group_vault.daemon.show_status") as status,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(run_daemon("http://localhost", "1"), 0)
        self.assertEqual(sum(call.args[0] == "EXPIRED" for call in status.call_args_list), 1)

    def test_changed_request_is_rejected(self) -> None:
        changed = SignatureRequest("demo-1", "demo-vault", ("1",), b"changed")
        with (
            patch(
                "group_vault.daemon.CoordinatorClient.pending_requests",
                side_effect=[[request()], [changed]],
            ),
            patch("group_vault.daemon.time.sleep", side_effect=[None, KeyboardInterrupt]),
            patch("group_vault.daemon.show_status") as status,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(run_daemon("http://localhost", "1"), 0)
        self.assertTrue(any(call.args[0] == "REJECTED" for call in status.call_args_list))


class TestExitCodes(unittest.TestCase):
    def test_parse_errors_exit_one(self) -> None:
        cases = [[], ["unknown"], ["start"], ["init", "--total", "bad", "--threshold", "2"]]
        for arguments in cases:
            with (
                self.subTest(arguments=arguments),
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit) as caught,
            ):
                _build_parser().parse_args(arguments)
            self.assertEqual(caught.exception.code, 1)

    def test_help_exit_zero(self) -> None:
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as caught:
            _build_parser().parse_args(["--help"])
        self.assertEqual(caught.exception.code, 0)

    def test_auto_approve_forwarded_and_failure_not_hidden(self) -> None:
        with patch("group_vault.vault_cli.run_daemon", return_value=1) as daemon:
            result = main(
                ["start", "--node-id", "1", "--coordinator", "http://localhost", "--auto-approve"]
            )
        self.assertEqual(result, 1)
        self.assertTrue(daemon.call_args.kwargs["auto_approve"])


if __name__ == "__main__":
    unittest.main()
