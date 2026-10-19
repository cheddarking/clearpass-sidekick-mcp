import sys
import io
import logging
import pytest
from src.logging_config import configure_mcp_logging


def test_configure_mcp_logging_sets_stderr_handlers():
    root_logger = configure_mcp_logging(level=logging.DEBUG)

    # Verify root logger has handlers
    assert len(root_logger.handlers) > 0
    for handler in root_logger.handlers:
        assert isinstance(handler, logging.StreamHandler)
        # Verify handler stream successfully writes to current sys.stderr via proxy
        capture = io.StringIO()
        old_stderr = sys.stderr
        try:
            sys.stderr = capture
            handler.stream.write("proxy test")
            handler.stream.flush()
        finally:
            sys.stderr = old_stderr
        assert "proxy test" in capture.getvalue()


def test_print_redirection_to_stderr():
    configure_mcp_logging()

    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()

    old_stdout = sys.stdout
    old_stderr = sys.stderr

    try:
        sys.stdout = stdout_capture
        sys.stderr = stderr_capture

        # 1. Print without file specified should go to sys.stderr
        print("test default print")

        # 2. Print with file=sys.stdout should be intercepted and go to sys.stderr
        print("test stdout redirect", file=sys.stdout)

        # 3. Print with file=sys.stderr should go to sys.stderr
        print("test explicit stderr", file=sys.stderr)

    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr

    stdout_output = stdout_capture.getvalue()
    stderr_output = stderr_capture.getvalue()

    # Verify sys.stdout received nothing from patched print
    assert stdout_output == ""

    # Verify sys.stderr received all prints
    assert "test default print" in stderr_output
    assert "test stdout redirect" in stderr_output
    assert "test explicit stderr" in stderr_output


def test_logging_does_not_pollute_stdout():
    configure_mcp_logging(level=logging.INFO)

    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()

    old_stdout = sys.stdout
    old_stderr = sys.stderr

    try:
        sys.stdout = stdout_capture
        sys.stderr = stderr_capture

        test_logger = logging.getLogger("mcp_test_logger")
        test_logger.info("This is an info log message")
        test_logger.error("This is an error log message")

    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr

    stdout_output = stdout_capture.getvalue()
    stderr_output = stderr_capture.getvalue()

    # Verify stdout is completely unpolluted
    assert stdout_output == ""

    # Verify stderr received the log messages
    assert "This is an info log message" in stderr_output
    assert "This is an error log message" in stderr_output
