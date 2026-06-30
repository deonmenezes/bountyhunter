"""Tests for core/llm/dispatcher/client.py — worker-side dispatcher helpers."""

from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from core.llm.dispatcher import client


class TestReadToken(unittest.TestCase):

    def test_reads_token_from_explicit_fd(self):
        r, w = os.pipe()
        os.write(w, b"test-token-value")
        os.close(w)
        token = client.read_token(fd=r)
        self.assertEqual(token, "test-token-value")

    def test_fd_closed_after_read(self):
        r, w = os.pipe()
        os.write(w, b"token123")
        os.close(w)
        client.read_token(fd=r)
        with self.assertRaises(OSError):
            os.read(r, 1)

    def test_raises_on_empty_pipe(self):
        r, w = os.pipe()
        os.close(w)
        with self.assertRaises(RuntimeError, msg="pipe was empty"):
            client.read_token(fd=r)

    def test_reads_from_env_var(self):
        r, w = os.pipe()
        os.write(w, b"env-token")
        os.close(w)
        with patch.dict(os.environ, {"MANTISHACK_LLM_TOKEN_FD": str(r)}):
            token = client.read_token()
            self.assertEqual(token, "env-token")

    def test_raises_when_env_not_set(self):
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("MANTISHACK_LLM_TOKEN_FD", None)
            with self.assertRaises(RuntimeError):
                client.read_token()

    def test_strips_whitespace(self):
        r, w = os.pipe()
        os.write(w, b"  trimmed-token  \n")
        os.close(w)
        token = client.read_token(fd=r)
        self.assertEqual(token, "trimmed-token")

    def test_non_ascii_raises_runtime_error(self):
        r, w = os.pipe()
        os.write(w, b"\xff\xfe\x00\x01")
        os.close(w)
        with self.assertRaises(RuntimeError):
            client.read_token(fd=r)


class TestGetOrReadToken(unittest.TestCase):

    def setUp(self):
        # Reset the module-level cache before each test
        client._cached_token = None

    def tearDown(self):
        client._cached_token = None

    def test_caches_token_across_calls(self):
        r, w = os.pipe()
        os.write(w, b"cached-token")
        os.close(w)
        with patch.dict(os.environ, {"MANTISHACK_LLM_TOKEN_FD": str(r)}):
            first = client._get_or_read_token()
            second = client._get_or_read_token()
            self.assertEqual(first, "cached-token")
            self.assertEqual(second, "cached-token")

    def test_returns_cached_value_without_reading(self):
        client._cached_token = "pre-cached"
        result = client._get_or_read_token()
        self.assertEqual(result, "pre-cached")


class TestMakeHttpxClient(unittest.TestCase):

    def test_creates_client_with_token_header(self):
        http = client._make_httpx_client("/tmp/test.sock", "my-token")
        self.assertEqual(http.headers.get("X-Mantishack-Token"), "my-token")

    def test_custom_timeout(self):
        http = client._make_httpx_client("/tmp/test.sock", "tok", timeout=120.0)
        self.assertEqual(http.timeout.read, 120.0)

    def test_default_timeout(self):
        http = client._make_httpx_client("/tmp/test.sock", "tok")
        self.assertEqual(http.timeout.read, 60.0)


class TestResolveSocketAndToken(unittest.TestCase):

    def setUp(self):
        client._cached_token = None

    def tearDown(self):
        client._cached_token = None

    def test_explicit_values_returned_as_is(self):
        sock, tok = client._resolve_socket_and_token("/my/sock", "my-tok")
        self.assertEqual(sock, "/my/sock")
        self.assertEqual(tok, "my-tok")

    def test_reads_socket_from_env(self):
        client._cached_token = "cached"
        with patch.dict(os.environ, {"MANTISHACK_LLM_SOCKET": "/env/sock"}):
            sock, tok = client._resolve_socket_and_token(None, None)
            self.assertEqual(sock, "/env/sock")
            self.assertEqual(tok, "cached")

    def test_raises_when_socket_env_not_set(self):
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("MANTISHACK_LLM_SOCKET", None)
            with self.assertRaises(RuntimeError):
                client._resolve_socket_and_token(None, "tok")


class TestRelayForGrandchild(unittest.TestCase):

    def setUp(self):
        client._cached_token = None

    def tearDown(self):
        client._cached_token = None

    def test_returns_socket_and_readable_fd(self):
        client._cached_token = "relay-token"
        with patch.dict(os.environ, {"MANTISHACK_LLM_SOCKET": "/relay/sock"}):
            sock, fd = client.relay_for_grandchild()
            self.assertEqual(sock, "/relay/sock")
            token_bytes = os.read(fd, 64)
            os.close(fd)
            self.assertEqual(token_bytes.decode(), "relay-token")

    def test_fd_is_inheritable(self):
        client._cached_token = "inherit-token"
        with patch.dict(os.environ, {"MANTISHACK_LLM_SOCKET": "/s"}):
            _, fd = client.relay_for_grandchild()
            self.assertTrue(os.get_inheritable(fd))
            os.close(fd)


class TestMakeAnthropicClient(unittest.TestCase):

    def test_creates_anthropic_client(self):
        try:
            import anthropic
        except ImportError:
            self.skipTest("anthropic not installed")
        c = client.make_anthropic_client(
            socket_path="/tmp/test.sock", token="t", timeout=30.0,
        )
        self.assertIsInstance(c, anthropic.Anthropic)


class TestMakeGeminiBaseUrl(unittest.TestCase):

    def test_returns_base_url_and_http_client(self):
        url, http = client.make_gemini_base_url(
            socket_path="/tmp/test.sock", token="tok",
        )
        self.assertEqual(url, "http://_/gemini")
        self.assertEqual(http.headers.get("X-Mantishack-Token"), "tok")


if __name__ == "__main__":
    unittest.main()
