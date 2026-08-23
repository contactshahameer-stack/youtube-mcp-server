"""Tests for the temporary remote authorization routes."""

from unittest.mock import AsyncMock, MagicMock

import pytest


class FakeRequest:
    def __init__(self, body="", query_params=None):
        self.body = AsyncMock(return_value=body.encode())
        self.query_params = query_params or {}

    def url_for(self, name):
        assert name == "remote_auth_callback"
        return "https://service.test/auth/callback"


@pytest.mark.asyncio
async def test_remote_auth_start_requires_key(monkeypatch):
    monkeypatch.setenv("YOUTUBE_MCP_REMOTE_AUTH_ENABLED", "true")
    monkeypatch.setenv("YOUTUBE_MCP_REMOTE_AUTH_KEY", "correct-key")
    from youtube_mcp import server

    response = await server.remote_auth_start(FakeRequest("key=wrong-key"))

    assert response.status_code == 401
    assert response.body == b"Unauthorized"


@pytest.mark.asyncio
async def test_remote_auth_start_redirects_without_exposing_key(monkeypatch):
    monkeypatch.setenv("YOUTUBE_MCP_REMOTE_AUTH_ENABLED", "true")
    monkeypatch.setenv("YOUTUBE_MCP_REMOTE_AUTH_KEY", "correct-key")
    monkeypatch.setenv(
        "YOUTUBE_MCP_REMOTE_REDIRECT_URI", "https://service.test/auth/callback"
    )
    from youtube_mcp import server

    monkeypatch.setattr(server, "auth", MagicMock())
    server.auth.begin_remote_auth.return_value = "https://accounts.google.test/auth"
    response = await server.remote_auth_start(FakeRequest("key=correct-key"))

    assert response.status_code == 303
    assert response.headers["location"] == "https://accounts.google.test/auth"
    assert "correct-key" not in response.headers["location"]
    server.auth.begin_remote_auth.assert_called_once_with(
        "https://service.test/auth/callback"
    )


@pytest.mark.asyncio
async def test_remote_auth_callback_hides_flow_errors(monkeypatch):
    monkeypatch.setenv("YOUTUBE_MCP_REMOTE_AUTH_ENABLED", "true")
    from youtube_mcp import server

    monkeypatch.setattr(server, "auth", MagicMock())
    server.auth.complete_remote_auth.side_effect = RuntimeError("secret token details")
    response = await server.remote_auth_callback(
        FakeRequest(query_params={"code": "code", "state": "state"})
    )

    assert response.status_code == 400
    assert b"secret token details" not in response.body
    assert b"code" not in response.body
