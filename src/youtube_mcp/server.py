"""YouTube MCP Server — FastMCP entry point."""

import os
import secrets
from urllib.parse import parse_qs

from mcp.server.fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse

from youtube_mcp.auth import YouTubeAuth
from youtube_mcp.utils.quota import QuotaTracker

mcp = FastMCP(
    "YouTube MCP Server",
    instructions="Comprehensive MCP server for YouTube Data API, Analytics API, and Reporting API",
    host=os.environ.get("HOST", "0.0.0.0"),
    port=int(os.environ.get("PORT", "8000")),
    streamable_http_path="/mcp",
)


@mcp.custom_route("/health", methods=["GET"], include_in_schema=False)
async def health_check(request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


@mcp.custom_route("/auth", methods=["GET"], include_in_schema=False)
async def remote_auth_page(request: Request) -> HTMLResponse | PlainTextResponse:
    if not auth.remote_auth_enabled or not os.environ.get("YOUTUBE_MCP_REMOTE_AUTH_KEY"):
        return PlainTextResponse("Not found", status_code=404)
    return HTMLResponse(
        """<!doctype html>
<title>YouTube authorization</title>
<h1>YouTube authorization</h1>
<form method="post" action="/auth/start">
  <label>Authorization key <input type="password" name="key" required></label>
  <button type="submit">Continue to Google</button>
</form>"""
    )


@mcp.custom_route("/auth/start", methods=["POST"], include_in_schema=False)
async def remote_auth_start(request: Request) -> RedirectResponse | PlainTextResponse:
    configured_key = os.environ.get("YOUTUBE_MCP_REMOTE_AUTH_KEY")
    if not auth.remote_auth_enabled or not configured_key:
        return PlainTextResponse("Not found", status_code=404)
    form = parse_qs((await request.body()).decode("utf-8"))
    provided_key = form.get("key", [""])[0]
    if not secrets.compare_digest(provided_key, configured_key):
        return PlainTextResponse("Unauthorized", status_code=401)
    try:
        callback_url = os.environ.get(
            "YOUTUBE_MCP_REMOTE_REDIRECT_URI",
            str(request.url_for("remote_auth_callback")),
        )
        authorization_url = auth.begin_remote_auth(callback_url)
    except Exception:
        return PlainTextResponse("Authorization is temporarily unavailable.", status_code=503)
    return RedirectResponse(authorization_url, status_code=303)


@mcp.custom_route("/auth/callback", methods=["GET"], include_in_schema=False)
async def remote_auth_callback(request: Request) -> PlainTextResponse:
    if not auth.remote_auth_enabled:
        return PlainTextResponse("Not found", status_code=404)
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    if not code or not state:
        return PlainTextResponse("Authorization was not completed.", status_code=400)
    try:
        callback_url = os.environ.get(
            "YOUTUBE_MCP_REMOTE_REDIRECT_URI",
            str(request.url_for("remote_auth_callback")),
        )
        auth.complete_remote_auth(code, state, callback_url)
    except Exception as e:
        print(f"REMOTE OAUTH CALLBACK ERROR: {type(e).__name__}: {e}", flush=True)
        return PlainTextResponse("Authorization failed. Please start again.", status_code=400)
    return PlainTextResponse("Authorization complete. You can close this window.")

# Shared state
auth = YouTubeAuth(
    client_secret_path=os.environ.get("YOUTUBE_MCP_CLIENT_SECRET"),
    config_dir=os.environ.get("YOUTUBE_MCP_CONFIG_DIR"),
    api_key=os.environ.get("YOUTUBE_API_KEY"),
)
quota = QuotaTracker()


# --- Auth tools ---


@mcp.tool()
def youtube_auth() -> dict:
    """Initiate OAuth 2.0 authentication flow.

    Opens a browser window for Google OAuth consent. Required before using
    any tools that access private channel data or analytics.
    """
    try:
        auth.authenticate()
        return {"status": "authenticated", "detail": auth.status()}
    except Exception as e:
        return {"status": "error", "detail": str(e)}


@mcp.tool()
def youtube_auth_status() -> dict:
    """Check current authentication status and quota usage."""
    return {
        "auth": auth.status(),
        "quota": quota.status(),
    }


# --- Register tool modules ---
# Import tool modules so their @mcp.tool() decorators run

from youtube_mcp.tools import (  # noqa: E402
    analytics,  # noqa: F401
    channel,  # noqa: F401
    comments,  # noqa: F401
    playlists,  # noqa: F401
    publishing,  # noqa: F401
    reporting,  # noqa: F401
    search,  # noqa: F401
    transcripts,  # noqa: F401
)


def main():
    mcp.run(transport=os.environ.get("MCP_TRANSPORT", "streamable-http"))


if __name__ == "__main__":
    main()
