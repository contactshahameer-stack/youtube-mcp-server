"""YouTube MCP Server — FastMCP entry point."""

import os

from mcp.server.fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse

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
