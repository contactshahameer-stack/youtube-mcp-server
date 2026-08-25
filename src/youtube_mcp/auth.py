"""OAuth 2.0 authentication for YouTube APIs.

Users must provide their own client_secret.json from their Google Cloud project.
On first use, a browser-based OAuth consent flow runs and stores the token locally.
"""

import json
import os
import secrets
import time
from pathlib import Path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# All scopes we need across all phases
SCOPES = [
    "https://www.googleapis.com/auth/youtube.readonly",
    "https://www.googleapis.com/auth/youtube",
    "https://www.googleapis.com/auth/youtube.upload",
    "https://www.googleapis.com/auth/youtube.analytics.readonly",
    "https://www.googleapis.com/auth/youtube.analytics.monetary.readonly",
]

DEFAULT_CONFIG_DIR = Path.home() / ".youtube-mcp"
TOKEN_FILE = "token.json"
PENDING_AUTH_FILE = "pending_auth.json"


class AuthError(Exception):
    pass


class YouTubeAuth:
    """Manages OAuth 2.0 credentials and builds API service clients."""

    def __init__(
        self,
        client_secret_path: str | Path | None = None,
        config_dir: str | Path | None = None,
        api_key: str | None = None,
    ):
        env_config_dir = os.environ.get("YOUTUBE_MCP_CONFIG_DIR")
        self.config_dir = (
            Path(config_dir)
            if config_dir
            else Path(env_config_dir) if env_config_dir else DEFAULT_CONFIG_DIR
        )
        env_token_path = os.environ.get("YOUTUBE_MCP_TOKEN_PATH")
        self.token_path = (
            Path(env_token_path) if env_token_path else self.config_dir / TOKEN_FILE
        )
        self._credentials: Credentials | None = None
        self.client_secret_json: str | None = None
        # File-backed (not in-memory) so a pending auth started on one
        # process/worker can be completed by another, as long as they share
        # the same config_dir volume. See begin_remote_auth / complete_remote_auth.
        self._pending_auth_path = self.config_dir / PENDING_AUTH_FILE
        
        # In-memory store for Railway (single worker)
        self._pending_store = {}

        # Resolve client_secret.json path
        if client_secret_path:
            self.client_secret_path = Path(client_secret_path)
        else:
            env_json = os.environ.get("YOUTUBE_MCP_CLIENT_SECRET_JSON")
            if env_json:
                self.client_secret_json = env_json
                self.client_secret_path = self.config_dir / "client_secret.json"
            else:
                env_path = os.environ.get("YOUTUBE_MCP_CLIENT_SECRET")
                if env_path:
                    self.client_secret_path = Path(env_path)
                else:
                    self.client_secret_path = self.config_dir / "client_secret.json"

        # API key fallback for public-only operations
        self.api_key = api_key or os.environ.get("YOUTUBE_API_KEY")

    @property
    def remote_auth_enabled(self) -> bool:
        """Whether the temporary remote authorization flow is enabled."""
        return os.environ.get("YOUTUBE_MCP_REMOTE_AUTH_ENABLED", "").lower() == "true"

    def _make_flow(self) -> InstalledAppFlow:
        """Create the OAuth flow using the configured client credentials."""
        if self.client_secret_json:
            try:
                client_config = json.loads(self.client_secret_json)
            except json.JSONDecodeError as e:
                raise AuthError(
                    "YOUTUBE_MCP_CLIENT_SECRET_JSON must contain valid JSON."
                ) from e
            return InstalledAppFlow.from_client_config(client_config, SCOPES)
        if not self.client_secret_path.exists():
            raise AuthError(
                f"client_secret.json not found at {self.client_secret_path}. "
                f"Download it from your Google Cloud Console "
                f"(APIs & Services > Credentials > OAuth 2.0 Client IDs) "
                f"and place it at this path, or set YOUTUBE_MCP_CLIENT_SECRET env var."
            )
        return InstalledAppFlow.from_client_secrets_file(
            str(self.client_secret_path), SCOPES
        )

    def _write_pending_auth(self, state: str, code_verifier: str | None, expires_at: float) -> None:
        """Persist the pending OAuth state/PKCE verifier to in-memory store (Railway fix)."""
        self._pending_store[state] = {
            "state": state,
            "code_verifier": code_verifier,
            "expires_at": expires_at,
        }
        
        # Also write to file for local development (backward compatible)
        self._pending_auth_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "state": state,
            "code_verifier": code_verifier,
            "expires_at": expires_at,
        }
        self._pending_auth_path.write_text(json.dumps(payload))
        try:
            os.chmod(self._pending_auth_path, 0o600)
        except OSError:
            # Best-effort; not fatal if the platform/filesystem doesn't support it.
            pass

    def _read_and_clear_pending_auth(self, state: str) -> dict | None:
        """Load the pending OAuth record from in-memory store (Railway fix) and delete it."""
        # Try in-memory first (Railway)
        data = self._pending_store.pop(state, None)
        if data and time.time() < data.get("expires_at", 0):
            return data
        
        # Fallback to file (local development)
        try:
            raw = self._pending_auth_path.read_text()
        except FileNotFoundError:
            return None
        finally:
            self._pending_auth_path.unlink(missing_ok=True)
        try:
            pending = json.loads(raw)
            if pending.get("state") == state and time.time() < pending.get("expires_at", 0):
                return pending
        except json.JSONDecodeError:
            return None
        return None

    def begin_remote_auth(self, redirect_uri: str) -> str:
        """Create a one-time authorization URL for a browser-based flow."""
        if not self.remote_auth_enabled:
            raise AuthError("Remote authorization is disabled.")
        flow = self._make_flow()
        flow.redirect_uri = redirect_uri
        authorization_url, state = flow.authorization_url(
            access_type="offline",
            include_granted_scopes="true",
            prompt="consent",
        )
        self._write_pending_auth(state, flow.code_verifier, time.time() + 600)
        return authorization_url

    def complete_remote_auth(self, code: str, state: str, redirect_uri: str) -> None:
        """Exchange a validated callback for credentials and persist the token."""
        pending = self._read_and_clear_pending_auth(state)
        if not pending or not secrets.compare_digest(pending["state"], state):
            raise AuthError("Invalid or expired OAuth state.")
        if time.time() >= pending["expires_at"]:
            raise AuthError("Invalid or expired OAuth state.")

        flow = self._make_flow()
        flow.redirect_uri = redirect_uri
        flow.code_verifier = pending["code_verifier"]
        flow.fetch_token(code=code)
        self._save_token(flow.credentials)
        self._credentials = flow.credentials

    def _load_token(self) -> Credentials | None:
        """Load saved credentials from token file."""
        if not self.token_path.exists():
            return None
        try:
            creds = Credentials.from_authorized_user_file(str(self.token_path), SCOPES)
            return creds
        except Exception:
            return None

    def _save_token(self, creds: Credentials):
        """Save credentials to token file."""
        self.token_path.parent.mkdir(parents=True, exist_ok=True)
        self.token_path.write_text(creds.to_json())

    def authenticate(self) -> Credentials:
        """Get valid credentials, running OAuth flow if needed.

        Returns valid credentials. Raises AuthError if client_secret.json
        is missing or the flow fails.
        """
        creds = self._load_token()

        if creds and creds.valid:
            self._credentials = creds
            return creds

        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
                self._save_token(creds)
                self._credentials = creds
                return creds
            except Exception:
                # Refresh failed, need to re-auth
                pass

        # Need to run the OAuth flow
        try:
            flow = self._make_flow()
            creds = flow.run_local_server(port=0)
            self._save_token(creds)
            self._credentials = creds
            return creds
        except Exception as e:
            raise AuthError(f"OAuth flow failed: {e}") from e

    @property
    def credentials(self) -> Credentials:
        """Get current credentials, authenticating if needed."""
        if self._credentials and self._credentials.valid:
            return self._credentials
        return self.authenticate()

    def build_youtube_service(self):
        """Build a YouTube Data API v3 service client."""
        return build("youtube", "v3", credentials=self.credentials)

    def build_youtube_analytics_service(self):
        """Build a YouTube Analytics API service client."""
        return build("youtubeAnalytics", "v2", credentials=self.credentials)

    def build_youtube_reporting_service(self):
        """Build a YouTube Reporting API service client."""
        return build("youtubereporting", "v1", credentials=self.credentials)

    def build_public_youtube_service(self):
        """Build a YouTube Data API client using API key only (public data)."""
        if not self.api_key:
            raise AuthError(
                "No API key available. Set YOUTUBE_API_KEY env var for public-only access."
            )
        return build("youtube", "v3", developerKey=self.api_key)

    def status(self) -> dict:
        """Return current auth status."""
        creds = self._load_token()
        if creds and creds.valid:
            return {
                "authenticated": True,
                "scopes": creds.scopes or [],
                "token_path": str(self.token_path),
                "expired": False,
            }
        if creds and creds.expired:
            return {
                "authenticated": False,
                "expired": True,
                "has_refresh_token": bool(creds.refresh_token),
                "token_path": str(self.token_path),
            }
        return {
            "authenticated": False,
            "token_exists": self.token_path.exists(),
            "client_secret_exists": bool(
                self.client_secret_json or self.client_secret_path.exists()
            ),
            "client_secret_path": str(self.client_secret_path),
            }
