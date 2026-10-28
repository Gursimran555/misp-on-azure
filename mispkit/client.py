"""A very small MISP REST client.

PyMISP is the proper library, but for the handful of calls this toolkit makes
I wanted something I could read top to bottom. The API key is only ever read
from the environment and is never printed.
"""

from __future__ import annotations

import os

import requests


class MispError(RuntimeError):
    pass


class MispClient:
    def __init__(self, url: str, key: str, verify: bool | str = True,
                 timeout: int = 30, session: requests.Session | None = None):
        if not url or not key:
            raise MispError("MISP URL and API key are required")
        self.url = url.rstrip("/")
        self.verify = verify
        self.timeout = timeout
        self.session = session or requests.Session()
        self.session.headers.update({
            "Authorization": key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        })

    @classmethod
    def from_env(cls) -> "MispClient":
        """MISP_URL, MISP_KEY and optionally MISP_VERIFY (path to CA bundle or 'false')."""
        verify_env = os.environ.get("MISP_VERIFY", "true")
        if verify_env.lower() in ("false", "0", "no"):
            verify: bool | str = False
        elif verify_env.lower() in ("true", "1", "yes"):
            verify = True
        else:
            verify = verify_env
        return cls(os.environ.get("MISP_URL", ""), os.environ.get("MISP_KEY", ""), verify)

    def _request(self, method: str, path: str, **kwargs):
        resp = self.session.request(method, f"{self.url}{path}", verify=self.verify,
                                    timeout=self.timeout, **kwargs)
        if resp.status_code >= 400:
            # MISP error bodies are JSON with a "message"/"errors" field; don't echo headers.
            try:
                detail = resp.json()
            except ValueError:
                detail = resp.text[:200]
            raise MispError(f"{method} {path} -> HTTP {resp.status_code}: {detail}")
        return resp.json()

    def feeds(self) -> list[dict]:
        data = self._request("GET", "/feeds/index")
        return [item.get("Feed", item) for item in data]

    def event(self, event_id: int | str) -> dict:
        data = self._request("GET", f"/events/view/{event_id}")
        return data.get("Event", data)

    def add_event(self, event: dict) -> dict:
        data = self._request("POST", "/events/add", json={"Event": event})
        return data.get("Event", data)
