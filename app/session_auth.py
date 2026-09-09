import os
import secrets
import threading
import time
from dataclasses import dataclass

COOKIE_NAME = os.getenv("SESSION_COOKIE_NAME", "postfix_dashboard_session")
IDLE_TIMEOUT_MINUTES = max(1, int(os.getenv("SESSION_IDLE_TIMEOUT_MINUTES", "15")))
IDLE_TIMEOUT_SECONDS = IDLE_TIMEOUT_MINUTES * 60
ABSOLUTE_TIMEOUT_HOURS = max(1, int(os.getenv("SESSION_ABSOLUTE_TIMEOUT_HOURS", "8")))
ABSOLUTE_TIMEOUT_SECONDS = ABSOLUTE_TIMEOUT_HOURS * 60 * 60
COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "false").strip().lower() in {
    "1", "true", "yes", "on"
}


@dataclass
class Session:
    username: str
    created_at: float
    last_activity: float


class SessionStore:
    def __init__(self):
        self._sessions = {}
        self._lock = threading.RLock()

    def create(self, username: str) -> str:
        token = secrets.token_urlsafe(32)
        now = time.time()
        with self._lock:
            self._sessions[token] = Session(
                username=username,
                created_at=now,
                last_activity=now,
            )
            self._cleanup_locked(now)
        return token

    def get(self, token: str):
        if not token:
            return None
        now = time.time()
        with self._lock:
            session = self._sessions.get(token)
            if not session:
                return None
            if (
                now - session.last_activity > IDLE_TIMEOUT_SECONDS
                or now - session.created_at > ABSOLUTE_TIMEOUT_SECONDS
            ):
                self._sessions.pop(token, None)
                return None
            return session

    def touch(self, token: str):
        if not token:
            return None
        now = time.time()
        with self._lock:
            session = self._sessions.get(token)
            if not session:
                return None
            if (
                now - session.last_activity > IDLE_TIMEOUT_SECONDS
                or now - session.created_at > ABSOLUTE_TIMEOUT_SECONDS
            ):
                self._sessions.pop(token, None)
                return None
            session.last_activity = now
            return session

    def destroy(self, token: str):
        if not token:
            return None
        with self._lock:
            return self._sessions.pop(token, None)

    def active_count(self) -> int:
        now = time.time()
        with self._lock:
            self._cleanup_locked(now)
            return len(self._sessions)

    def _cleanup_locked(self, now: float):
        expired = [
            token
            for token, session in self._sessions.items()
            if (
                now - session.last_activity > IDLE_TIMEOUT_SECONDS
                or now - session.created_at > ABSOLUTE_TIMEOUT_SECONDS
            )
        ]
        for token in expired:
            self._sessions.pop(token, None)


store = SessionStore()
