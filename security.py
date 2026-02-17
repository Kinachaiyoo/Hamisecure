import time
from collections import defaultdict, deque
from flask import request, jsonify

# Simple in-memory limiter (good for prototype; production use Redis)
class RateLimiter:
    def __init__(self, max_requests=30, window_seconds=60):
        self.max_requests = max_requests
        self.window = window_seconds
        self.hits = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.time()
        q = self.hits[key]
        while q and (now - q[0]) > self.window:
            q.popleft()
        if len(q) >= self.max_requests:
            return False
        q.append(now)
        return True

limiter = RateLimiter(max_requests=60, window_seconds=60)


def client_key():
    # behind proxy you might use X-Forwarded-For; keep it simple
    return request.remote_addr or "unknown"


def require_rate_limit():
    if not limiter.allow(client_key()):
        return jsonify({"error": "Too many requests. Please slow down."}), 429
    return None


def apply_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    resp.headers["Cache-Control"] = "no-store"
    # Light CSP for prototype (adjust if you add external assets)
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
    )
    return resp


def require_admin_key():
    import os
    admin = os.getenv("HAMISECURE_ADMIN_KEY", "").strip()
    if not admin:
        return jsonify({"error": "Admin key not set on server."}), 403

    key = request.headers.get("X-Admin-Key", "").strip()
    if key != admin:
        return jsonify({"error": "Unauthorized."}), 401
    return None

