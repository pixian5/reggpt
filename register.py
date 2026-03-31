"""
Automated OpenAI/ChatGPT account registration script.

Phase 1 – Register a new account using a TempMail.lol disposable address.
Phase 2 – Log in via the ChatGPT web channel (avoids add-phone prompt) and
           return the access_token.

Dependencies:
    pip install curl_cffi
"""

import base64
import hashlib
import json
import os
import random
import re
import string
import time
import urllib.parse
from typing import Optional


# ---------------------------------------------------------------------------
# Optional: set PROXY environment variable, e.g. "http://user:pass@host:port"
# ---------------------------------------------------------------------------
PROXY: Optional[str] = os.environ.get("PROXY")

# OAuth constants (Codex CLI client – used only during registration)
CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
AUTH_URL = "https://auth.openai.com/oauth/authorize"
REDIRECT_URI = "http://localhost:1455/auth/callback"
SCOPE = "openid email profile offline_access"

# TempMail.lol base URL
TEMPMAIL_BASE = "https://api.tempmail.lol"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_session():
    """Return a curl_cffi AsyncSession-like object configured for Chrome."""
    try:
        from curl_cffi.requests import Session
    except ImportError as exc:
        raise ImportError(
            "curl_cffi is required. Install it with: pip install curl_cffi"
        ) from exc

    kwargs = {}
    if PROXY:
        kwargs["proxies"] = {"http": PROXY, "https": PROXY}
    return Session(impersonate="chrome", **kwargs)


def _b64url(data: bytes) -> str:
    """URL-safe base64 encoding without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _pkce_pair() -> tuple[str, str]:
    """Return (code_verifier, code_challenge) for PKCE."""
    verifier = _b64url(os.urandom(32))
    challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
    return verifier, challenge


def _random_state() -> str:
    return _b64url(os.urandom(16))


def _random_password(length: int = 16) -> str:
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(random.choices(chars, k=length))


def _random_name() -> tuple[str, str]:
    first_names = [
        "Alice", "Bob", "Carol", "David", "Emma", "Frank",
        "Grace", "Henry", "Iris", "Jack", "Karen", "Liam",
        "Mia", "Noah", "Olivia", "Peter", "Quinn", "Rachel",
        "Sam", "Tara",
    ]
    last_names = [
        "Smith", "Johnson", "Williams", "Brown", "Jones",
        "Garcia", "Miller", "Davis", "Wilson", "Anderson",
        "Taylor", "Thomas", "Moore", "Jackson", "Martin",
        "Lee", "Perez", "Thompson", "White", "Harris",
    ]
    return random.choice(first_names), random.choice(last_names)


def _random_birthday() -> str:
    """Return a birthday string YYYY-MM-DD for a person aged 20-40."""
    year = random.randint(1985, 2005)
    month = random.randint(1, 12)
    day = random.randint(1, 28)
    return f"{year}-{month:02d}-{day:02d}"


def _raise_for_status(resp, context: str = "") -> None:
    if resp.status_code >= 400:
        raise RuntimeError(
            f"HTTP {resp.status_code} [{context}]: {resp.text[:500]}"
        )


# ---------------------------------------------------------------------------
# TempMail.lol helpers
# ---------------------------------------------------------------------------

def create_temp_email(session) -> tuple[str, str]:
    """Create a temporary inbox and return (email, token)."""
    resp = session.get(f"{TEMPMAIL_BASE}/generate/random")
    _raise_for_status(resp, "create_temp_email")
    data = resp.json()
    return data["address"], data["token"]


def poll_for_otp(
    session,
    token: str,
    exclude: Optional[set] = None,
    timeout: int = 120,
    interval: int = 5,
) -> str:
    """
    Poll the TempMail.lol inbox until a 6-digit OTP is found.

    :param exclude: set of OTP codes already used (for deduplication).
    :param timeout: maximum seconds to wait.
    :param interval: polling interval in seconds.
    :returns: the OTP string.
    """
    if exclude is None:
        exclude = set()
    deadline = time.time() + timeout
    while time.time() < deadline:
        resp = session.get(f"{TEMPMAIL_BASE}/auth/messages/{token}")
        if resp.status_code == 200:
            messages = resp.json().get("email", [])
            for msg in messages:
                body = msg.get("body", "") or ""
                subject = msg.get("subject", "") or ""
                combined = subject + " " + body
                codes = re.findall(r"\b(\d{6})\b", combined)
                for code in codes:
                    if code not in exclude:
                        return code
        time.sleep(interval)
    raise TimeoutError("Timed out waiting for OTP email.")


# ---------------------------------------------------------------------------
# Phase 1 – Registration
# ---------------------------------------------------------------------------

def _get_sentinel_token(
    session,
    *,
    p: str = "",
    token_id: str = "",
    flow: str = "authorize_continue",
) -> str:
    """POST to sentinel/req and return the sentinel token string."""
    payload = {"p": p, "id": token_id, "flow": flow}
    resp = session.post(
        "https://sentinel.openai.com/backend-api/sentinel/req",
        json=payload,
        headers={"Content-Type": "application/json"},
    )
    _raise_for_status(resp, "sentinel/req")
    return resp.json().get("token", resp.json().get("t", ""))


def _sentinel_header(sentinel_token: str, p: str = "", token_id: str = "", flow: str = "authorize_continue") -> str:
    """Build the openai-sentinel-token header value (full JSON)."""
    return json.dumps(
        {"p": p, "t": "", "c": sentinel_token, "id": token_id, "flow": flow},
        separators=(",", ":"),
    )


def phase1_register(
    session,
    email: str,
    password: str,
) -> str:
    """
    Full registration flow using the given *session*.

    After this function returns the account exists and the email is verified.
    Returns the registration OTP code that was consumed.
    """
    # ------------------------------------------------------------------
    # 1. Build OAuth URL with PKCE
    # ------------------------------------------------------------------
    code_verifier, code_challenge = _pkce_pair()
    state = _random_state()
    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPE,
        "response_type": "code",
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    oauth_url = AUTH_URL + "?" + urllib.parse.urlencode(params)

    # ------------------------------------------------------------------
    # 2. GET the OAuth URL – picks up oai-did device-id cookie
    # ------------------------------------------------------------------
    resp = session.get(oauth_url, allow_redirects=True)
    _raise_for_status(resp, "GET oauth_url")
    # The cookie jar on *session* now contains oai-did

    # ------------------------------------------------------------------
    # 3. Obtain the first sentinel token
    # ------------------------------------------------------------------
    sentinel_token = _get_sentinel_token(session)

    # ------------------------------------------------------------------
    # 4. Submit email for signup (authorize/continue)
    # ------------------------------------------------------------------
    resp = session.post(
        "https://auth.openai.com/api/accounts/authorize/continue",
        json={"username": {"value": email, "kind": "email"}, "screen_hint": "signup"},
        headers={
            "Content-Type": "application/json",
            "openai-sentinel-token": _sentinel_header(sentinel_token),
        },
    )
    _raise_for_status(resp, "authorize/continue signup")

    # ------------------------------------------------------------------
    # 5. Set password
    # ------------------------------------------------------------------
    resp = session.post(
        "https://auth.openai.com/api/accounts/user/register",
        json={"password": password},
        headers={"Content-Type": "application/json"},
    )
    _raise_for_status(resp, "user/register")

    # ------------------------------------------------------------------
    # 6. Trigger OTP email
    # ------------------------------------------------------------------
    resp = session.get("https://auth.openai.com/api/accounts/email-otp/send")
    _raise_for_status(resp, "email-otp/send")

    # ------------------------------------------------------------------
    # 7. Poll inbox for registration OTP
    # ------------------------------------------------------------------
    print("[Phase 1] Waiting for registration OTP…")
    reg_token = getattr(session, "_tempmail_token", None)
    otp = poll_for_otp(session, reg_token)
    print(f"[Phase 1] Got OTP: {otp}")

    # ------------------------------------------------------------------
    # 8. Validate OTP
    # ------------------------------------------------------------------
    resp = session.post(
        "https://auth.openai.com/api/accounts/email-otp/validate",
        json={"code": otp},
        headers={"Content-Type": "application/json"},
    )
    _raise_for_status(resp, "email-otp/validate")

    # ------------------------------------------------------------------
    # 9. Refresh sentinel token before create_account
    # ------------------------------------------------------------------
    sentinel_token = _get_sentinel_token(session)

    # ------------------------------------------------------------------
    # 10. Create account (random name + birthday)
    # ------------------------------------------------------------------
    first, last = _random_name()
    birthday = _random_birthday()
    resp = session.post(
        "https://auth.openai.com/api/accounts/create_account",
        json={
            "first_name": first,
            "last_name": last,
            "birthday": birthday,
        },
        headers={
            "Content-Type": "application/json",
            "openai-sentinel-token": _sentinel_header(sentinel_token),
        },
    )
    _raise_for_status(resp, "create_account")
    print(f"[Phase 1] Account created: {first} {last}")
    return otp


# ---------------------------------------------------------------------------
# Phase 2 – Login via ChatGPT web channel and retrieve access_token
# ---------------------------------------------------------------------------

def phase2_get_token(
    session,
    email: str,
    password: str,
    tempmail_token: str,
    inbox_session,
    used_otps: Optional[set] = None,
) -> str:
    """
    Log in through the ChatGPT web channel and return the access_token.

    :param session: fresh curl_cffi Session (no registration cookies).
    :param inbox_session: session used to poll TempMail.lol (can be the
                          registration session – cookies are irrelevant there).
    """
    if used_otps is None:
        used_otps = set()

    # ------------------------------------------------------------------
    # 1. Get CSRF token
    # ------------------------------------------------------------------
    resp = session.get("https://chatgpt.com/api/auth/csrf")
    _raise_for_status(resp, "GET csrf")
    csrf_token = resp.json()["csrfToken"]

    # ------------------------------------------------------------------
    # 2. Initiate signin
    # ------------------------------------------------------------------
    resp = session.post(
        "https://chatgpt.com/api/auth/signin/openai",
        data=f"callbackUrl=%2F&csrfToken={csrf_token}&json=true",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    _raise_for_status(resp, "signin/openai")
    auth_redirect_url = resp.json()["url"]

    # ------------------------------------------------------------------
    # 3. Follow redirect to auth.openai.com (sets session cookies)
    # ------------------------------------------------------------------
    resp = session.get(auth_redirect_url, allow_redirects=True)
    _raise_for_status(resp, "GET auth_redirect_url")

    # ------------------------------------------------------------------
    # 4. Submit email for login
    # ------------------------------------------------------------------
    # Obtain a fresh sentinel token in the new session
    sentinel_token = _get_sentinel_token(session)

    resp = session.post(
        "https://auth.openai.com/api/accounts/authorize/continue",
        json={"username": {"value": email, "kind": "email"}, "screen_hint": "login"},
        headers={
            "Content-Type": "application/json",
            "openai-sentinel-token": _sentinel_header(sentinel_token),
        },
    )
    _raise_for_status(resp, "authorize/continue login")
    data = resp.json()
    if "continue_url" in data:
        resp = session.get(data["continue_url"], allow_redirects=True)
        _raise_for_status(resp, "GET continue_url after email")

    # ------------------------------------------------------------------
    # 5. Submit password
    # ------------------------------------------------------------------
    resp = session.post(
        "https://auth.openai.com/api/accounts/password/verify",
        json={"password": password},
        headers={"Content-Type": "application/json"},
    )
    _raise_for_status(resp, "password/verify")

    # ------------------------------------------------------------------
    # 6. Poll for login OTP (dedup against already-used registration OTPs)
    # ------------------------------------------------------------------
    print("[Phase 2] Waiting for login OTP…")
    otp = poll_for_otp(inbox_session, tempmail_token, exclude=used_otps)
    print(f"[Phase 2] Got login OTP: {otp}")

    # ------------------------------------------------------------------
    # 7. Validate login OTP
    # ------------------------------------------------------------------
    resp = session.post(
        "https://auth.openai.com/api/accounts/email-otp/validate",
        json={"code": otp},
        headers={"Content-Type": "application/json"},
    )
    _raise_for_status(resp, "email-otp/validate (login)")
    data = resp.json()
    if "continue_url" in data:
        resp = session.get(data["continue_url"], allow_redirects=True)
        _raise_for_status(resp, "GET continue_url after login otp")

    # ------------------------------------------------------------------
    # 8. Retrieve access token from ChatGPT session endpoint
    # ------------------------------------------------------------------
    resp = session.get("https://chatgpt.com/api/auth/session")
    _raise_for_status(resp, "GET /api/auth/session")
    access_token = resp.json().get("accessToken")
    if not access_token:
        raise RuntimeError(
            "accessToken not found in /api/auth/session response: "
            + resp.text[:300]
        )
    return access_token


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def register_and_get_token() -> dict:
    """
    Full end-to-end flow: register a new OpenAI account and return a dict
    with email, password, and access_token.
    """
    # ── Phase 1 session ──────────────────────────────────────────────────
    reg_session = _make_session()

    print("[*] Creating temporary email address…")
    email, tempmail_token = create_temp_email(reg_session)
    print(f"[*] Temporary email: {email}")

    password = _random_password()
    print("[*] Password generated.")

    # Attach the tempmail token so poll_for_otp can access it inside phase1
    reg_session._tempmail_token = tempmail_token  # noqa: SLF001

    print("[Phase 1] Starting registration…")
    reg_otp = phase1_register(reg_session, email, password)
    print("[Phase 1] Registration complete.")

    # Track OTPs used during registration so phase 2 can skip them.
    used_otps: set = {reg_otp}

    # ── Phase 2 session (fresh) ───────────────────────────────────────────
    login_session = _make_session()

    print("[Phase 2] Starting ChatGPT web-channel login…")
    access_token = phase2_get_token(
        login_session,
        email,
        password,
        tempmail_token,
        inbox_session=reg_session,
        used_otps=used_otps,
    )
    print("[Phase 2] Login complete.")

    credentials = {"email": email, "password": password, "access_token": access_token}
    out_file = "credentials.json"
    with open(out_file, "w", encoding="utf-8") as fh:
        json.dump(credentials, fh, indent=2)
    print(f"\n{'='*60}")
    print(f"Email       : {email}")
    print(f"Credentials saved to: {out_file}")
    print(f"{'='*60}\n")

    return credentials


if __name__ == "__main__":
    register_and_get_token()
    print("Credentials (email, password, access_token) saved to credentials.json")
