"""Secret redaction for harness logs, adapter errors, and scoreboard fields.

Ensures OXYLABS passwords, proxy user:pass URLs, and FIRECRAWL_API_KEY
values never land in normalized artifacts or operator output
(VAL-BENCH-013, 015, 036).
"""

from __future__ import annotations

import os
import re
from typing import Iterable, List, Optional, Sequence

REDACTED = "[REDACTED]"

# user:pass@host patterns in proxy URLs (http/https/socks5).
_CRED_URL_RE = re.compile(
    r"(?i)\b((?:https?|socks5h?)://)([^/\s:@]+):([^/@\s]+)@"
)

# Authorization: Bearer … and Basic …
_AUTH_HEADER_RE = re.compile(
    r"(?i)(authorization\s*[:=]\s*)(bearer\s+)?([^\s\"']+)"
)

# Common env dumps / CLI echoes.
_ENV_KESECRET_RE = re.compile(
    r"(?i)\b(FIRECRAWL_API_KEY|OXYLABS_PROXY_PASS|OXYLABS_PASSWORD|"
    r"BASECRAWL_HTTPS_PROXY|BASECRAWL_HTTP_PROXY|HTTPS_PROXY|HTTP_PROXY|"
    r"ALL_PROXY|PROXY_PASSWORD|PROXY_PASS)\s*[=:]\s*([^\s\"']+)"
)


def collect_secret_fragments(
    extra: Optional[Sequence[str]] = None,
    *,
    env: Optional[dict] = None,
) -> List[str]:
    """Gather non-empty secret strings from process env (never return keys alone)."""
    environ = env if env is not None else os.environ
    keys = (
        "FIRECRAWL_API_KEY",
        "OXYLABS_PROXY_PASS",
        "OXYLABS_PASSWORD",
        "PROXY_PASSWORD",
        "PROXY_PASS",
        "BASECRAWL_HTTP_PROXY",
        "BASECRAWL_HTTPS_PROXY",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "ALL_PROXY",
        "OXYLABS_PROXY_USER",
    )
    frags: List[str] = []
    for key in keys:
        val = environ.get(key)
        if not val:
            continue
        frags.append(val)
        # Also strip user:pass embedded in proxy URLs.
        if "@" in val and "://" in val:
            try:
                # ...://user:pass@host...
                after_scheme = val.split("://", 1)[1]
                if "@" in after_scheme and ":" in after_scheme.split("@", 1)[0]:
                    userinfo = after_scheme.split("@", 1)[0]
                    user, password = userinfo.split(":", 1)
                    if password:
                        frags.append(password)
                    if user:
                        frags.append(user)
            except (IndexError, ValueError):
                pass
    if extra:
        for item in extra:
            if item:
                frags.append(str(item))
    # Longest first so partial overlaps redact fully.
    uniq = sorted({f for f in frags if f and len(f) >= 4}, key=len, reverse=True)
    return uniq


def redact_text(text: str, secrets: Optional[Iterable[str]] = None) -> str:
    """Return ``text`` with known secrets and credential URL userinfo redacted."""
    if text is None:
        return ""
    out = str(text)
    secret_list = list(secrets) if secrets is not None else collect_secret_fragments()
    for secret in secret_list:
        if secret and secret in out:
            out = out.replace(secret, REDACTED)
    out = _CRED_URL_RE.sub(rf"\1{REDACTED}:{REDACTED}@", out)
    out = _AUTH_HEADER_RE.sub(rf"\1\2{REDACTED}", out)
    out = _ENV_KESECRET_RE.sub(rf"\1={REDACTED}", out)
    return out


def looks_like_secret_leak(text: str, secrets: Optional[Iterable[str]] = None) -> bool:
    """True if any full secret value still appears in ``text``."""
    if not text:
        return False
    secret_list = list(secrets) if secrets is not None else collect_secret_fragments()
    for secret in secret_list:
        if secret and secret in text:
            return True
    if _CRED_URL_RE.search(text):
        return True
    return False
