"""Bounded HTTPS download: timeouts, size cap, total deadline, bounded retries."""

import socket
import ssl
import time
import urllib.error
import urllib.request

from . import __version__, log
from .errors import DataError

MAX_REDIRECTS = 3


class _HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    max_redirections = MAX_REDIRECTS

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.lower().startswith("https://"):
            raise urllib.error.URLError("refusing redirect to non-https URL")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _context(ca_file: str) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=ca_file or None)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def _fetch_once(url: str, ctx, connect_timeout: int, deadline: float, max_bytes: int) -> bytes:
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx), _HttpsOnlyRedirect()
    )
    req = urllib.request.Request(url, headers={  # noqa: S310 - scheme enforced to https by fetch_text
        "User-Agent": f"geoblock/{__version__}",
        "Accept": "text/plain",
        "Accept-Encoding": "identity",
    })
    with opener.open(req, timeout=connect_timeout) as resp:
        if resp.status != 200:
            raise DataError(f"unexpected HTTP status {resp.status}")
        declared = resp.headers.get("Content-Length")
        if declared is not None and declared.isdigit() and int(declared) > max_bytes:
            raise DataError(f"response too large ({declared} bytes, limit {max_bytes})")
        chunks = []
        total = 0
        while True:
            if time.monotonic() > deadline:
                raise DataError("download exceeded the total time limit")
            chunk = resp.read(min(65536, max_bytes + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise DataError(f"response exceeded the size limit of {max_bytes} bytes")
            chunks.append(chunk)
    return b"".join(chunks)


def _retryable(exc: Exception) -> bool:
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code == 429 or exc.code >= 500
    if isinstance(exc, ssl.SSLCertVerificationError):
        return False
    if isinstance(exc, urllib.error.URLError):
        return not isinstance(exc.reason, ssl.SSLCertVerificationError)
    return isinstance(exc, (socket.timeout, TimeoutError, ConnectionError, ssl.SSLError))


def fetch_text(url: str, *, ca_file: str, connect_timeout: int, total_timeout: int,
               retries: int, retry_delay: int, max_bytes: int, sleep=time.sleep) -> str:
    """Download url as strict UTF-8 text. Never raises anything but DataError."""
    if not url.lower().startswith("https://"):
        raise DataError("refusing non-https URL")
    deadline = time.monotonic() + total_timeout
    try:
        ctx = _context(ca_file)
    except (OSError, ssl.SSLError) as exc:
        raise DataError(f"can not load CA file: {exc}") from None
    last = "unknown error"
    for attempt in range(retries + 1):
        try:
            raw = _fetch_once(url, ctx, connect_timeout, deadline, max_bytes)
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError:
                raise DataError("response is not valid UTF-8 text") from None
        except DataError:
            raise
        except Exception as exc:  # noqa: BLE001 - classified below
            last = f"{type(exc).__name__}: {getattr(exc, 'reason', exc)}"
            if not _retryable(exc):
                raise DataError(f"download failed: {last}") from None
        if attempt < retries:
            delay = min(retry_delay * (2 ** attempt), 120)
            if time.monotonic() + delay > deadline:
                break
            log.warning(f"download attempt {attempt + 1} failed ({last}); retrying in {delay}s")
            sleep(delay)
    raise DataError(f"download failed after {retries + 1} attempt(s): {last}")
