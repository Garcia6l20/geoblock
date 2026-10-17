import pytest

from geoblock import download
from geoblock.errors import DataError

KW = {"connect_timeout": 3, "total_timeout": 10, "retries": 0, "retry_delay": 1, "max_bytes": 1024 * 1024,
      "sleep": lambda s: None}


def get(server, path, **over):
    return download.fetch_text(server.url(path), ca_file=server.cert, **{**KW, **over})


def test_success(server):
    assert "203.0.113" in get(server, "/xx-v4.zone")


def test_rejects_untrusted_certificate(server):
    with pytest.raises(DataError):
        download.fetch_text(server.url("/xx-v4.zone"), ca_file="", **KW)


def test_rejects_http_url():
    with pytest.raises(DataError, match="non-https"):
        download.fetch_text("http://127.0.0.1/x", ca_file="", **KW)


def test_http_error_not_retried_on_404(server):
    with pytest.raises(DataError):
        get(server, "/missing", retries=3)
    assert server.hits["/missing"] == 1


def test_retries_on_503_then_succeeds(server):
    server.routes["/flaky"] = lambda n: (503, "no") if n < 3 else (200, "203.0.113.0/24\n")
    assert get(server, "/flaky", retries=3) == "203.0.113.0/24\n"
    assert server.hits["/flaky"] == 3


def test_retries_are_bounded(server):
    server.routes["/down"] = (503, "no")
    with pytest.raises(DataError, match="2 attempt"):
        get(server, "/down", retries=1)
    assert server.hits["/down"] == 2


def test_size_limit_declared_and_streamed(server):
    server.routes["/big"] = (200, "x" * 5000)
    with pytest.raises(DataError, match="too large|size limit"):
        get(server, "/big", max_bytes=1000)


def test_size_limit_without_content_length(server):
    server.routes["/lie"] = (200, "x" * 5000, {"X-No-Length": "1"})  # close-delimited body
    with pytest.raises(DataError, match="size limit"):
        get(server, "/lie", max_bytes=1000)


def test_non_utf8_rejected(server):
    server.routes["/bin"] = (200, b"\xff\xfe\x00")
    with pytest.raises(DataError, match="UTF-8"):
        get(server, "/bin")


def test_redirect_to_http_refused(server):
    server.routes["/redir"] = (302, "", {"Location": "http://127.0.0.1:1/x"})
    with pytest.raises(DataError):
        get(server, "/redir")


def test_total_deadline(server):
    import time
    server.routes["/slow"] = (200, "a" * 10)
    with pytest.raises(DataError):
        get(server, "/slow", total_timeout=-1)
    assert time.monotonic() > 0


def test_connection_refused_is_data_error():
    with pytest.raises(DataError):
        download.fetch_text("https://127.0.0.1:1/x", ca_file="", **KW)
