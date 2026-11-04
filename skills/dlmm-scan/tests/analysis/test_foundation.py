import io
import json
import urllib.error

import pytest

from ha import env
from ha.solana import b58decode, is_on_curve, is_solana_address
from ha.transport import TransportError, redact, request_json

WALLET = "8bDutiwy7JgL9fmjdz6LNsVZ9P91fw58SqSicy5rt2v8"
TOKEN_ACCOUNT = "CR2wd49zdgdstjNjxNgz6ddZ5Nr87nJHpsAwhZJLiL4j"  # an ATA, therefore a PDA


def test_address_validation_and_curve():
    assert is_solana_address(WALLET)
    assert not is_solana_address("0xabc")
    assert not is_solana_address("l" * 40)  # 'l' is not base58
    assert len(b58decode(WALLET)) == 32
    assert is_on_curve(WALLET)
    assert not is_on_curve(TOKEN_ACCOUNT)


# ---- env ------------------------------------------------------------------
def test_env_reads_only_requested_name(tmp_path, monkeypatch):
    monkeypatch.delenv("HELIUS_API_KEY", raising=False)
    path = tmp_path / ".env"
    path.write_text("OTHER_SECRET=nope\nHELIUS_API_KEY='abc123'\n# comment\n")
    assert env.load_keys(["HELIUS_API_KEY"], path) == {"HELIUS_API_KEY": "abc123"}


def test_env_process_environment_wins(tmp_path, monkeypatch):
    monkeypatch.setenv("HELIUS_API_KEY", "from-env")
    path = tmp_path / ".env"
    path.write_text("HELIUS_API_KEY=from-file\n")
    assert env.load_keys(["HELIUS_API_KEY"], path)["HELIUS_API_KEY"] == "from-env"


def test_env_rejects_interpolation_and_duplicates(tmp_path, monkeypatch):
    monkeypatch.delenv("HELIUS_API_KEY", raising=False)
    path = tmp_path / ".env"
    path.write_text("HELIUS_API_KEY=$(curl evil)\n")
    with pytest.raises(env.EnvError):
        env.load_keys(["HELIUS_API_KEY"], path)
    path.write_text("HELIUS_API_KEY=a\nHELIUS_API_KEY=b\n")
    with pytest.raises(env.EnvError):
        env.load_keys(["HELIUS_API_KEY"], path)


def test_env_missing_file_or_key_returns_empty(tmp_path, monkeypatch):
    monkeypatch.delenv("HELIUS_API_KEY", raising=False)
    assert env.load_keys(["HELIUS_API_KEY"], tmp_path / "nope.env") == {}
    (tmp_path / ".env").write_text("X=1\n")
    assert env.load_keys(["HELIUS_API_KEY"], tmp_path / ".env") == {}


def test_env_rejects_bad_name():
    with pytest.raises(env.EnvError):
        env.load_keys(["bad name"])


# ---- transport ------------------------------------------------------------
class FakeResponse:
    def __init__(self, body: bytes, status: int = 200):
        self._body, self.status = body, status

    def read(self, n=-1):
        return self._body if n < 0 else self._body[:n]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeOpener:
    def __init__(self, *outcomes):
        self.outcomes, self.requests = list(outcomes), []

    def open(self, request, timeout=None):
        self.requests.append(request)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def http_error(code):
    return urllib.error.HTTPError("https://x", code, "err", {}, io.BytesIO(b"secret-key-body"))


def call(opener, **kw):
    return request_json("GET", "https://datapi.jup.ag/v1/x", allowed_hosts={"datapi.jup.ag"}, opener=opener, sleep=lambda s: None, **kw)


def test_transport_returns_json():
    assert call(FakeOpener(FakeResponse(b'{"a": 1}'))) == {"a": 1}


@pytest.mark.parametrize(
    "url",
    ["http://datapi.jup.ag/x", "https://evil.example/x", "https://user:pw@datapi.jup.ag/x", "https://datapi.jup.ag:8443/x"],
)
def test_transport_blocks_unlisted_targets(url):
    opener = FakeOpener()
    with pytest.raises(TransportError):
        request_json("GET", url, allowed_hosts={"datapi.jup.ag"}, opener=opener)
    assert opener.requests == []  # nothing was sent


def test_transport_retries_transient_then_succeeds():
    opener = FakeOpener(http_error(429), http_error(503), FakeResponse(b"[]"))
    assert call(opener) == []
    assert len(opener.requests) == 3


def test_transport_gives_up_and_maps_reasons():
    with pytest.raises(TransportError) as exc:
        call(FakeOpener(http_error(429), http_error(429), http_error(429)))
    assert exc.value.reason == "rate_limited" and exc.value.http_status == 429
    with pytest.raises(TransportError) as exc:
        call(FakeOpener(http_error(404)))
    assert exc.value.reason == "not_found"


def test_transport_redirect_oversize_and_bad_json():
    with pytest.raises(TransportError) as exc:
        call(FakeOpener(http_error(302)))
    assert exc.value.reason == "redirect_disallowed"
    with pytest.raises(TransportError) as exc:
        call(FakeOpener(FakeResponse(b"x" * 50)), max_bytes=10)
    assert exc.value.reason == "response_too_large"
    with pytest.raises(TransportError) as exc:
        call(FakeOpener(FakeResponse(b"<html>")))
    assert exc.value.reason == "invalid_json"


def test_transport_errors_never_leak_response_body_or_secret():
    with pytest.raises(TransportError) as exc:
        call(FakeOpener(http_error(500), http_error(500), http_error(500)), secrets=("secret-key-body",))
    assert "secret-key-body" not in str(exc.value) and "secret-key-body" not in repr(exc.value)
    assert redact("a SECRET b", ["SECRET"]) == "a <redacted> b"


def test_transport_maps_midread_http_exceptions_instead_of_crashing():
    import http.client

    with pytest.raises(TransportError) as exc:
        call(FakeOpener(http.client.IncompleteRead(b"par"), http.client.IncompleteRead(b"par"), http.client.IncompleteRead(b"par")))
    assert exc.value.reason == "network_error"
    assert call(FakeOpener(http.client.IncompleteRead(b"par"), FakeResponse(b"[1]"))) == [1]


def test_transport_has_an_overall_deadline():
    ticks = iter([0.0, 0.0, 100.0, 200.0, 300.0])
    opener = FakeOpener(http_error(503), http_error(503), http_error(503))
    with pytest.raises(TransportError) as exc:
        request_json("GET", "https://datapi.jup.ag/v1/x", allowed_hosts={"datapi.jup.ag"}, opener=opener, sleep=lambda s: None, deadline_s=50, clock=lambda: next(ticks))
    assert exc.value.reason == "deadline_exceeded" and len(opener.requests) == 1


def test_transport_posts_json_body():
    opener = FakeOpener(FakeResponse(b"{}"))
    request_json("POST", "https://datapi.jup.ag/v1/x", allowed_hosts={"datapi.jup.ag"}, body={"k": 1}, opener=opener)
    sent = opener.requests[0]
    assert json.loads(sent.data) == {"k": 1} and sent.get_header("Content-type") == "application/json"
