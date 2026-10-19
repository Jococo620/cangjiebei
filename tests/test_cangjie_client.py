"""cangjie_engine_client 仓颉 DAG 引擎客户端单元测试。"""

import pytest

from nexus.adapters import cangjie_engine_client as cj


def test_engine_constants():
    assert cj.ENGINE_PORT == 2270
    assert cj.BASE_URL == "http://127.0.0.1:2270"


def test_start_reuses_cached_state():
    client = cj.CangjieEngineClient()
    client.available = False
    assert client.start() is False


def test_start_when_already_up(monkeypatch):
    client = cj.CangjieEngineClient()
    monkeypatch.setattr(client, "_already_up", lambda: True)
    assert client.start() is True
    assert client.available is True


def test_start_when_exe_missing(monkeypatch):
    client = cj.CangjieEngineClient()
    monkeypatch.setattr(client, "_already_up", lambda: False)
    monkeypatch.setattr(cj, "_EXE", "/nonexistent/cangjie_engine.exe")
    assert client.start() is False
    assert client.available is False


def test_plan_dag_fallback_when_unavailable(monkeypatch):
    client = cj.CangjieEngineClient()
    monkeypatch.setattr(client, "start", lambda: False)
    out = client.plan_dag("A -> B")
    assert out == {"available": False, "source": "python_fallback"}


def test_health_unavailable(monkeypatch):
    client = cj.CangjieEngineClient()
    monkeypatch.setattr(client, "start", lambda: False)
    out = client.health()
    assert out["available"] is False


def test_plan_dag_parses_levels_and_costs(monkeypatch):
    client = cj.CangjieEngineClient()
    monkeypatch.setattr(client, "start", lambda: True)
    raw = "OK\nLEVEL|A|B\nLEVEL|C\nCOST|A|1\nCOST|B|2\n"

    class _FakeResp:
        text = raw

        def raise_for_status(self):
            return None

    monkeypatch.setattr(cj.requests, "post", lambda *a, **k: _FakeResp())
    out = client.plan_dag("A -> B")
    assert out["available"] is True
    assert out["source"] == "cangjie"
    assert out["levels"] == [["A", "B"], ["C"]]
    assert out["costs"] == {"A": 1, "B": 2}
    assert out["ok"] is True
