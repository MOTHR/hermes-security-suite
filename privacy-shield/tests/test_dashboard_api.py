"""Tests for the Privacy-Shield Desktop-Controls backend.

Uses FastAPI's TestClient against the plugin API router, scoped to a
throwaway HERMES_HOME so config writes never touch the real ~/.hermes state.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from privacy_shield import __version__


def _make_client(tmp_path: Path) -> TestClient:
    """Mount the plugin router in a throwaway FastAPI app and HERMES_HOME."""
    # router imports load_config lazily; point it at a temp home.
    home = tmp_path / "hermes_home"
    home.mkdir(parents=True)
    os.environ["HERMES_HOME"] = str(home)
    # Load the router inside this fixture so it sees the patched home.
    from privacy_shield.dashboard.plugin_api import router

    app = FastAPI()
    app.include_router(router, prefix="/api/plugins/privacy-shield")
    return TestClient(app)


@pytest.fixture
def client(tmp_path):
    yield _make_client(tmp_path)


def test_get_config_returns_schema_and_values(client):
    resp = client.get("/api/plugins/privacy-shield/config")
    assert resp.status_code == 200
    data = resp.json()
    assert data["version"] == __version__
    assert "fields" in data
    assert "values" in data
    assert data["fields"]["mode"]["choices"] == [
        "off",
        "audit",
        "limited",
        "strict",
        "paranoid",
    ]
    assert data["values"]["mode"] in data["fields"]["mode"]["choices"]


def test_post_config_validates_unknown_mode(client):
    resp = client.post(
        "/api/plugins/privacy-shield/config",
        json={"updates": {"mode": "invalid"}},
    )
    assert resp.status_code == 400


def test_post_config_persists_and_get_reflects(client, tmp_path):
    resp = client.post(
        "/api/plugins/privacy-shield/config",
        json={"updates": {"mode": "audit", "confidence_threshold": 0.95}},
    )
    assert resp.status_code == 200
    assert resp.json()["ok"] is True

    config_yaml = tmp_path / "hermes_home" / "config.yaml"
    assert config_yaml.exists()
    text = config_yaml.read_text()
    assert "privacy-shield:" in text
    assert "mode: audit" in text
    assert "confidence_threshold: 0.95" in text

    resp = client.get("/api/plugins/privacy-shield/config")
    assert resp.status_code == 200
    assert resp.json()["overrides"]["mode"] == "audit"


def test_get_status(client):
    resp = client.get("/api/plugins/privacy-shield/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["version"] == __version__
    assert data["mode"] in {"off", "audit", "limited", "strict", "paranoid"}
    assert "enabled" in data


def test_restore_test_roundtrips_synthetic_pii(client):
    resp = client.post(
        "/api/plugins/privacy-shield/restore-test",
        json={"text": "email test@example.com"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data["matches"] > 0
    assert data["restored_count"] == data["matches"]
    assert data["restore_works"] is True
    assert data["masked"] != data["original"]
    assert data["restored"] == data["original"]


def test_restore_test_no_pii(client):
    resp = client.post(
        "/api/plugins/privacy-shield/restore-test",
        json={"text": "This sentence contains no detectable PII."},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data.get("matches", 0) == 0
    assert data.get("restore_works") is False


def test_frontend_file_is_readable():
    """Sanity check that the bundled desktop plugin file exists and is valid UTF-8."""
    repo = Path(__file__).resolve().parent.parent
    js_path = repo / "desktop" / "plugin.js"
    assert js_path.exists()
    text = js_path.read_text(encoding="utf-8")
    assert text.strip().endswith("};")
    assert "ctx.register" in text
    assert "ctx.rest" in text
