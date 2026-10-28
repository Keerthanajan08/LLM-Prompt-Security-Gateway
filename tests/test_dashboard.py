"""The optional React dashboard: served at /ui when built, with / pointing at it."""

from fastapi import FastAPI
from fastapi.testclient import TestClient

import app.main as main_module


def test_root_redirects_to_docs_without_a_build(client, monkeypatch, tmp_path):
    monkeypatch.setattr(main_module, "UI_DIR", tmp_path)
    response = client.get("/", follow_redirects=False)
    assert response.status_code in (302, 307)
    assert response.headers["location"] == "/docs"


def test_root_redirects_to_dashboard_when_built(client, monkeypatch, tmp_path):
    (tmp_path / "index.html").write_text("<!doctype html>", encoding="utf-8")
    monkeypatch.setattr(main_module, "UI_DIR", tmp_path)
    response = client.get("/", follow_redirects=False)
    assert response.headers["location"] == "/ui/"


def test_serves_a_build(tmp_path):
    (tmp_path / "index.html").write_text("<h1>dashboard</h1>", encoding="utf-8")
    (tmp_path / "assets").mkdir()
    (tmp_path / "assets" / "app.js").write_text("console.log(1)", encoding="utf-8")
    target = FastAPI()
    assert main_module.mount_ui(target, tmp_path) is True
    ui = TestClient(target)
    assert "dashboard" in ui.get("/ui/").text
    assert ui.get("/ui/assets/app.js").status_code == 200


def test_skips_mounting_without_a_build(tmp_path):
    target = FastAPI()
    assert main_module.mount_ui(target, tmp_path) is False
    assert TestClient(target).get("/ui/").status_code == 404
