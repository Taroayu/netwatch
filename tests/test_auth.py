# -*- coding: utf-8 -*-
"""Tests de l'authentification et de la protection CSRF."""


def _reset_throttle(app_module):
    with app_module._login_lock:
        app_module._login_state.clear()


def test_state_requires_auth(app_module, client):
    _reset_throttle(app_module)
    client.post("/api/auth/logout", json={})
    assert client.get("/api/state").status_code == 401


def test_status_is_public(client):
    r = client.get("/api/auth/status")
    assert r.status_code == 200
    assert r.get_json()["auth_enabled"] is True


def test_wrong_password_rejected(app_module, client):
    _reset_throttle(app_module)
    r = client.post("/api/auth/login", json={"password": "mauvais"})
    assert r.status_code == 401
    _reset_throttle(app_module)


def test_login_then_access(app_module, client):
    _reset_throttle(app_module)
    r = client.post("/api/auth/login", json={"password": "TestPassw0rd!"})
    assert r.status_code == 200 and r.get_json()["csrf"]
    assert client.get("/api/state").status_code == 200


def test_csrf_required_on_mutation(app_module, client):
    _reset_throttle(app_module)
    login = client.post("/api/auth/login", json={"password": "TestPassw0rd!"})
    csrf = login.get_json()["csrf"]
    # Sans jeton -> 403
    assert client.post("/api/control/scan").status_code == 403
    # Avec jeton -> 200
    ok = client.post("/api/control/scan", headers={"X-CSRF-Token": csrf})
    assert ok.status_code == 200


def test_security_headers_present(client):
    r = client.get("/api/auth/status")
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("X-Frame-Options") == "DENY"
    assert "Content-Security-Policy" in r.headers


def test_bruteforce_lockout(app_module):
    _reset_throttle(app_module)
    c = app_module.app.test_client()
    # 5 échecs déclenchent le verrouillage (429) au 6e essai.
    for _ in range(5):
        c.post("/api/auth/login", json={"password": "x"})
    locked = c.post("/api/auth/login", json={"password": "x"})
    assert locked.status_code == 429
    _reset_throttle(app_module)
