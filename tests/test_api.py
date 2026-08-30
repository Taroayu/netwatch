# -*- coding: utf-8 -*-
"""Tests des routes de l'API (état, actions, export)."""


def test_state_payload_shape(seeded, auth_client):
    client, _ = auth_client
    data = client.get("/api/state").get_json()
    for key in ("devices", "alerts", "metrics", "network", "responder",
                "asset_types", "app"):
        assert key in data
    assert isinstance(data["devices"], list) and len(data["devices"]) >= 3
    dev = data["devices"][0]
    for key in ("mac", "ip", "display_name", "type_label", "risk_score"):
        assert key in dev


def test_device_update_requires_csrf(seeded, auth_client):
    client, csrf = auth_client
    mac = "b8:27:eb:aa:bb:cc"
    # Sans CSRF -> 403
    assert client.post(f"/api/device/{mac}", json={"label": "X"}).status_code == 403
    # Avec CSRF -> 200 et libellé appliqué
    r = client.post(f"/api/device/{mac}", json={"label": "Serveur test"},
                    headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200 and r.get_json()["device"]["label"] == "Serveur test"


def test_quarantine_gateway_refused(seeded, auth_client):
    client, csrf = auth_client
    # La passerelle ne peut jamais être isolée (garde-fou serveur).
    r = client.post("/api/device/3c:5a:b4:11:22:33/quarantine",
                    headers={"X-CSRF-Token": csrf})
    assert r.status_code == 400
    assert "passerelle" in r.get_json()["error"].lower()


def test_ack_alert_flow(seeded, auth_client):
    client, csrf = auth_client
    alerts = client.get("/api/state").get_json()["alerts"]
    if not alerts:
        return  # rien à acquitter dans ce contexte
    aid = alerts[0]["id"]
    r = client.post(f"/api/alerts/{aid}/ack", headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200 and r.get_json()["ok"] is True


def test_export_csv_and_json(seeded, auth_client):
    client, _ = auth_client
    csv_resp = client.get("/api/export/csv")
    assert csv_resp.status_code == 200
    assert "text/csv" in csv_resp.headers["Content-Type"]
    json_resp = client.get("/api/export/json")
    assert json_resp.status_code == 200
    assert "devices" in json_resp.get_json()


def test_spa_shell_public(client):
    # La coquille HTML reste servie sans authentification (elle n'affiche que
    # l'écran de connexion tant que la session n'est pas établie).
    assert client.get("/").status_code == 200
