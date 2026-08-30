# -*- coding: utf-8 -*-
"""Tests unitaires de la couche de persistance (core/database.py)."""

import os

from core.database import Database, now_ts
import config


def _fresh():
    return Database()


def test_normalize_mac_formats():
    assert Database.normalize_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"
    assert Database.normalize_mac("aabb.ccdd.eeff") == "aa:bb:cc:dd:ee:ff"
    assert Database.normalize_mac("A:B:C:D:E:F") == "0a:0b:0c:0d:0e:0f"


def test_upsert_creates_then_updates():
    db = _fresh()
    rec, is_new = db.upsert_device("aa:bb:cc:00:00:01", ip="10.0.0.5")
    assert is_new and rec["ip"] == "10.0.0.5"
    rec2, is_new2 = db.upsert_device("aa:bb:cc:00:00:01", ip="10.0.0.6")
    assert not is_new2
    # L'historique d'IP consigne le changement d'adresse.
    assert any(h["ip"] == "10.0.0.6" for h in rec2["ip_history"])


def test_manual_label_not_overwritten_by_auto():
    db = _fresh()
    db.upsert_device("aa:bb:cc:00:00:02", ip="10.0.0.7")
    db.update_device_meta("aa:bb:cc:00:00:02", label="Poste RH")
    # Une mise à jour automatique ne doit pas écraser le libellé analyste.
    rec, _ = db.upsert_device("aa:bb:cc:00:00:02", label="auto-detecté")
    assert rec["label"] == "Poste RH"


def test_quarantine_state():
    db = _fresh()
    db.upsert_device("aa:bb:cc:00:00:03", ip="10.0.0.8")
    db.set_quarantine("aa:bb:cc:00:00:03", True, enforced=True)
    rec = db.get_device("aa:bb:cc:00:00:03")
    assert rec["quarantined"] and rec["quarantine_enforced"]
    db.set_quarantine("aa:bb:cc:00:00:03", False)
    assert not db.get_device("aa:bb:cc:00:00:03")["quarantined"]


def test_alert_cooldown_dedup():
    db = _fresh()
    first = db.add_alert("system", "T", "d", dedup_key="k-uniq-1")
    second = db.add_alert("system", "T", "d", dedup_key="k-uniq-1")
    assert first is not None and second is None  # absorbée par le cooldown


def test_dirty_flush_writes_file():
    db = _fresh()
    db.upsert_device("aa:bb:cc:00:00:04", ip="10.0.0.9")
    db.mark_devices_dirty()
    assert db.flush_devices() is True          # a écrit
    assert db.flush_devices() is False         # plus rien à écrire
    assert os.path.exists(config.KNOWN_DEVICES_FILE)


def test_metrics_shape():
    db = _fresh()
    db.upsert_device("aa:bb:cc:00:00:05", ip="10.0.0.10")
    m = db.compute_metrics()
    for key in ("total", "online", "posture", "threat_level", "distribution"):
        assert key in m
    assert 0 <= m["posture"] <= 100


def test_update_risk_scores_via_public_api():
    db = _fresh()
    db.upsert_device("aa:bb:cc:00:00:06", ip="10.0.0.11")
    db.update_risk_scores(lambda rec, alerts: 42, [])
    assert db.get_device("aa:bb:cc:00:00:06")["risk_score"] == 42
