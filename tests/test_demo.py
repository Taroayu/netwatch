# -*- coding: utf-8 -*-
"""Tests du mode démonstration (peuplement simulé, sans réseau)."""

from core.database import Database
from core.resolver import AssetResolver
from core.monitor import NetworkMonitor
from core.demo import DemoSimulator


def test_demo_seed_populates_inventory_and_alerts():
    db = Database()
    db.alerts.clear()
    db.devices.clear()
    mon = NetworkMonitor(db, AssetResolver())
    sim = DemoSimulator(db, AssetResolver(), mon)
    sim.seed()

    devices = db.all_devices()
    assert len(devices) >= 8
    # Contexte réseau « démo » appliqué au moniteur.
    assert mon.demo is True
    assert mon.network_info()["demo"] is True
    # Une passerelle et une sonde sont marquées de confiance.
    assert any(d["is_gateway"] for d in devices)
    # Les scénarios d'attaque de démonstration sont présents.
    types = {a["type"] for a in db.all_alerts()}
    assert "gateway_impersonation" in types
    # Typage cohérent : plusieurs catégories distinctes.
    assert len({d["asset_type"] for d in devices}) >= 5
