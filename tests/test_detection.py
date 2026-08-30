# -*- coding: utf-8 -*-
"""
Tests du moteur de détection : on injecte des paquets ARP synthétiques dans
les fonctions internes du moniteur (aucune trame réelle émise) et on vérifie
que les alertes attendues sont levées.
"""

import pytest

from core.database import Database
from core.resolver import AssetResolver
from core.monitor import NetworkMonitor, SCAPY_AVAILABLE

pytestmark = pytest.mark.skipif(not SCAPY_AVAILABLE, reason="Scapy requis")

if SCAPY_AVAILABLE:
    from scapy.all import ARP, Ether


def _engine():
    db = Database()
    # Isolation : les instances Database partagent le dossier de données de test ;
    # on repart d'un journal d'alertes vierge pour ce banc.
    db.alerts.clear()
    db._alert_cooldown.clear()
    mon = NetworkMonitor(db, AssetResolver())
    mon.gateway_ip = "192.168.5.1"
    mon.gateway_mac = "3c:5a:b4:aa:aa:aa"
    mon.local_ip = "192.168.5.50"
    mon.local_mac = "dc:a6:32:bb:bb:bb"
    mon._process_scan_results([("192.168.5.1", "3c:5a:b4:aa:aa:aa")])
    return db, mon


def _arp(op, psrc, hwsrc, pdst=None):
    return Ether(src=hwsrc) / ARP(op=op, psrc=psrc, hwsrc=hwsrc,
                                  pdst=pdst or psrc)


def _types(db):
    return {a["type"] for a in db.all_alerts()}


def test_gateway_impersonation_detected():
    db, mon = _engine()
    mon._record_binding("192.168.5.1", "3c:5a:b4:aa:aa:aa", source="sniff")
    mon._on_arp_packet(_arp(2, "192.168.5.1", "00:11:22:de:ad:01"))
    assert "gateway_impersonation" in _types(db)


def test_host_poisoning_detected():
    db, mon = _engine()
    mon._record_binding("192.168.5.60", "b8:27:eb:00:00:60", source="sniff")
    mon._on_arp_packet(_arp(2, "192.168.5.60", "00:11:22:de:ad:02"))
    assert "arp_poisoning" in _types(db)


def test_mac_multi_ip_detected():
    db, mon = _engine()
    intruder = "00:11:22:de:ad:03"
    mon._process_scan_results([
        ("192.168.5.81", intruder),
        ("192.168.5.82", intruder),
        ("192.168.5.83", intruder),
        ("192.168.5.84", intruder),
    ])
    assert "mac_multi_ip" in _types(db)


def test_arp_flood_detected():
    db, mon = _engine()
    import config
    for _ in range(config.GRATUITOUS_ARP_RATE + 5):
        mon._on_arp_packet(_arp(2, "192.168.5.90", "00:11:22:de:ad:04"))
    assert "arp_flood" in _types(db)


def test_legit_traffic_no_attack_alert():
    db, mon = _engine()
    mon._process_scan_results([("192.168.5.120", "f0:18:98:00:01:20")])
    mon._on_arp_packet(_arp(2, "192.168.5.120", "f0:18:98:00:01:20"))
    attack = {"gateway_impersonation", "arp_poisoning", "mac_multi_ip", "arp_flood"}
    assert not (attack & _types(db))
