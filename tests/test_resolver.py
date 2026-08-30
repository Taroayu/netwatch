# -*- coding: utf-8 -*-
"""Tests du moteur d'identification/typage (core/resolver.py)."""

import warnings

import core.resolver as R
from core.resolver import AssetResolver


def test_virtual_oui_detected():
    res = AssetResolver()
    ident = res.identify("00:50:56:12:34:56")   # VMware
    assert ident.is_virtual
    assert "vmware" in ident.vendor.lower()


def test_randomized_mac_flagged():
    res = AssetResolver()
    # 2e caractère hexa impair sur le 1er octet => bit U/L (localement administré)
    ident = res.identify("a2:9f:10:00:11:22")
    assert ident.is_randomized


def test_classify_gateway_and_confidence():
    res = AssetResolver()
    out = res.classify("3c:5a:b4:11:22:33", ip="192.168.1.1",
                       hostname=None, open_ports=[], is_gateway=True)
    assert out["asset_type"] == "gateway"
    assert 0 <= out["type_confidence"] <= 99
    assert isinstance(out["type_evidence"], list) and out["type_evidence"]


def test_classify_hostname_signal():
    res = AssetResolver()
    out = res.classify("00:11:32:ab:cd:ef", ip="192.168.1.80",
                       hostname="diskstation", open_ports=[])
    assert out["asset_type"] == "server"


def test_await_if_needed_consumes_coroutine_without_warning():
    async def fake():
        return "Vendeur Async"
    with warnings.catch_warnings():
        warnings.simplefilter("error", RuntimeWarning)  # 'never awaited' -> échec
        assert R._await_if_needed(fake()) == "Vendeur Async"
        assert R._await_if_needed("déjà sync") == "déjà sync"


def test_risk_score_bounds():
    res = AssetResolver()
    device = {"mac": "aa:bb:cc:dd:ee:ff", "trusted": False,
              "flags": ["OUI_INCONNU"], "is_randomized": True,
              "criticality": "high", "hostname": None}
    score = res.risk_score(device, [])
    assert 0 <= score <= 100
