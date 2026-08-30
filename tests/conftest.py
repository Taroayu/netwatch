# -*- coding: utf-8 -*-
"""
Fixtures partagées de la suite de tests NetWatch.

Chaque session de test s'exécute dans un environnement isolé :
  * dossier de données temporaire (aucun impact sur l'inventaire réel) ;
  * sniffer passif et sonde de ports désactivés (aucun accès réseau) ;
  * plage réseau minuscule et mot de passe fixe.

Ces variables sont posées AVANT le premier import de `config`/`app`, afin que
la configuration les prenne en compte.
"""

import os
import sys
import tempfile

import pytest

# --- Environnement de test (doit précéder l'import de l'application) ----------
_TMP = tempfile.mkdtemp(prefix="netwatch_pytest_")
os.environ.update(
    NETWATCH_DATA_DIR=_TMP,
    NETWATCH_ENABLE_SNIFFER="0",
    NETWATCH_ENABLE_PORT_PROBE="0",
    NETWATCH_ENABLE_REVERSE_DNS="0",
    NETWATCH_TARGET_NETWORK="192.168.123.0/30",
    NETWATCH_PASSWORD="TestPassw0rd!",
    NETWATCH_DEBUG="0",
)

# Racine du projet importable (le dossier parent de tests/).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture()
def app_module():
    """Charge le module applicatif une fois, moteur non démarré."""
    import app as A
    return A


@pytest.fixture()
def client(app_module):
    """Client de test Flask (non authentifié)."""
    app_module.app.config.update(TESTING=True)
    return app_module.app.test_client()


@pytest.fixture()
def auth_client(app_module, client):
    """Client authentifié : renvoie (client, csrf_token)."""
    resp = client.post("/api/auth/login", json={"password": "TestPassw0rd!"})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    csrf = resp.get_json()["csrf"]
    return client, csrf


@pytest.fixture()
def seeded(app_module):
    """Injecte un petit inventaire simulé et renvoie le module applicatif."""
    A = app_module
    A.MONITOR.gateway_ip = "192.168.1.1"
    A.MONITOR.local_ip = "192.168.1.50"
    A.MONITOR._process_scan_results([
        ("192.168.1.1", "3c:5a:b4:11:22:33"),
        ("192.168.1.20", "b8:27:eb:aa:bb:cc"),
        ("192.168.1.44", "a2:9f:10:00:11:22"),
    ])
    return A
