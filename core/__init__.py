# -*- coding: utf-8 -*-
"""
NetWatch Enterprise — package `core`.

Regroupe la logique métier de la plateforme :

    - database.py : persistance thread-safe de l'inventaire et des alertes
    - resolver.py : identification fabricant (OUI) et typage intelligent d'actifs
    - monitor.py  : collecte ARP (active + passive) et moteur de détection
"""

from .database import Database          # noqa: F401
from .resolver import AssetResolver     # noqa: F401
from .monitor import NetworkMonitor     # noqa: F401
from .responder import ActiveResponder  # noqa: F401
from .auth import AuthManager           # noqa: F401
from .notifier import AlertNotifier     # noqa: F401
from .demo import DemoSimulator         # noqa: F401

__all__ = ["Database", "AssetResolver", "NetworkMonitor", "ActiveResponder",
           "AuthManager", "AlertNotifier", "DemoSimulator"]
