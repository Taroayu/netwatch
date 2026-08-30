# -*- coding: utf-8 -*-
"""
================================================================================
 NetWatch Enterprise — core/demo.py
--------------------------------------------------------------------------------
 Mode DÉMONSTRATION.

 Peuple la plateforme avec un inventaire, des alertes et une tendance
 entièrement SIMULÉS, puis anime légèrement l'état dans le temps — le tout
 SANS aucun accès réseau, sans Scapy, sans Npcap et sans privilèges.

 Objectif : permettre à quiconque de découvrir l'interface en 30 secondes
 (`python app.py --demo`) avant même d'installer la capture réelle. C'est le
 principal levier d'adoption d'un projet open source.

 ⚠ Le mode démo écrit dans un dossier de données dédié (config.DATA_DIR pointe
   sur `data_demo/`) : il n'écrase jamais un inventaire de production.
================================================================================
"""

import random
import threading

from .database import now_ts, iso

# Parc simulé : (ip, mac, hostname, libellé, ports ouverts, passerelle?, sonde?)
# MAC choisies avec de vrais préfixes OUI pour un typage réaliste.
_FLEET = [
    ("192.168.1.1",  "3c:5a:b4:2f:11:01", None,          "Box Internet",        [53, 80, 443], True,  False),
    ("192.168.1.2",  "5c:b1:3e:a0:22:02", None,          "Point d'accès Wi-Fi", [80, 443],     False, False),
    ("192.168.1.10", "00:11:32:8c:33:03", "nas-01",      "NAS Synologie",       [22, 5000, 5001], False, False),
    ("192.168.1.15", "3c:97:0e:d1:44:04", "DESKTOP-K4P", "Poste comptabilité",  [139, 445, 3389], False, False),
    ("192.168.1.20", "00:1e:8f:b2:55:05", "BRW-imprim",  "Imprimante étage 2",  [515, 631, 9100], False, False),
    ("192.168.1.24", "bc:fc:e7:08:e6:5a", None,          "Poste analyste (sonde)", [], False, True),
    ("192.168.1.30", "c0:56:e3:77:66:06", "cam-hall",    "Caméra hall",         [554, 80],     False, False),
    ("192.168.1.40", "e4:ae:e4:89:4d:59", None,          "Prise connectée",     [80],          False, False),
    ("192.168.1.55", "a2:9f:10:3c:77:07", None,          "Smartphone (invité)", [],            False, False),
    ("192.168.1.60", "00:50:56:9a:88:08", "vm-lab",      "VM de test",          [22],          False, False),
]


class DemoSimulator:
    """Alimente et anime un état simulé pour le mode démonstration."""

    def __init__(self, db, resolver, monitor):
        self.db = db
        self.resolver = resolver
        self.monitor = monitor
        self._stop = threading.Event()
        self._thread = None

    # -------------------------------------------------------------- CONTEXTE
    def _apply_network_context(self):
        m = self.monitor
        m.demo = True
        m.iface = "demo0"
        m.local_ip = "192.168.1.24"
        m.local_mac = "bc:fc:e7:08:e6:5a"
        m.gateway_ip = "192.168.1.1"
        m.gateway_mac = "3c:5a:b4:2f:11:01"
        m.cidr = "192.168.1.0/24"
        m.target_hosts = [f"192.168.1.{i}" for i in range(1, 255)]
        m.running = True
        m.sniffer_active = True
        m.last_error = None

    # ------------------------------------------------------------- PEUPLEMENT
    def seed(self):
        self._apply_network_context()
        base = now_ts()

        for idx, (ip, mac, host, label, ports, is_gw, is_local) in enumerate(_FLEET):
            classification = self.resolver.classify(
                mac, ip=ip, hostname=host, open_ports=ports,
                is_gateway=is_gw, is_local_host=is_local,
            )
            record, _ = self.db.upsert_device(mac, ip=ip, **classification)
            if record is None:
                continue
            record["hostname"] = host
            record["label"] = label
            record["online"] = True
            record["first_seen"] = base - 86400 * (idx + 1)     # ancienneté variée
            record["last_seen"] = base - random.randint(1, 40)
            record["seen_count"] = random.randint(20, 400)
            record["_enriched_at"] = base
            if is_gw or is_local:
                record["trusted"] = True

        # --- Quelques événements de sécurité représentatifs ------------------
        self.db.add_alert(
            "gateway_impersonation",
            "USURPATION DE PASSERELLE — 192.168.1.1",
            "L'adresse MAC de la passerelle est passée de 3c:5a:b4:2f:11:01 à "
            "de:ad:be:ef:00:01 en 4 s. Signature d'une attaque Man-in-the-Middle.",
            ip="192.168.1.1", mac="de:ad:be:ef:00:01",
            dedup_key="demo-gw", severity="critical",
            evidence={"previous_mac": "3c:5a:b4:2f:11:01", "current_mac": "de:ad:be:ef:00:01"},
        )
        self.db.add_alert(
            "mac_randomized", "Adresse MAC aléatoire sur 192.168.1.55",
            "Terminal mobile en mode anti-tracking (bit localement administré).",
            ip="192.168.1.55", mac="a2:9f:10:3c:77:07", dedup_key="demo-rand",
        )
        self.db.add_alert(
            "new_device", "Nouvel actif détecté : 192.168.1.60",
            "MAC 00:50:56:9a:88:08 — fabricant VMware, Inc. Actif absent de "
            "l'inventaire de référence.",
            ip="192.168.1.60", mac="00:50:56:9a:88:08", dedup_key="demo-new",
        )

        # --- Tendance initiale -----------------------------------------------
        for _ in range(30):
            self.db.push_timeline_point()

        self.db.audit("DEMO", "Mode démonstration initialisé (données simulées)")

    # -------------------------------------------------------------- ANIMATION
    def start(self):
        self.seed()
        self._thread = threading.Thread(target=self._loop, name="nw-demo", daemon=True)
        self._thread.start()
        return True

    def stop(self):
        self._stop.set()
        return True

    def _loop(self):
        """Anime discrètement l'état pour que le temps réel paraisse vivant."""
        tick = 0
        while not self._stop.wait(4):
            tick += 1
            try:
                macs = [d["mac"] for d in self.db.all_devices()
                        if not d.get("is_gateway") and not d.get("is_local_host")]
                # Bascule aléatoire d'un actif en ligne / hors ligne.
                if macs:
                    rec = self.db.get_device(random.choice(macs))
                    if rec:
                        rec["online"] = not rec.get("online", True)
                        if rec["online"]:
                            rec["last_seen"] = now_ts()

                # De temps en temps, un flood ARP transitoire (démonstration).
                if tick % 6 == 0:
                    self.db.add_alert(
                        "arp_flood", "Débit ARP anormal depuis 192.168.1.55",
                        "Pic de réponses ARP gratuites — comportement typique d'un "
                        "outil d'empoisonnement automatisé.",
                        ip="192.168.1.55", mac="a2:9f:10:3c:77:07",
                        dedup_key=f"demo-flood-{tick}",
                    )

                self.db.push_timeline_point()
            except Exception:
                pass
