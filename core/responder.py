# -*- coding: utf-8 -*-
"""
================================================================================
 NetWatch Enterprise — core/responder.py
--------------------------------------------------------------------------------
 Module de RÉPONSE ACTIVE — mise en quarantaine d'un actif.

 ┌────────────────────────────────────────────────────────────────────────┐
 │  PÉRIMÈTRE ET ÉTHIQUE                                                     │
 │                                                                          │
 │  Ce module coupe le trafic entre LE POSTE DE SUPERVISION et un actif,    │
 │  en posant une règle sur LE PARE-FEU LOCAL de la machine qui exécute     │
 │  NetWatch (Windows Defender Firewall via `netsh`, ou Netfilter via       │
 │  `iptables` sous Linux). Autrement dit : NetWatch ne configure QUE sa    │
 │  propre machine.                                                         │
 │                                                                          │
 │  Il ne fait PAS — et ne fera pas — d'isolation « à l'échelle du réseau » │
 │  par injection de réponses ARP forgées : cette technique EST l'attaque   │
 │  ARP spoofing (MITRE T1557.002) que NetWatch a précisément pour rôle de  │
 │  détecter, et un tel bouton permettrait de couper n'importe quel appareil│
 │  d'un tiers. La véritable isolation « réseau » se fait au point          │
 │  d'application légitime : filtrage MAC ou coupure de port sur le switch  │
 │  ou la passerelle (l'interface le rappelle à l'analyste).                │
 └────────────────────────────────────────────────────────────────────────┘

 Toutes les actions sont :
   * RÉVERSIBLES  — chaque blocage peut être levé d'un clic ;
   * TRAÇABLES    — journalisées dans l'audit ;
   * PROTÉGÉES    — la passerelle, l'hôte local et les actifs approuvés
                    (liste blanche) ne peuvent jamais être coupés, ce qui
                    évite de se couper soi-même d'Internet par mégarde.
================================================================================
"""

import ipaddress
import os
import subprocess
import threading

import config


def _valid_ip(ip: str) -> bool:
    """Valide strictement une adresse IPv4 (barrière anti-injection shell)."""
    try:
        ipaddress.IPv4Address(ip)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


class ActiveResponder:
    """
    Applique et lève des mesures d'isolation via le pare-feu local.

    Aucune commande n'est passée par un shell : `subprocess.run` reçoit une
    liste d'arguments et l'IP est validée en amont — il n'existe donc aucune
    surface d'injection, même si une IP venait d'une source non fiable.
    """

    # Préfixe commun à toutes les règles créées : facilite l'audit et le
    # nettoyage manuel (`netsh advfirewall firewall show rule name=all`).
    RULE_PREFIX = "NetWatch-Quarantine"

    def __init__(self, db, monitor):
        self.db = db
        self.monitor = monitor
        self._lock = threading.RLock()
        self.platform = "windows" if os.name == "nt" else "linux"
        # Journalise l'indisponibilité éventuelle du back-end pare-feu.
        self.backend_ok, self.backend_note = self._probe_backend()

    # ------------------------------------------------------------- DIAGNOSTIC
    def _probe_backend(self):
        """Vérifie que l'outil de pare-feu attendu est présent."""
        tool = "netsh" if self.platform == "windows" else "iptables"
        try:
            from shutil import which
            if which(tool):
                return True, f"Back-end pare-feu : {tool}"
            return False, (f"« {tool} » introuvable : la quarantaine réseau "
                           f"sera enregistrée mais non appliquée.")
        except Exception as exc:                             # pragma: no cover
            return False, f"Back-end pare-feu indisponible : {exc}"

    def status(self) -> dict:
        """État exposé au dashboard (bandeau système)."""
        return {
            "enabled": config.ENABLE_ACTIVE_RESPONSE,
            "backend_ok": self.backend_ok,
            "note": self.backend_note,
            "platform": self.platform,
        }

    # --------------------------------------------------------------- GARDES
    def _guard(self, device: dict):
        """
        Empêche toute action dangereuse ou absurde.

        Retourne un message d'erreur si l'action doit être refusée, sinon None.
        """
        if not config.ENABLE_ACTIVE_RESPONSE:
            return "La réponse active est désactivée dans la configuration."

        ip = device.get("ip")
        if not ip or not _valid_ip(ip):
            return "Adresse IP invalide ou inconnue : isolation impossible."

        # On ne se coupe jamais de la passerelle (perte d'Internet garantie)…
        if device.get("is_gateway") or ip == self.monitor.gateway_ip:
            return ("Refus : cet actif est la passerelle par défaut. "
                    "L'isoler couperait tout votre trafic sortant.")
        # …ni de soi-même…
        if device.get("is_local_host") or ip == self.monitor.local_ip:
            return "Refus : il s'agit du poste de supervision lui-même."
        # …ni d'un actif que l'analyste a explicitement approuvé.
        if device.get("trusted"):
            return ("Refus : cet actif est approuvé (liste blanche). "
                    "Retirez d'abord son approbation pour pouvoir l'isoler.")
        return None

    # ------------------------------------------------------- EXÉCUTION SHELL
    def _run(self, args) -> tuple:
        """Exécute une commande système sans shell. Retourne (ok, sortie)."""
        try:
            completed = subprocess.run(
                args,
                capture_output=True, text=True,
                timeout=8,
                creationflags=(subprocess.CREATE_NO_WINDOW
                               if self.platform == "windows" else 0),
            )
            output = (completed.stdout + completed.stderr).strip()
            return completed.returncode == 0, output
        except FileNotFoundError:
            return False, "Outil de pare-feu introuvable."
        except subprocess.TimeoutExpired:
            return False, "Délai dépassé lors de l'application de la règle."
        except Exception as exc:                             # pragma: no cover
            return False, str(exc)

    def _rule_names(self, ip: str):
        """Noms des règles entrante/sortante associées à une IP (Windows)."""
        base = f"{self.RULE_PREFIX}-{ip}"
        return f"{base}-IN", f"{base}-OUT"

    # ---------------------------------------------------------- APPLICATION
    def _apply_block(self, ip: str) -> tuple:
        """Pose les règles de blocage bidirectionnel pour une IP."""
        if self.platform == "windows":
            name_in, name_out = self._rule_names(ip)
            ok1, out1 = self._run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={name_in}", "dir=in", "action=block",
                f"remoteip={ip}", "enable=yes",
            ])
            ok2, out2 = self._run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={name_out}", "dir=out", "action=block",
                f"remoteip={ip}", "enable=yes",
            ])
            return (ok1 and ok2), (out1 or out2 or "Règles pare-feu posées.")
        # Linux / Netfilter — on insère en tête de chaîne (priorité maximale).
        ok1, out1 = self._run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])
        ok2, out2 = self._run(["iptables", "-I", "OUTPUT", "-d", ip, "-j", "DROP"])
        return (ok1 and ok2), (out1 or out2 or "Règles iptables posées.")

    def _remove_block(self, ip: str) -> tuple:
        """Lève les règles de blocage pour une IP (idempotent)."""
        if self.platform == "windows":
            name_in, name_out = self._rule_names(ip)
            self._run(["netsh", "advfirewall", "firewall", "delete", "rule",
                       f"name={name_in}"])
            self._run(["netsh", "advfirewall", "firewall", "delete", "rule",
                       f"name={name_out}"])
            return True, "Règles pare-feu retirées."
        # Sous Linux, -D peut devoir être répété si la règle a été insérée
        # plusieurs fois ; on boucle prudemment avec une borne.
        for _ in range(4):
            ok_in, _ = self._run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
            ok_out, _ = self._run(["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"])
            if not (ok_in or ok_out):
                break
        return True, "Règles iptables retirées."

    # =========================================================================
    #  API PUBLIQUE
    # =========================================================================

    def quarantine(self, mac: str) -> dict:
        """Met un actif en quarantaine (blocage pare-feu local + état)."""
        device = self.db.get_device(mac)
        if not device:
            return {"ok": False, "error": "Actif introuvable."}

        refusal = self._guard(device)
        if refusal:
            return {"ok": False, "error": refusal}

        ip = device["ip"]
        with self._lock:
            applied, detail = (True, "Enregistré (pare-feu indisponible).")
            if self.backend_ok:
                applied, detail = self._apply_block(ip)

            self.db.set_quarantine(mac, True, enforced=applied and self.backend_ok)

        self.db.add_alert(
            "quarantine",
            f"Actif mis en quarantaine : {device.get('label') or ip}",
            f"Le trafic entre le poste de supervision et {ip} ({mac}) a été "
            f"bloqué au pare-feu local. {detail} Pour une isolation à l'échelle "
            f"du réseau, appliquez un filtrage MAC ou une coupure de port sur "
            f"le switch/la passerelle.",
            mac=mac, ip=ip, severity=config.SEV_WARNING,
            dedup_key=f"quarantine:{mac}",
            evidence={"action": "quarantine", "enforced": applied, "detail": detail},
        )
        return {"ok": True, "enforced": bool(applied and self.backend_ok),
                "detail": detail, "device": self.db.get_device(mac)}

    def release(self, mac: str) -> dict:
        """Lève la quarantaine d'un actif (retrait des règles + état)."""
        device = self.db.get_device(mac)
        if not device:
            return {"ok": False, "error": "Actif introuvable."}

        ip = device.get("ip")
        with self._lock:
            detail = "État réinitialisé."
            if self.backend_ok and ip and _valid_ip(ip):
                _, detail = self._remove_block(ip)
            self.db.set_quarantine(mac, False)

        self.db.add_alert(
            "quarantine_release",
            f"Quarantaine levée : {device.get('label') or ip}",
            f"Le blocage pare-feu de {ip} ({mac}) a été retiré. {detail}",
            mac=mac, ip=ip, severity=config.SEV_INFO,
            dedup_key=f"release:{mac}",
            evidence={"action": "release", "detail": detail},
        )
        return {"ok": True, "detail": detail, "device": self.db.get_device(mac)}

    def release_all(self) -> int:
        """Lève toutes les quarantaines (utile à l'arrêt du service)."""
        count = 0
        for device in self.db.all_devices():
            if device.get("quarantined"):
                self.release(device["mac"])
                count += 1
        return count
