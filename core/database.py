# -*- coding: utf-8 -*-
"""
================================================================================
 NetWatch Enterprise — core/database.py
--------------------------------------------------------------------------------
 Couche de persistance de la plateforme.

 Responsabilités :
   * Inventaire des actifs (known_devices.json) : MAC comme clé primaire,
     métadonnées enrichies (libellé analyste, criticité, historique IP,
     statistiques de présence).
   * Journal des alertes (alerts.json) : file FIFO bornée, acquittement,
     déduplication par cooldown.
   * Journal d'audit append-only (netwatch_audit.log).
   * Série temporelle courte pour les graphiques du dashboard.

 Contraintes :
   * Toutes les opérations sont protégées par un RLock réentrant : le moteur de
     scan, le sniffer passif et les requêtes HTTP écrivent en concurrence.
   * Les écritures disque sont atomiques (fichier temporaire + os.replace) afin
     de ne jamais laisser un JSON tronqué en cas d'arrêt brutal.
================================================================================
"""

import json
import logging
import os
import threading
import time
import uuid
from collections import deque
from datetime import datetime
from logging.handlers import RotatingFileHandler

import config


# ==============================================================================
# Utilitaires
# ==============================================================================

def now_ts() -> float:
    """Horodatage epoch (float, précision seconde/milliseconde)."""
    return time.time()


def iso(ts: float = None) -> str:
    """Horodatage ISO 8601 local, lisible par le front-end."""
    return datetime.fromtimestamp(ts if ts else now_ts()).isoformat(timespec="seconds")


def _atomic_write(path: str, payload) -> None:
    """Écriture JSON atomique : aucun risque de fichier partiellement écrit."""
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def _safe_read(path: str, default):
    """Lecture JSON tolérante aux fichiers absents, vides ou corrompus."""
    try:
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            return default
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError, ValueError):
        # Fichier corrompu : on le met de côté plutôt que de perdre la donnée.
        try:
            os.replace(path, f"{path}.corrupted.{int(now_ts())}")
        except OSError:
            pass
        return default


# ==============================================================================
# Classe principale
# ==============================================================================

class Database:
    """Entrepôt de données en mémoire, adossé à une persistance JSON."""

    # ------------------------------------------------------------------ INIT
    def __init__(self):
        self._lock = threading.RLock()

        # Inventaire : { mac_normalisée: {…} }
        self.devices = {}

        # Alertes : liste ordonnée du plus récent au plus ancien.
        self.alerts = []

        # Anti-spam d'alertes : { clé_dedup: timestamp_dernière_émission }
        self._alert_cooldown = {}

        # Série temporelle du dashboard.
        self.timeline = deque(maxlen=config.TIMELINE_POINTS)

        # Compteurs de session.
        self.stats = {
            "started_at": now_ts(),
            "scan_count": 0,
            "packets_seen": 0,
            "last_scan_at": None,
            "last_scan_duration": None,
        }

        # Écriture debouncée : les mises à jour d'inventaire du chemin critique
        # (scans) marquent l'état « sale » ; un flush périodique écrit le
        # fichier au plus une fois par cycle, au lieu d'une réécriture complète
        # à chaque scan.
        self._devices_dirty = False

        # Callback optionnel appelé pour chaque nouvelle alerte (export SIEM).
        # Signature : on_alert(alert: dict) -> None. Best-effort, non bloquant.
        self.on_alert = None

        os.makedirs(config.DATA_DIR, exist_ok=True)
        self._audit_logger = self._build_audit_logger()
        self.load()

    # -------------------------------------------------------- AUDIT (rotation)
    @staticmethod
    def _build_audit_logger() -> logging.Logger:
        """
        Journal d'audit sur fichier tournant : borne la taille disque au lieu
        de croître sans fin. Une archive .1, .2, … est conservée par rotation.
        """
        logger = logging.getLogger("netwatch.audit")
        logger.setLevel(logging.INFO)
        logger.propagate = False
        # Évite d'empiler plusieurs handlers si plusieurs Database sont créés
        # (par ex. dans les tests).
        if not logger.handlers:
            try:
                handler = RotatingFileHandler(
                    config.AUDIT_LOG_FILE,
                    maxBytes=config.AUDIT_MAX_BYTES,
                    backupCount=config.AUDIT_BACKUPS,
                    encoding="utf-8",
                )
                handler.setFormatter(logging.Formatter("%(message)s"))
                logger.addHandler(handler)
            except Exception:                    # pragma: no cover
                logger.addHandler(logging.NullHandler())
        return logger

    # ------------------------------------------------------------- PERSISTANCE
    def load(self) -> None:
        """Recharge l'inventaire et les alertes depuis le disque."""
        with self._lock:
            raw_devices = _safe_read(config.KNOWN_DEVICES_FILE, {})
            if isinstance(raw_devices, dict):
                self.devices = {
                    self.normalize_mac(k): self._migrate_device(k, v)
                    for k, v in raw_devices.items()
                    if isinstance(v, dict)
                }
            raw_alerts = _safe_read(config.ALERTS_FILE, [])
            if isinstance(raw_alerts, list):
                self.alerts = [a for a in raw_alerts if isinstance(a, dict)]

    def save_devices(self) -> None:
        with self._lock:
            self._devices_dirty = False
            _atomic_write(config.KNOWN_DEVICES_FILE, self.devices)

    def save_alerts(self) -> None:
        with self._lock:
            _atomic_write(config.ALERTS_FILE, self.alerts[:config.MAX_ALERTS])

    def save_all(self) -> None:
        self.save_devices()
        self.save_alerts()

    def mark_devices_dirty(self) -> None:
        """Signale une modification d'inventaire à écrire au prochain flush."""
        with self._lock:
            self._devices_dirty = True

    def flush_devices(self) -> bool:
        """Écrit l'inventaire uniquement s'il a changé depuis le dernier flush."""
        with self._lock:
            dirty = self._devices_dirty
        if dirty:
            self.save_devices()
        return dirty

    # ----------------------------------------------------------------- AUDIT
    def audit(self, category: str, message: str) -> None:
        """Écrit une ligne dans le journal d'audit (fichier tournant)."""
        try:
            self._audit_logger.info(f"{iso()} | {category.upper():<18} | {message}")
        except Exception:
            pass  # Le journal d'audit ne doit jamais interrompre la collecte.

    # ------------------------------------------------------------- NORMALISATION
    @staticmethod
    def normalize_mac(mac: str) -> str:
        """Normalise une MAC au format aa:bb:cc:dd:ee:ff."""
        if not mac:
            return ""
        cleaned = mac.strip().lower().replace("-", ":").replace(".", ":")
        parts = [p for p in cleaned.split(":") if p]
        if len(parts) == 6:
            return ":".join(p.zfill(2) for p in parts)
        hexonly = "".join(c for c in cleaned if c in "0123456789abcdef")
        if len(hexonly) == 12:
            return ":".join(hexonly[i:i + 2] for i in range(0, 12, 2))
        return cleaned

    @staticmethod
    def _migrate_device(mac: str, record: dict) -> dict:
        """Complète un enregistrement issu d'une version antérieure du schéma."""
        defaults = {
            "mac": Database.normalize_mac(mac),
            "ip": record.get("ip", "—"),
            "hostname": None,
            "vendor": "Inconnu",
            "vendor_source": "none",
            "asset_type": "unknown",
            "type_label": "Actif non identifié",
            "type_confidence": 0,
            "type_evidence": [],
            "label": None,
            "notes": "",
            "criticality": "medium",
            "trusted": False,
            "is_gateway": False,
            "is_local_host": False,
            "is_virtual": False,
            "is_randomized": False,
            "open_ports": [],
            "first_seen": now_ts(),
            "last_seen": now_ts(),
            "seen_count": 1,
            "ip_history": [],
            "online": False,
            "risk_score": 0,
            "flags": [],
            "quarantined": False,
            "quarantined_at": None,
            "quarantine_enforced": False,
        }
        merged = dict(defaults)
        merged.update({k: v for k, v in record.items() if k in defaults})
        return merged

    # =========================================================================
    #  INVENTAIRE DES ACTIFS
    # =========================================================================

    def get_device(self, mac: str):
        with self._lock:
            return self.devices.get(self.normalize_mac(mac))

    def all_devices(self) -> list:
        """Copie défensive de l'inventaire, prête à être sérialisée."""
        with self._lock:
            return [dict(d) for d in self.devices.values()]

    def update_risk_scores(self, scorer, open_alerts) -> None:
        """
        Recalcule le score de risque de chaque actif via `scorer(record, alerts)`.

        Exposé publiquement pour que le moteur de surveillance n'ait pas à
        manipuler le verrou interne de la base (bonne encapsulation).
        """
        with self._lock:
            for record in self.devices.values():
                record["risk_score"] = scorer(record, open_alerts)

    def upsert_device(self, mac: str, **fields):
        """
        Crée ou met à jour un actif.

        Retourne (record, is_new) — `is_new` permet au moteur de détection de
        décider s'il doit lever une alerte « nouvel actif ».
        """
        mac = self.normalize_mac(mac)
        if not mac:
            return None, False

        with self._lock:
            is_new = mac not in self.devices
            if is_new:
                self.devices[mac] = self._migrate_device(mac, {"mac": mac})
                self.devices[mac]["first_seen"] = now_ts()

            record = self.devices[mac]
            previous_ip = record.get("ip")

            for key, value in fields.items():
                if value is None:
                    continue
                # On ne remplace jamais un libellé analyste par une valeur auto.
                if key == "label" and record.get("label"):
                    continue
                record[key] = value

            # Historique d'adressage (utile pour l'investigation).
            new_ip = fields.get("ip")
            if new_ip and new_ip != previous_ip:
                history = record.setdefault("ip_history", [])
                history.append({"ip": new_ip, "at": iso()})
                del history[:-15]  # on conserve les 15 dernières mutations

            return record, is_new

    def mark_seen(self, mac: str) -> None:
        """Rafraîchit les compteurs de présence d'un actif."""
        with self._lock:
            record = self.devices.get(self.normalize_mac(mac))
            if record:
                record["last_seen"] = now_ts()
                record["seen_count"] = record.get("seen_count", 0) + 1
                record["online"] = True

    def refresh_online_states(self) -> list:
        """
        Bascule hors ligne les actifs muets depuis plus de OFFLINE_AFTER.

        Retourne la liste des actifs dont l'état vient de changer.
        """
        transitions = []
        threshold = now_ts() - config.OFFLINE_AFTER
        with self._lock:
            for record in self.devices.values():
                was_online = record.get("online", False)
                is_online = record.get("last_seen", 0) >= threshold
                if was_online != is_online:
                    record["online"] = is_online
                    transitions.append((record, is_online))
        return transitions

    def update_device_meta(self, mac: str, label=None, criticality=None,
                           notes=None, trusted=None, asset_type=None):
        """Mise à jour manuelle par l'analyste (modale d'édition du dashboard)."""
        mac = self.normalize_mac(mac)
        with self._lock:
            record = self.devices.get(mac)
            if not record:
                return None
            if label is not None:
                record["label"] = label.strip() or None
            if criticality in ("low", "medium", "high", "critical"):
                record["criticality"] = criticality
            if notes is not None:
                record["notes"] = notes.strip()[:1000]
            if trusted is not None:
                record["trusted"] = bool(trusted)
            if asset_type in config.ASSET_TYPES:
                record["asset_type"] = asset_type
                record["type_label"] = config.ASSET_TYPES[asset_type]["label"]
                record["type_confidence"] = 100
                record["type_evidence"] = ["Classification manuelle (analyste)"]
        self.save_devices()
        self.audit("ASSET_EDIT", f"{mac} mis à jour par l'analyste")
        return record

    def set_quarantine(self, mac: str, active: bool, enforced: bool = False):
        """Bascule l'état de quarantaine d'un actif (piloté par le responder)."""
        mac = self.normalize_mac(mac)
        with self._lock:
            record = self.devices.get(mac)
            if not record:
                return None
            record["quarantined"] = bool(active)
            record["quarantine_enforced"] = bool(active and enforced)
            record["quarantined_at"] = iso() if active else None
        self.save_devices()
        return record

    def forget_device(self, mac: str) -> bool:
        """Supprime un actif de l'inventaire (purge d'un faux positif)."""
        mac = self.normalize_mac(mac)
        with self._lock:
            existed = self.devices.pop(mac, None) is not None
        if existed:
            self.save_devices()
            self.audit("ASSET_DELETE", f"{mac} retiré de l'inventaire")
        return existed

    # =========================================================================
    #  ALERTES
    # =========================================================================

    def add_alert(self, alert_type: str, title: str, detail: str,
                  mac: str = None, ip: str = None,
                  severity: str = None, dedup_key: str = None,
                  evidence: dict = None):
        """
        Enregistre une alerte de sécurité.

        Le paramètre `dedup_key` active l'anti-spam : une même clé ne peut être
        réémise qu'après config.ALERT_COOLDOWN secondes. Retourne None si
        l'alerte a été absorbée par le cooldown.
        """
        meta = config.ALERT_TYPES.get(alert_type, config.ALERT_TYPES["system"])
        severity = severity or meta["severity"]
        key = dedup_key or f"{alert_type}:{mac or ''}:{ip or ''}"

        with self._lock:
            last = self._alert_cooldown.get(key, 0)
            if now_ts() - last < config.ALERT_COOLDOWN:
                return None
            self._alert_cooldown[key] = now_ts()

            # Purge opportuniste : on évite que la table anti-spam ne grossisse
            # indéfiniment sur une très longue durée de fonctionnement.
            if len(self._alert_cooldown) > 1024:
                cutoff = now_ts() - config.ALERT_COOLDOWN * 4
                self._alert_cooldown = {
                    k: v for k, v in self._alert_cooldown.items() if v > cutoff
                }

            alert = {
                "id": uuid.uuid4().hex[:12],
                "ts": now_ts(),
                "time": iso(),
                "type": alert_type,
                "type_label": meta["label"],
                "mitre": meta.get("mitre", "—"),
                "severity": severity,
                "title": title,
                "detail": detail,
                "mac": self.normalize_mac(mac) if mac else None,
                "ip": ip,
                "evidence": evidence or {},
                "acknowledged": False,
                "acknowledged_at": None,
            }
            self.alerts.insert(0, alert)
            del self.alerts[config.MAX_ALERTS:]

        self.save_alerts()
        self.audit(f"ALERT_{severity}", f"[{alert_type}] {title} — {detail}")

        # Export externe (webhook / syslog), best-effort et non bloquant.
        if self.on_alert is not None:
            try:
                self.on_alert(alert)
            except Exception:
                pass

        return alert

    def all_alerts(self) -> list:
        with self._lock:
            return [dict(a) for a in self.alerts]

    def acknowledge(self, alert_id: str) -> bool:
        with self._lock:
            for alert in self.alerts:
                if alert["id"] == alert_id:
                    alert["acknowledged"] = True
                    alert["acknowledged_at"] = iso()
                    break
            else:
                return False
        self.save_alerts()
        self.audit("ALERT_ACK", f"Alerte {alert_id} acquittée")
        return True

    def acknowledge_all(self) -> int:
        count = 0
        with self._lock:
            for alert in self.alerts:
                if not alert["acknowledged"]:
                    alert["acknowledged"] = True
                    alert["acknowledged_at"] = iso()
                    count += 1
        if count:
            self.save_alerts()
            self.audit("ALERT_ACK", f"{count} alerte(s) acquittée(s) en masse")
        return count

    def clear_alerts(self) -> int:
        with self._lock:
            count = len(self.alerts)
            self.alerts = []
            self._alert_cooldown = {}
        self.save_alerts()
        self.audit("ALERT_PURGE", f"{count} alerte(s) purgée(s)")
        return count

    # =========================================================================
    #  MÉTRIQUES & SÉRIES TEMPORELLES
    # =========================================================================

    def push_timeline_point(self) -> None:
        """Ajoute un point à la série temporelle affichée par le dashboard."""
        with self._lock:
            online = sum(1 for d in self.devices.values() if d.get("online"))
            criticals = sum(
                1 for a in self.alerts
                if a["severity"] == config.SEV_CRITICAL and not a["acknowledged"]
            )
            self.timeline.append({
                "t": iso(),
                "online": online,
                "total": len(self.devices),
                "critical": criticals,
            })

    def compute_metrics(self) -> dict:
        """Agrégats consommés par les tuiles KPI du dashboard."""
        with self._lock:
            devices = list(self.devices.values())
            alerts = list(self.alerts)

        total = len(devices)
        online = sum(1 for d in devices if d.get("online"))
        untrusted = sum(1 for d in devices if not d.get("trusted"))
        virtual = sum(1 for d in devices if d.get("is_virtual"))
        randomized = sum(1 for d in devices if d.get("is_randomized"))
        recent = sum(1 for d in devices if now_ts() - d.get("first_seen", 0) < 86400)

        open_alerts = [a for a in alerts if not a["acknowledged"]]
        critical = sum(1 for a in open_alerts if a["severity"] == config.SEV_CRITICAL)
        warning = sum(1 for a in open_alerts if a["severity"] == config.SEV_WARNING)

        # Score de posture : 100 = réseau sain, 0 = compromission avérée.
        posture = 100 - min(100, critical * 30 + warning * 8 + randomized * 2)

        if critical:
            level, level_label = config.SEV_CRITICAL, "COMPROMISSION PROBABLE"
        elif warning:
            level, level_label = config.SEV_WARNING, "VIGILANCE RENFORCÉE"
        else:
            level, level_label = config.SEV_SECURE, "RÉSEAU NOMINAL"

        # Répartition par type d'actif (pour le graphique en anneau).
        distribution = {}
        for device in devices:
            key = device.get("asset_type", "unknown")
            distribution[key] = distribution.get(key, 0) + 1

        return {
            "total": total,
            "online": online,
            "offline": total - online,
            "untrusted": untrusted,
            "virtual": virtual,
            "randomized": randomized,
            "new_24h": recent,
            "alerts_open": len(open_alerts),
            "alerts_critical": critical,
            "alerts_warning": warning,
            "posture": max(0, posture),
            "threat_level": level,
            "threat_label": level_label,
            "distribution": distribution,
            "scan_count": self.stats["scan_count"],
            "packets_seen": self.stats["packets_seen"],
            "last_scan_at": self.stats["last_scan_at"],
            "last_scan_duration": self.stats["last_scan_duration"],
            "uptime": int(now_ts() - self.stats["started_at"]),
        }

    def timeline_points(self) -> list:
        with self._lock:
            return list(self.timeline)
