# -*- coding: utf-8 -*-
"""
================================================================================
 NetWatch Enterprise — core/notifier.py
--------------------------------------------------------------------------------
 Export des alertes vers des systèmes externes (intégration SIEM).

   * Webhook générique — un POST JSON par alerte (Slack/Teams/n8n, ou toute
     API HTTP). Utilise uniquement la bibliothèque standard (urllib) : aucune
     dépendance supplémentaire.
   * Syslog (RFC 3164, UDP) — pour un collecteur type rsyslog, Graylog, Wazuh…

 L'envoi est :
   * FILTRÉ par sévérité minimale (NOTIFY_MIN_SEVERITY) ;
   * NON BLOQUANT — les alertes sont empilées et traitées par un fil dédié, de
     sorte que la collecte n'est jamais ralentie par un endpoint lent ;
   * BEST-EFFORT — toute erreur d'envoi est absorbée (jamais d'interruption).
================================================================================
"""

import json
import queue
import socket
import threading
import urllib.request
from datetime import datetime

import config

# Priorité numérique des sévérités pour le filtrage.
_SEV_RANK = {"info": 10, "warning": 50, "critical": 100, "secure": 0}

# Sévérité NetWatch -> niveau syslog (RFC 5424).
_SEV_SYSLOG = {"critical": 2, "warning": 4, "info": 6, "secure": 6}


class AlertNotifier:
    """File d'envoi asynchrone des alertes vers webhook et/ou syslog."""

    def __init__(self):
        self.webhook_url = config.WEBHOOK_URL
        self.syslog_host = config.SYSLOG_HOST
        self.syslog_port = int(config.SYSLOG_PORT)
        self.min_rank = _SEV_RANK.get(config.NOTIFY_MIN_SEVERITY, 50)
        self.enabled = bool(self.webhook_url or self.syslog_host)

        self._queue: "queue.Queue" = queue.Queue(maxsize=1000)
        self._thread = None
        if self.enabled:
            self._thread = threading.Thread(
                target=self._worker, name="nw-notifier", daemon=True)
            self._thread.start()

    def status(self) -> dict:
        """État exposé au dashboard / à la bannière."""
        sinks = []
        if self.webhook_url:
            sinks.append("webhook")
        if self.syslog_host:
            sinks.append(f"syslog:{self.syslog_host}:{self.syslog_port}")
        return {"enabled": self.enabled, "sinks": sinks,
                "min_severity": config.NOTIFY_MIN_SEVERITY}

    # ------------------------------------------------------------- INGESTION
    def dispatch(self, alert: dict) -> None:
        """Point d'entrée branché sur Database.on_alert (appelé à chaud)."""
        if not self.enabled:
            return
        if _SEV_RANK.get(alert.get("severity", "info"), 0) < self.min_rank:
            return
        try:
            self._queue.put_nowait(alert)
        except queue.Full:
            pass  # file saturée : on abandonne plutôt que de bloquer la collecte

    # -------------------------------------------------------------- WORKER
    def _worker(self):
        while True:
            alert = self._queue.get()
            try:
                if self.webhook_url:
                    self._send_webhook(alert)
                if self.syslog_host:
                    self._send_syslog(alert)
            except Exception:
                pass  # best-effort
            finally:
                self._queue.task_done()

    # -------------------------------------------------------------- WEBHOOK
    def _send_webhook(self, alert: dict):
        payload = {
            "source": "NetWatch",
            "severity": alert.get("severity"),
            "type": alert.get("type"),
            "title": alert.get("title"),
            "detail": alert.get("detail"),
            "mac": alert.get("mac"),
            "ip": alert.get("ip"),
            "mitre": alert.get("mitre"),
            "time": alert.get("time"),
            # Champ « text » : rendu lisible par Slack/Teams/Discord.
            "text": f"[NetWatch][{str(alert.get('severity','')).upper()}] "
                    f"{alert.get('title')} — {alert.get('detail')}",
        }
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            self.webhook_url, data=data, method="POST",
            headers={"Content-Type": "application/json", "User-Agent": "NetWatch"},
        )
        urllib.request.urlopen(req, timeout=config.WEBHOOK_TIMEOUT).close()

    # --------------------------------------------------------------- SYSLOG
    def _send_syslog(self, alert: dict):
        # Priorité = facility(local0=16)*8 + severity.
        severity = _SEV_SYSLOG.get(alert.get("severity", "info"), 6)
        pri = 16 * 8 + severity
        ts = datetime.now().strftime("%b %d %H:%M:%S")
        host = socket.gethostname().split(".")[0]
        msg = (f"<{pri}>{ts} {host} NetWatch: "
               f"[{alert.get('type')}] {alert.get('title')} — {alert.get('detail')} "
               f"(ip={alert.get('ip')} mac={alert.get('mac')})")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(msg.encode("utf-8", "replace"),
                        (self.syslog_host, self.syslog_port))
        finally:
            sock.close()
