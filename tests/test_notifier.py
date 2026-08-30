# -*- coding: utf-8 -*-
"""Tests de l'export d'alertes (webhook/syslog) — filtrage par sévérité."""

import config
from core.notifier import AlertNotifier


def _notifier_with(webhook="http://localhost:9/hook", min_sev="warning"):
    config.WEBHOOK_URL = webhook
    config.SYSLOG_HOST = ""
    config.NOTIFY_MIN_SEVERITY = min_sev
    return AlertNotifier()


def test_severity_filtering():
    n = _notifier_with(min_sev="warning")
    sent = []
    n._send_webhook = lambda alert: sent.append(alert["severity"])  # type: ignore
    n.dispatch({"severity": "info", "title": "t", "detail": "d"})       # ignoré
    n.dispatch({"severity": "warning", "title": "t", "detail": "d"})    # envoyé
    n.dispatch({"severity": "critical", "title": "t", "detail": "d"})   # envoyé
    n._queue.join()
    assert "info" not in sent
    assert set(sent) == {"warning", "critical"}


def test_disabled_when_no_sink():
    config.WEBHOOK_URL = ""
    config.SYSLOG_HOST = ""
    n = AlertNotifier()
    assert n.enabled is False
    # dispatch ne lève rien même désactivé
    n.dispatch({"severity": "critical", "title": "t", "detail": "d"})


def test_status_reports_sinks():
    n = _notifier_with(webhook="http://x/y")
    st = n.status()
    assert st["enabled"] is True
    assert "webhook" in st["sinks"]
