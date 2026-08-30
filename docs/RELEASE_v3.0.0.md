# NetWatch v3.0.0 — Enterprise / Pro-SecOps

> Copiez ce texte dans le champ « description » de la release GitHub
> (Releases → Draft a new release → Tag `v3.0.0`).

Refonte majeure de NetWatch : une console défensive de supervision réseau
prête pour la production et pour un usage en SOC.

## 🚀 À l'essai en 20 secondes

```bash
pip install -r requirements.txt
python app.py --demo
```

Aucun réseau, aucun privilège : le **mode démonstration** peuple la console
avec une flotte simulée et des scénarios d'attaque réalistes.

## ✨ Points forts

- **Mode démonstration** (`--demo`) — découverte complète sans risque.
- **Export SIEM** — webhook (Slack/Teams/HTTP) et syslog (RFC 3164), avec
  seuil de sévérité configurable.
- **Nouvelle interface React + TypeScript** — thème clair/sombre, responsive,
  accessible (WCAG AA), mises à jour optimistes (zéro latence perçue).
- **Sécurité applicative** — authentification par session, protection CSRF,
  anti-bruteforce, en-têtes de sécurité, HTTPS optionnel.
- **Temps réel scalable** — flux SSE à producteur unique.
- **Qualité** — 36 tests backend + 14 frontend, CI GitHub Actions, Docker.

## 🔒 Toujours strictement défensif

La mise en quarantaine passe uniquement par le pare-feu de l'hôte
(`netsh`/`iptables`) — **jamais** par une trame ARP forgée. Aucune capacité
offensive.

## 📋 Détail complet

Voir le [CHANGELOG](../CHANGELOG.md).

---

**Installation, options CLI, configuration SIEM et captures** : voir le
[README](../README.md).
