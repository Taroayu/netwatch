# Journal des modifications

Toutes les évolutions notables de NetWatch sont consignées ici.

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) et le
projet applique le [versionnage sémantique](https://semver.org/lang/fr/).

## [3.0.0] — 2026-08-30

Édition **Enterprise / Pro-SecOps** : refonte complète, prête pour la
production et pour un usage en centre opérationnel de sécurité (SOC).

### Ajouté

- **Mode démonstration** (`python app.py --demo`) : flotte simulée de 10 actifs
  et scénarios d'attaque, sans réseau ni privilèges. Écrit dans `data_demo/`,
  jamais dans les données réelles.
- **Export SIEM** : diffusion asynchrone des alertes vers un **webhook**
  (Slack/Teams/HTTP) et/ou un serveur **syslog** (RFC 3164), avec seuil de
  sévérité configurable (`NETWATCH_NOTIFY_MIN_SEVERITY`).
- **Arguments en ligne de commande** : `--demo`, `--host`, `--port`,
  `--target`, `--password`, `--no-auth`, `--no-browser`.
- **Interface React + TypeScript** (Vite, Zustand) remplaçant l'ancien rendu
  serveur : thème **clair/sombre**, design responsive, skeleton screens,
  graphique de tendance, accessibilité WCAG AA (piège de focus, ARIA).
- **Mises à jour optimistes** : acquittement et actions rendus sans latence.
- **Authentification** par session (cookie HttpOnly, SameSite), **protection
  CSRF** (double-submit), anti-bruteforce par IP, en-têtes de sécurité, HTTPS
  optionnel + générateur de certificat auto-signé.
- **Console de démarrage colorée** (bannière ANSI, respecte `NO_COLOR`).
- Intégration continue (GitHub Actions), Dockerfile multi-étapes + compose.
- Suite de tests étendue : **36 tests backend** (pytest) + **14 tests
  frontend** (Vitest).

### Modifié

- **Résolution OUI** basculée sur `netaddr` (base IEEE hors-ligne, ~35 000
  préfixes) complétée par `mac-vendor-lookup`, avec table de repli.
- **Flux temps réel SSE** refondu : un seul producteur diffusant vers N clients
  (au lieu d'un recalcul par client), plafond de clients configurable.
- **Typage des actifs** par score pondéré (OUI + nom d'hôte + ports exposés)
  avec faisceau de preuves consultable.

### Corrigé

- `RuntimeWarning: coroutine 'AsyncMacLookup.lookup' was never awaited` sous
  résolution concurrente (boucle asyncio dédiée par appel).
- En-tête SSE `Connection: keep-alive` rejeté par Waitress (hop-by-hop).
- Carré blanc du coin de défilement en thème sombre.

### Sécurité

- NetWatch reste **strictement défensif** : la mise en quarantaine passe
  uniquement par le **pare-feu de l'hôte** (`netsh`/`iptables`), **jamais** par
  une trame ARP forgée. Aucune capacité offensive.

## [2.0.0] — antérieur

- Base Flask + Scapy : détection d'empoisonnement ARP, inventaire des actifs,
  balayage actif et sniffer passif.

[3.0.0]: https://github.com/melk/netwatch/releases/tag/v3.0.0
