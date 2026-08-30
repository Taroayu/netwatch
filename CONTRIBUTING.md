# Contribuer à NetWatch

Merci de votre intérêt ! Les *issues* et *pull requests* sont les bienvenues.
Ce guide décrit comment mettre en place l'environnement et les règles à
respecter avant de proposer une contribution.

> ⚠️ NetWatch est un **outil défensif**. Aucune contribution ajoutant des
> capacités offensives (émission de trames ARP forgées, contre-attaque,
> interception de trafic tiers, etc.) ne sera acceptée. Voir
> [SECURITY.md](SECURITY.md).

## Mise en place de l'environnement

```bash
# Backend
python -m venv .venv
# Windows : .venv\Scripts\activate   |   Linux/macOS : source .venv/bin/activate
pip install -r requirements-dev.txt

# Front-end
cd frontend
npm install
```

Développement avec rechargement à chaud :

```bash
python app.py                 # terminal 1 — backend (port 5000)
cd frontend && npm run dev    # terminal 2 — Vite (port 5173)
```

## Avant d'ouvrir une Pull Request

Toutes ces commandes doivent passer au vert (la CI les rejoue de toute façon) :

```bash
# Backend
pytest                        # 32 tests
python -m compileall app.py config.py core

# Front-end (dans frontend/)
npm run lint                  # ESLint — 0 erreur
npm run test                  # Vitest — 14 tests
npm run build                 # build de production
```

Si vous modifiez l'interface, **recompilez et committez `frontend/dist/`**
(il est versionné pour permettre un lancement sans Node).

## Conventions

- **Python** : PEP 8, fonctions et modules commentés en français comme le reste
  du code, pas de dépendance offensive.
- **TypeScript/React** : mode `strict`, composants fonctionnels, état via le
  store Zustand, respect d'ESLint + Prettier (`npm run format`).
- **Commits** : messages clairs à l'impératif (ex. « Ajoute la détection de
  rogue DHCP »). Un commit = un changement cohérent.
- **Accessibilité** : conserver la navigation clavier, les attributs ARIA et le
  contraste WCAG AA sur toute évolution de l'UI.
- **Tests** : toute nouvelle logique (détection, API, résolveur) doit être
  couverte par un test.

## Signaler un bug

Ouvrez une *issue* en décrivant : version/OS, étapes de reproduction,
comportement attendu vs observé, et logs pertinents (sans données sensibles).
Pour une **faille de sécurité**, n'ouvrez pas d'issue publique — voir
[SECURITY.md](SECURITY.md).

## Idées de contributions

- Nouvelles heuristiques de détection (rogue DHCP, scan de ports hostile…).
- Export des alertes vers un SIEM (webhook / syslog).
- Internationalisation de l'interface (actuellement en français).
- Comptes multi-utilisateurs et rôles.

Merci de contribuer à un réseau plus sûr ! 🛡️
