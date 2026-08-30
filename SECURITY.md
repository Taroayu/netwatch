# Politique de sécurité & usage responsable

## ⚠️ Cadre d'utilisation

NetWatch est un **outil défensif** de supervision réseau. Il détecte les
attaques d'empoisonnement de cache ARP (Adversary-in-the-Middle, MITRE ATT&CK
**T1557.002**) et inventorie les actifs d'un segment local.

**Vous ne devez l'utiliser que sur un réseau dont vous êtes propriétaire ou
pour lequel vous disposez d'une autorisation écrite.** L'écoute et l'émission
de trames sur un réseau tiers sans autorisation sont illégales dans la plupart
des juridictions.

### Ce que fait NetWatch
- Balayage ARP actif + capture passive pour découvrir et surveiller les actifs.
- Détection d'anomalies d'association IP↔MAC (empoisonnement, usurpation de
  passerelle, flood ARP, MAC multiples).
- **Réponse active strictement locale** : le bouton « Isoler » pose une règle
  sur le **pare-feu de la machine hôte uniquement**.

### Ce que NetWatch ne fait PAS
- Il **n'émet jamais de trames ARP forgées** et ne réalise aucune contre-attaque.
- Il ne configure **aucun autre équipement** que la machine sur laquelle il
  tourne.
- Il ne contient aucun outil offensif. Le script `simulate_detection.py`
  n'émet rien sur le réseau : il injecte des paquets synthétiques *en mémoire*
  pour tester le moteur de détection.

## Bonnes pratiques de déploiement
- Définir un mot de passe stable via `NETWATCH_PASSWORD` (sinon un mot de passe
  aléatoire est généré à chaque démarrage).
- Activer **HTTPS** en production (`NETWATCH_TLS_CERT` / `NETWATCH_TLS_KEY`,
  voir `tools/generate_cert.py`) et laisser `HOST=127.0.0.1` si l'accès distant
  n'est pas nécessaire.
- Ne jamais committer le dossier `data/` (clé de session, inventaire, journaux) —
  il est déjà exclu par `.gitignore`.

## Signaler une vulnérabilité
Merci de **ne pas** ouvrir d'issue publique pour une faille de sécurité.
Utilisez l'onglet **Security → Report a vulnerability** de GitHub (Private
Vulnerability Reporting), ou contactez directement le mainteneur.
