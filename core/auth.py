# -*- coding: utf-8 -*-
"""
================================================================================
 NetWatch Enterprise — core/auth.py
--------------------------------------------------------------------------------
 Authentification de la console et primitives anti-CSRF.

 Modèle retenu (adapté à une console de supervision locale) :
   * Mot de passe unique d'opérateur, jamais stocké en clair — seul son
     empreinte salée (werkzeug / PBKDF2) est conservée en mémoire.
   * Aucun mot de passe par défaut : si l'exploitant n'en fixe pas, un mot de
     passe aléatoire est généré au démarrage et affiché dans la console.
   * Clé de signature des sessions persistée (droits 600) pour que les sessions
     survivent aux redémarrages sans être devinables.
   * Jetons CSRF : valeurs aléatoires à comparer en temps constant.

 Ce module ne connaît PAS Flask : il ne fournit que la logique (hash, secret,
 jetons). L'application (app.py) l'utilise dans une garde `before_request`.
================================================================================
"""

import hmac
import os
import secrets

from werkzeug.security import check_password_hash, generate_password_hash

import config


class AuthManager:
    """Détenteur de l'empreinte du mot de passe et de la clé de session."""

    def __init__(self):
        self.enabled = bool(config.AUTH_ENABLED)
        self.secret_key = self._load_or_create_secret()
        self._password_hash, self.generated_password = self._resolve_password()

    # ------------------------------------------------------------- SECRET
    def _load_or_create_secret(self) -> str:
        """Renvoie la clé de signature : env > fichier persistant > génération."""
        if config.SECRET_KEY:
            return config.SECRET_KEY
        try:
            if os.path.exists(config.SECRET_KEY_FILE):
                with open(config.SECRET_KEY_FILE, "r", encoding="utf-8") as fh:
                    existing = fh.read().strip()
                if existing:
                    return existing
        except OSError:
            pass

        secret = secrets.token_hex(32)
        try:
            os.makedirs(config.DATA_DIR, exist_ok=True)
            with open(config.SECRET_KEY_FILE, "w", encoding="utf-8") as fh:
                fh.write(secret)
            # Restreint la lecture au propriétaire (sans effet notable sous NTFS,
            # mais correct sous Linux/macOS).
            try:
                os.chmod(config.SECRET_KEY_FILE, 0o600)
            except OSError:
                pass
        except OSError:
            # En dernier recours, une clé volatile : les sessions ne survivront
            # pas au redémarrage, mais l'application reste fonctionnelle.
            pass
        return secret

    # ----------------------------------------------------------- PASSWORD
    def _resolve_password(self):
        """
        Renvoie (empreinte, mot_de_passe_généré).

        `mot_de_passe_généré` n'est non nul que lorsqu'aucun mot de passe n'a été
        configuré : il est alors affiché une fois dans la bannière de démarrage.
        """
        raw = (config.AUTH_PASSWORD or "").strip()
        if raw:
            return generate_password_hash(raw), None
        generated = secrets.token_urlsafe(12)
        return generate_password_hash(generated), generated

    def verify_password(self, password: str) -> bool:
        """Vérifie le mot de passe fourni contre l'empreinte enregistrée."""
        if not password:
            return False
        try:
            return check_password_hash(self._password_hash, password)
        except Exception:                                    # pragma: no cover
            return False

    # --------------------------------------------------------------- CSRF
    @staticmethod
    def new_csrf_token() -> str:
        """Génère un jeton CSRF imprévisible."""
        return secrets.token_urlsafe(32)

    @staticmethod
    def csrf_valid(expected: str, received: str) -> bool:
        """Compare deux jetons CSRF en temps constant."""
        if not expected or not received:
            return False
        return hmac.compare_digest(str(expected), str(received))
