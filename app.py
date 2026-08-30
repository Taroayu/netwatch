# -*- coding: utf-8 -*-
"""
================================================================================
 NetWatch Enterprise — app.py
--------------------------------------------------------------------------------
 Point d'entrée de la plateforme.

   * Initialise la couche de persistance, le résolveur d'actifs et le moteur
     de surveillance ARP.
   * Expose une API REST JSON consommée par le dashboard SOC.
   * Sert le front-end statique.

 ⚠ PRIVILÈGES : la capture et l'émission de trames ARP brutes exigent des
   droits élevés.
      - Windows : exécuter le terminal « en tant qu'administrateur » et
        installer Npcap (mode WinPcap-compatible).
      - Linux/macOS : `sudo python app.py`, ou attribuer les capacités
        `sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))`

 ⚠ USAGE : NetWatch est un outil DÉFENSIF de supervision. Ne l'utilisez que sur
   un réseau dont vous êtes propriétaire ou pour lequel vous disposez d'une
   autorisation écrite.
================================================================================
"""

import csv
import io
import json
import os
import sys
import time
import webbrowser
from datetime import timedelta
from threading import Timer


def _parse_cli_into_env():
    """
    Traduit les arguments de ligne de commande en variables d'environnement
    NETWATCH_*, AVANT l'import de `config` (qui les lit à l'import).

    N'est appelé que lorsque app.py est lancé directement (`python app.py`) :
    en import (tests), argv appartient à pytest et ne doit pas être analysé.
    """
    import argparse

    p = argparse.ArgumentParser(
        prog="netwatch",
        description="NetWatch Enterprise — console défensive de supervision réseau.",
    )
    p.add_argument("--demo", action="store_true",
                   help="Mode démonstration : données simulées, sans privilèges ni Npcap/root.")
    p.add_argument("--host", metavar="ADRESSE", help="Adresse d'écoute (défaut 127.0.0.1).")
    p.add_argument("--port", type=int, metavar="PORT", help="Port d'écoute (défaut 5000).")
    p.add_argument("--target", metavar="CIDR", help="Plage à surveiller (ex. 192.168.1.0/24).")
    p.add_argument("--password", metavar="MDP", help="Mot de passe de la console.")
    p.add_argument("--no-auth", action="store_true",
                   help="Désactive l'authentification (développement uniquement).")
    p.add_argument("--no-browser", action="store_true",
                   help="Ne pas ouvrir le navigateur au démarrage.")
    args = p.parse_args()

    mapping = {
        "DEMO": "1" if args.demo else None,
        "HOST": args.host,
        "PORT": str(args.port) if args.port else None,
        "TARGET_NETWORK": args.target,
        "PASSWORD": args.password,
        "AUTH_ENABLED": "0" if args.no_auth else None,
        "OPEN_BROWSER": "0" if args.no_browser else None,
    }
    for key, value in mapping.items():
        if value is not None:
            os.environ[f"NETWATCH_{key}"] = value


if __name__ == "__main__":
    _parse_cli_into_env()

from flask import (Flask, jsonify, request, Response, send_from_directory,
                   session, stream_with_context)

import config
from core.auth import AuthManager
from core.database import Database, iso
from core.demo import DemoSimulator
from core.monitor import NetworkMonitor, SCAPY_AVAILABLE, SCAPY_ERROR
from core.notifier import AlertNotifier
from core.resolver import AssetResolver
from core.responder import ActiveResponder

# ==============================================================================
#  INITIALISATION
# ==============================================================================

# Le front-end est désormais une application React/TypeScript compilée dans
# frontend/dist. Flask ne sert plus de template Jinja : il expose une API JSON
# pure + un flux temps réel, et distribue les fichiers statiques du SPA.
FRONTEND_DIST = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "frontend", "dist")

app = Flask(__name__, static_folder=None)
app.config["JSON_AS_ASCII"] = False
app.config["JSONIFY_PRETTYPRINT_REGULAR"] = False

DB = Database()
RESOLVER = AssetResolver()
MONITOR = NetworkMonitor(DB, RESOLVER)
RESPONDER = ActiveResponder(DB, MONITOR)
AUTH = AuthManager()
DEMO = DemoSimulator(DB, RESOLVER, MONITOR)

# Diffusion des alertes vers un webhook / syslog (intégration SIEM), branchée
# sur la base : chaque nouvelle alerte est transmise, de façon non bloquante.
NOTIFIER = AlertNotifier()
DB.on_alert = NOTIFIER.dispatch

# --- Session signée + cookie durci -------------------------------------------
app.config.update(
    SECRET_KEY=AUTH.secret_key,
    SESSION_COOKIE_NAME="netwatch_session",
    SESSION_COOKIE_HTTPONLY=True,      # inaccessible au JavaScript
    SESSION_COOKIE_SAMESITE="Lax",     # première barrière anti-CSRF
    SESSION_COOKIE_SECURE=bool(config.SESSION_COOKIE_SECURE),  # True en HTTPS
    PERMANENT_SESSION_LIFETIME=timedelta(hours=config.SESSION_HOURS),
)

# Chemins publics (accessibles sans session établie).
_PUBLIC_API = {"/api/auth/login", "/api/auth/status"}
_MUTATING = {"POST", "PUT", "PATCH", "DELETE"}


@app.before_request
def _enforce_auth_and_csrf():
    """
    Garde centrale : exige une session authentifiée pour toute l'API, et un
    jeton CSRF valide pour chaque requête mutante. Le SPA (coquille HTML +
    assets) reste public — il n'affiche que l'écran de connexion tant que la
    session n'est pas établie.
    """
    path = request.path
    if not path.startswith("/api/"):
        return None                     # coquille SPA / fichiers statiques
    if not AUTH.enabled:
        return None                     # authentification désactivée (dev)
    if path in _PUBLIC_API:
        return None                     # login / status
    if not session.get("authenticated"):
        return jsonify({"ok": False, "error": "Authentification requise"}), 401
    if request.method in _MUTATING:
        token = request.headers.get("X-CSRF-Token", "")
        if not AUTH.csrf_valid(session.get("csrf", ""), token):
            return jsonify({"ok": False, "error": "Jeton CSRF invalide ou absent"}), 403
    return None


@app.after_request
def _security_headers(response):
    """
    En-têtes de sécurité HTTP appliqués à toutes les réponses.

    • nosniff       : empêche le navigateur de « deviner » les types MIME.
    • frame DENY    : anti-clickjacking (la console n'est jamais encadrable).
    • Referrer      : ne fuite aucune URL vers l'extérieur.
    • CSP           : tout provient de la même origine ; styles en ligne tolérés
                      (attributs style de React) ; images en data: (icônes).
    • HSTS          : uniquement en HTTPS, pour forcer le TLS ensuite.
    """
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; "
        "frame-ancestors 'none'",
    )
    if config.SESSION_COOKIE_SECURE:
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response


def is_privileged() -> bool:
    """Vérifie que le processus dispose des droits nécessaires à la capture."""
    try:
        if os.name == "nt":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


# ==============================================================================
#  ROUTES — AUTHENTIFICATION
# ==============================================================================

# --- Anti-force-brute : suivi par adresse IP, avec verrouillage temporaire ----
import threading as _threading

_LOGIN_MAX_FAILS = 5          # échecs tolérés avant verrouillage
_LOGIN_LOCK_SECONDS = 90      # durée du verrouillage
_login_lock = _threading.Lock()
_login_state = {}             # ip -> {"fails": int, "until": epoch, "seen": epoch}


def _client_ip() -> str:
    """IP du client, en tenant compte d'un éventuel reverse-proxy de confiance."""
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.remote_addr or "?"


def _login_locked_for(ip: str) -> float:
    """Secondes de verrouillage restantes pour cette IP (0 si non verrouillée)."""
    with _login_lock:
        entry = _login_state.get(ip)
        if not entry:
            return 0.0
        remaining = entry.get("until", 0) - time.time()
        return max(0.0, remaining)


def _login_register(ip: str, success: bool) -> None:
    """Met à jour le compteur d'échecs et purge les entrées trop anciennes."""
    now = time.time()
    with _login_lock:
        # Purge des IP inactives depuis longtemps (borne mémoire).
        for stale in [k for k, v in _login_state.items()
                      if now - v.get("seen", 0) > 3600]:
            _login_state.pop(stale, None)

        if success:
            _login_state.pop(ip, None)
            return

        entry = _login_state.setdefault(ip, {"fails": 0, "until": 0, "seen": now})
        entry["fails"] += 1
        entry["seen"] = now
        if entry["fails"] >= _LOGIN_MAX_FAILS:
            entry["until"] = now + _LOGIN_LOCK_SECONDS
            entry["fails"] = 0


@app.route("/api/auth/status")
def api_auth_status():
    """État d'authentification (public) : consommé au chargement du SPA."""
    authed = (not AUTH.enabled) or bool(session.get("authenticated"))
    return jsonify({
        "ok": True,
        "auth_enabled": AUTH.enabled,
        "authenticated": authed,
        "csrf": session.get("csrf") if authed else None,
    })


@app.route("/api/auth/login", methods=["POST"])
def api_auth_login():
    """Établit une session après vérification du mot de passe."""
    if not AUTH.enabled:
        return jsonify({"ok": True, "authenticated": True, "csrf": None})

    ip = _client_ip()
    locked = _login_locked_for(ip)
    if locked > 0:
        DB.audit("AUTH", f"Connexion bloquée (verrou anti-bruteforce) depuis {ip}")
        return jsonify({
            "ok": False,
            "error": f"Trop de tentatives. Réessayez dans {int(locked)} s.",
        }), 429

    payload = request.get_json(silent=True) or {}
    password = payload.get("password", "")

    if AUTH.verify_password(password):
        _login_register(ip, success=True)
        session.clear()
        session["authenticated"] = True
        session["csrf"] = AUTH.new_csrf_token()
        session.permanent = True
        DB.audit("AUTH", f"Connexion réussie à la console depuis {ip}")
        return jsonify({"ok": True, "csrf": session["csrf"]})

    # Échec : petite temporisation + comptage par IP (verrouillage au seuil).
    _login_register(ip, success=False)
    time.sleep(0.6)
    DB.audit("AUTH", f"Tentative de connexion refusée depuis {ip}")
    return jsonify({"ok": False, "error": "Mot de passe incorrect"}), 401


@app.route("/api/auth/logout", methods=["POST"])
def api_auth_logout():
    """Détruit la session courante."""
    session.clear()
    DB.audit("AUTH", "Déconnexion de la console")
    return jsonify({"ok": True})


# ==============================================================================
#  CONSTRUCTION DE L'ÉTAT (partagée par /api/state et le flux SSE)
# ==============================================================================

def build_state() -> dict:
    """
    Assemble l'instantané complet consommé par la console :
    inventaire enrichi, alertes, métriques, contexte réseau et réponse active.
    """
    devices = DB.all_devices()
    alerts = DB.all_alerts()

    # Enrichissement de présentation (icône/couleur de type, ancienneté).
    for device in devices:
        meta = config.ASSET_TYPES.get(device.get("asset_type", "unknown"),
                                      config.ASSET_TYPES["unknown"])
        device["type_icon"] = meta["icon"]
        device["type_color"] = meta["color"]
        device["type_label"] = device.get("type_label") or meta["label"]
        device["display_name"] = (device.get("label")
                                  or device.get("hostname")
                                  or device.get("ip")
                                  or device.get("mac"))
        device["first_seen_iso"] = iso(device.get("first_seen", 0))
        device["last_seen_iso"] = iso(device.get("last_seen", 0))
        device["alert_count"] = sum(
            1 for a in alerts
            if a.get("mac") == device.get("mac") and not a.get("acknowledged")
        )

    return {
        "ok": True,
        "server_time": iso(),
        "devices": devices,
        "alerts": alerts[:250],
        "metrics": DB.compute_metrics(),
        "timeline": DB.timeline_points(),
        "network": MONITOR.network_info(),
        "responder": RESPONDER.status(),
        "notifier": NOTIFIER.status(),
        "demo": config.DEMO_MODE,
        "privileged": is_privileged(),
        "asset_types": config.ASSET_TYPES,
        "app": {
            "name": config.APP_NAME,
            "edition": config.APP_EDITION,
            "version": config.APP_VERSION,
            "codename": config.APP_CODENAME,
        },
    }


# ==============================================================================
#  DIFFUSEUR TEMPS RÉEL (un seul producteur, N consommateurs)
# ==============================================================================

class StateBroadcaster:
    """
    Calcule l'instantané de l'état UNE SEULE FOIS par intervalle, dans un fil
    dédié, et le diffuse à tous les clients SSE connectés.

    Sans ce diffuseur, chaque client recalculait et re-sérialisait l'état
    complet à sa propre cadence : coût = N clients × M actifs à chaque tick.
    Ici le coût de calcul est constant quel que soit le nombre de clients ;
    les connexions ne font que relayer une charge utile déjà prête.
    """

    def __init__(self, builder, interval: float, max_clients: int):
        self._builder = builder
        self._interval = max(0.5, float(interval))
        self._max_clients = max_clients
        self._payload = None           # dernière charge utile JSON (str)
        self._version = 0              # incrémenté à chaque nouveau calcul
        self._cond = _threading.Condition()
        self._clients = 0
        self._stop = _threading.Event()
        self._thread = None

    # -------------------------------------------------------------- CYCLE DE VIE
    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = _threading.Thread(
            target=self._loop, name="nw-broadcaster", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        with self._cond:
            self._cond.notify_all()

    def _loop(self):
        while not self._stop.is_set():
            try:
                payload = json.dumps(self._builder(), ensure_ascii=False)
                with self._cond:
                    self._payload = payload
                    self._version += 1
                    self._cond.notify_all()
            except Exception:                # pragma: no cover
                pass
            self._stop.wait(self._interval)

    # ------------------------------------------------------------------ CLIENTS
    @property
    def client_count(self) -> int:
        return self._clients

    def stream(self):
        """Générateur SSE pour un client : relaie la charge utile partagée."""
        # Le producteur tourne dès qu'il y a au moins un client.
        self.start()

        with self._cond:
            if self._clients >= self._max_clients:
                yield ("event: error\ndata: "
                       "{\"error\":\"Trop de clients temps réel connectés\"}\n\n")
                return
            self._clients += 1

        last_version = -1
        try:
            yield "retry: 3000\n\n"       # délai de reconnexion navigateur
            while not self._stop.is_set():
                with self._cond:
                    got = self._cond.wait_for(
                        lambda: self._version != last_version,
                        timeout=self._interval * 3,
                    )
                    payload = self._payload if got else None
                    if got:
                        last_version = self._version
                if payload is not None:
                    yield f"data: {payload}\n\n"
                else:
                    yield ": keepalive\n\n"   # maintient la connexion ouverte
        except GeneratorExit:
            pass
        finally:
            with self._cond:
                self._clients = max(0, self._clients - 1)


BROADCASTER = StateBroadcaster(build_state, config.STREAM_INTERVAL,
                               config.MAX_STREAM_CLIENTS)


# ==============================================================================
#  ROUTES — API D'ÉTAT
# ==============================================================================

@app.route("/api/state")
def api_state():
    """Instantané complet, en un seul appel (chargement initial et repli)."""
    return jsonify(build_state())


@app.route("/api/stream")
def api_stream():
    """
    Flux temps réel Server-Sent Events, alimenté par le diffuseur partagé.

    Choix SSE (plutôt que WebSocket) : diffusion unidirectionnelle serveur →
    console, reconnexion automatique du navigateur, aucun serveur asynchrone.
    """
    return Response(
        stream_with_context(BROADCASTER.stream()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",       # désactive le tampon d'un proxy nginx
        },
    )


@app.route("/api/arp-table")
def api_arp_table():
    """Table d'associations IP↔MAC observées par le moteur de corrélation."""
    return jsonify({"ok": True, "bindings": MONITOR.snapshot_bindings()})


@app.route("/api/device/<mac>")
def api_device_detail(mac):
    """Fiche détaillée d'un actif (panneau d'investigation)."""
    device = DB.get_device(mac)
    if not device:
        return jsonify({"ok": False, "error": "Actif introuvable"}), 404
    related = [a for a in DB.all_alerts() if a.get("mac") == device["mac"]]
    return jsonify({"ok": True, "device": device, "alerts": related[:50]})


# ==============================================================================
#  ROUTES — ACTIONS ANALYSTE
# ==============================================================================

@app.route("/api/device/<mac>", methods=["POST", "PATCH"])
def api_device_update(mac):
    """Renommage, classification manuelle, criticité, approbation, notes."""
    payload = request.get_json(silent=True) or {}
    record = DB.update_device_meta(
        mac,
        label=payload.get("label"),
        criticality=payload.get("criticality"),
        notes=payload.get("notes"),
        trusted=payload.get("trusted"),
        asset_type=payload.get("asset_type"),
    )
    if not record:
        return jsonify({"ok": False, "error": "Actif introuvable"}), 404
    return jsonify({"ok": True, "device": record})


@app.route("/api/device/<mac>/quarantine", methods=["POST"])
def api_device_quarantine(mac):
    """
    Isole un actif : blocage du trafic hôte↔actif sur le pare-feu LOCAL.

    Réponse défensive et réversible. NetWatch ne touche qu'à son propre
    pare-feu — aucune trame ARP forgée, aucun autre équipement configuré.
    """
    result = RESPONDER.quarantine(mac)
    return jsonify(result), (200 if result.get("ok") else 400)


@app.route("/api/device/<mac>/release", methods=["POST"])
def api_device_release(mac):
    """Lève la quarantaine d'un actif (retrait de la règle pare-feu)."""
    result = RESPONDER.release(mac)
    return jsonify(result), (200 if result.get("ok") else 400)


@app.route("/api/device/<mac>", methods=["DELETE"])
def api_device_delete(mac):
    """Purge un actif de l'inventaire (nettoyage d'un faux positif)."""
    if DB.forget_device(mac):
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "Actif introuvable"}), 404


@app.route("/api/alerts/<alert_id>/ack", methods=["POST"])
def api_alert_ack(alert_id):
    """Acquittement d'une alerte unitaire."""
    if DB.acknowledge(alert_id):
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "Alerte introuvable"}), 404


@app.route("/api/alerts/ack-all", methods=["POST"])
def api_alert_ack_all():
    """Acquittement de masse (fin de quart SOC)."""
    return jsonify({"ok": True, "count": DB.acknowledge_all()})


@app.route("/api/alerts/clear", methods=["POST"])
def api_alert_clear():
    """Purge complète du journal d'alertes."""
    return jsonify({"ok": True, "count": DB.clear_alerts()})


# ==============================================================================
#  ROUTES — CONTRÔLE DU MOTEUR
# ==============================================================================

@app.route("/api/control/<action>", methods=["POST"])
def api_control(action):
    """Démarrage, arrêt et balayage à la demande."""
    if action == "start":
        return jsonify({"ok": MONITOR.start(), "running": MONITOR.running})
    if action == "stop":
        return jsonify({"ok": MONITOR.stop(), "running": MONITOR.running})
    if action == "scan":
        MONITOR.request_scan()
        return jsonify({"ok": True, "queued": True})
    return jsonify({"ok": False, "error": "Action inconnue"}), 400


# ==============================================================================
#  ROUTES — EXPORT
# ==============================================================================

@app.route("/api/export/<fmt>")
def api_export(fmt):
    """Export de l'inventaire au format CSV ou JSON (rapport d'audit)."""
    devices = DB.all_devices()

    if fmt == "json":
        payload = json.dumps(
            {"generated_at": iso(), "devices": devices, "alerts": DB.all_alerts()},
            ensure_ascii=False, indent=2,
        )
        return Response(
            payload.encode("utf-8"),
            mimetype="application/json",
            headers={"Content-Disposition":
                     "attachment; filename=netwatch_inventaire.json"},
        )

    if fmt == "csv":
        buffer = io.StringIO()
        columns = ["mac", "ip", "hostname", "label", "vendor", "type_label",
                   "type_confidence", "criticality", "trusted", "online",
                   "risk_score", "first_seen_iso", "last_seen_iso", "open_ports"]
        writer = csv.writer(buffer, delimiter=";")
        writer.writerow(columns)
        for device in devices:
            device["first_seen_iso"] = iso(device.get("first_seen", 0))
            device["last_seen_iso"] = iso(device.get("last_seen", 0))
            writer.writerow([device.get(col, "") for col in columns])
        return Response(
            buffer.getvalue().encode("utf-8-sig"),
            mimetype="text/csv",
            headers={"Content-Disposition":
                     "attachment; filename=netwatch_inventaire.csv"},
        )

    return jsonify({"ok": False, "error": "Format non supporté"}), 400


# ==============================================================================
#  SERVICE DU FRONT-END (SPA React compilé)
# ==============================================================================

_MISSING_BUILD_HTML = """<!doctype html><html lang="fr"><head><meta charset="utf-8">
<title>NetWatch — build requis</title>
<style>body{{font-family:system-ui,sans-serif;background:#070a14;color:#e8eeff;
display:grid;place-items:center;height:100vh;margin:0}}
.card{{max-width:640px;padding:32px;border:1px solid #24314d;border-radius:14px;
background:#12182a}}code{{background:#0a0f1a;padding:2px 7px;border-radius:5px;
color:#00e5ff}}h1{{margin-top:0}}</style></head><body><div class="card">
<h1>Front-end non compilé</h1>
<p>L'interface React n'a pas encore été construite. Depuis le dossier
<code>frontend/</code>, lancez&nbsp;:</p>
<pre><code>npm install
npm run build</code></pre>
<p>Puis rechargez cette page. En développement, utilisez plutôt
<code>npm run dev</code> (port 5173) qui relaie l'API vers Flask.</p>
<p>L'API JSON, elle, est déjà active : <code>/api/state</code>.</p>
</div></body></html>"""


@app.route("/")
def index():
    """Sert l'application React compilée (ou un guide si le build manque)."""
    index_file = os.path.join(FRONTEND_DIST, "index.html")
    if os.path.exists(index_file):
        return send_from_directory(FRONTEND_DIST, "index.html")
    return Response(_MISSING_BUILD_HTML, mimetype="text/html")


@app.route("/<path:asset_path>")
def spa_assets(asset_path):
    """
    Sert les fichiers statiques du SPA (JS, CSS, favicon…). Toute route
    non-API et non-fichier retombe sur index.html (routage côté client).
    """
    if asset_path.startswith("api/"):
        return jsonify({"ok": False, "error": "Ressource introuvable"}), 404
    candidate = os.path.join(FRONTEND_DIST, asset_path)
    if os.path.isfile(candidate):
        return send_from_directory(FRONTEND_DIST, asset_path)
    # Repli SPA.
    index_file = os.path.join(FRONTEND_DIST, "index.html")
    if os.path.exists(index_file):
        return send_from_directory(FRONTEND_DIST, "index.html")
    return Response(_MISSING_BUILD_HTML, mimetype="text/html")


# ==============================================================================
#  GESTION D'ERREURS
# ==============================================================================

@app.errorhandler(404)
def not_found(_error):
    return jsonify({"ok": False, "error": "Ressource introuvable"}), 404


@app.errorhandler(500)
def server_error(error):                                     # pragma: no cover
    DB.audit("ERROR", f"HTTP 500 : {error}")
    return jsonify({"ok": False, "error": "Erreur interne"}), 500


# ==============================================================================
#  DÉMARRAGE
# ==============================================================================

# ------------------------------------------------------------------------------
# Couleurs terminal (ambiance « centre opérationnel de sécurité »)
# ------------------------------------------------------------------------------
# Les séquences ANSI sont activées sous Windows via colorama, et neutralisées
# automatiquement si la sortie est redirigée ou si NO_COLOR est défini.
_COLOR = True
try:
    import colorama
    try:
        colorama.just_fix_windows_console()   # colorama >= 0.4.6
    except AttributeError:                     # pragma: no cover
        colorama.init()
except Exception:                              # pragma: no cover
    _COLOR = os.name != "nt"

if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
    _COLOR = False

# Palette (codes 256 couleurs).
RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"; UNDER = "\033[4m"
CYAN = "\033[38;5;44m"; CYAN2 = "\033[38;5;51m"; BLUE = "\033[38;5;39m"
VIOLET = "\033[38;5;141m"; GREEN = "\033[38;5;46m"; RED = "\033[38;5;196m"
YELLOW = "\033[38;5;220m"; GREY = "\033[38;5;245m"; WHITE = "\033[97m"

_LEADW = 20


def col(text, *codes) -> str:
    """Enveloppe un texte de séquences ANSI (ou le renvoie brut si couleurs off)."""
    if not _COLOR or not codes:
        return str(text)
    return "".join(codes) + str(text) + RESET


def _line(label, value, *codes, glyph=None):
    """Affiche une ligne « label ......... valeur » alignée et colorée."""
    lead = f"{label} "
    lead = lead + "." * max(2, _LEADW - len(lead))
    mark = col(glyph, *codes) + " " if glyph else ""
    print("  " + col(lead, GREY) + " " + mark + col(value, *codes))


BANNER_ART = [
    r"   _  __    __  _      __     __      __",
    r"  / |/ /__ / /_| | /| / /__ _/ /_____/ /",
    r" /    / -_) __/| |/ |/ / _ `/ __/ __/ _ \ ",
    r"/_/|_/\__/\__/ |__/|__/\_,_/\__/\__/_//_/",
]
_BANNER_PALETTE = [CYAN2, CYAN, BLUE, VIOLET]


def _print_banner():
    print()
    for i, art_line in enumerate(BANNER_ART):
        print(col(art_line, _BANNER_PALETTE[min(i, len(_BANNER_PALETTE) - 1)], BOLD))
    print("  " + col(config.APP_EDITION, VIOLET, BOLD)
          + col("  ·  ", DIM)
          + col(f"v{config.APP_VERSION} « {config.APP_CODENAME} »", CYAN))
    print("  " + col("─" * 58, DIM))
    if config.DEMO_MODE:
        print("  " + col("★ MODE DÉMONSTRATION", VIOLET, BOLD)
              + col(" — données simulées, aucun accès réseau", GREY))

    # --- Contexte réseau -----------------------------------------------------
    _line("Interface", MONITOR.iface, WHITE)
    _line("IP locale", MONITOR.local_ip, CYAN2)
    _line("Passerelle", MONITOR.gateway_ip, CYAN2)
    _line("Plage surveillée",
          f"{MONITOR.cidr}  ({len(MONITOR.target_hosts)} hôtes)", WHITE)
    _line("Bases OUI", ", ".join(RESOLVER.backends()["engines"]), GREEN)

    # --- Réponse active ------------------------------------------------------
    if RESPONDER.backend_ok:
        _line("Réponse active", RESPONDER.backend_note, GREEN, glyph="●")
    else:
        _line("Réponse active", RESPONDER.backend_note, YELLOW, glyph="▲")

    # --- Authentification ----------------------------------------------------
    if not AUTH.enabled:
        _line("Authentification", "DÉSACTIVÉE (développement)", RED, glyph="✖")
    elif AUTH.generated_password:
        _line("Authentification", "ACTIVE", GREEN, glyph="●")
        _password_box(AUTH.generated_password)
    else:
        _line("Authentification", "ACTIVE (mot de passe configuré)", GREEN, glyph="●")

    # --- Privilèges ----------------------------------------------------------
    if is_privileged():
        _line("Privilèges", "OK", GREEN, glyph="●")
    else:
        _line("Privilèges", "INSUFFISANTS", RED, glyph="✖")

    # --- TLS -----------------------------------------------------------------
    if config.tls_enabled():
        _line("TLS", "ACTIF (HTTPS)", GREEN, glyph="●")
    else:
        _line("TLS", "désactivé (HTTP)", YELLOW, glyph="○")

    # --- Export SIEM ---------------------------------------------------------
    _notif = NOTIFIER.status()
    if _notif["enabled"]:
        _line("Export SIEM", ", ".join(_notif["sinks"]), GREEN, glyph="●")

    # --- Avertissements ------------------------------------------------------
    if not os.path.exists(os.path.join(FRONTEND_DIST, "index.html")):
        _warn("Front-end non compilé : cd frontend && npm install && npm run build")
    if not SCAPY_AVAILABLE:
        _warn(f"Scapy indisponible : {SCAPY_ERROR}")
    elif not is_privileged():
        _warn("Sans privilèges élevés, la capture ARP échouera.")
        print("      " + col("Windows : terminal « en tant qu'administrateur » + Npcap", DIM))
        print("      " + col("Linux   : sudo python app.py", DIM))

    print("  " + col("─" * 58, DIM))
    url = f"{_scheme()}://{config.HOST}:{config.PORT}"
    print("  " + col("▶ CONSOLE", GREEN, BOLD) + "  "
          + col(url, CYAN2, BOLD, UNDER))
    print()


def _password_box(password: str):
    """Encadré mettant en évidence le mot de passe généré."""
    inner = 56
    top = "┌" + "─" * inner + "┐"
    bot = "└" + "─" * inner + "┘"
    l1 = "  Aucun mot de passe configuré — mot de passe généré :"
    l3 = "  définissez NETWATCH_PASSWORD pour en fixer un stable"
    pw = f"      {password}"
    print("  " + col(top, YELLOW))
    print("  " + col("│", YELLOW) + col(f"{l1:<{inner}}", WHITE) + col("│", YELLOW))
    print("  " + col("│", YELLOW) + col(f"{pw:<{inner}}", YELLOW, BOLD) + col("│", YELLOW))
    print("  " + col("│", YELLOW) + col(f"{l3:<{inner}}", DIM) + col("│", YELLOW))
    print("  " + col(bot, YELLOW))


def _warn(message: str):
    print("  " + col("▲", YELLOW, BOLD) + " " + col(message, YELLOW))


def _scheme() -> str:
    return "https" if config.tls_enabled() else "http"


def _open_browser():                                         # pragma: no cover
    try:
        webbrowser.open(f"{_scheme()}://{config.HOST}:{config.PORT}")
    except Exception:
        pass


def main():
    _print_banner()
    DB.audit("BOOT", f"{config.APP_NAME} {config.APP_VERSION} démarré")

    # Mode démonstration : données simulées, aucun accès réseau. Sinon, moteur
    # de collecte ARP réel.
    if config.DEMO_MODE:
        DEMO.start()
    else:
        MONITOR.start()
    BROADCASTER.start()

    # Ouverture du navigateur (uniquement dans le processus principal Flask).
    if config.OPEN_BROWSER and (not config.DEBUG
                                or os.environ.get("WERKZEUG_RUN_MAIN") == "true"):
        Timer(1.2, _open_browser).start()

    print("  " + col("● SYSTÈME OPÉRATIONNEL", GREEN, BOLD)
          + col(" — supervision temps réel active", GREY))

    try:
        # En production, on privilégie Waitress (serveur WSGI robuste, multi-
        # threads) au serveur de développement de Flask. Waitress diffuse
        # correctement le flux SSE. On retombe sur Flask si Waitress est absent
        # ou si le mode debug est explicitement demandé.
        if config.tls_enabled():
            # Waitress ne gère pas le TLS nativement : on sert alors via le
            # serveur intégré (multi-thread) avec le contexte SSL. Pour une
            # charge élevée, placer plutôt un reverse-proxy TLS (nginx) devant
            # la version HTTP.
            _line("Serveur", "Flask + TLS (HTTPS)", GREEN, glyph="●"); print()
            app.run(host=config.HOST, port=config.PORT, debug=False,
                    threaded=True, use_reloader=False,
                    ssl_context=(config.TLS_CERT_FILE, config.TLS_KEY_FILE))
        elif not config.DEBUG:
            try:
                from waitress import serve
                _line("Serveur", "Waitress (production)", GREEN, glyph="●"); print()
                serve(app, host=config.HOST, port=config.PORT,
                      threads=config.SERVER_THREADS,
                      channel_timeout=120, ident="NetWatch")
            except ImportError:
                _line("Serveur", "Flask (dev — Waitress absent)", YELLOW, glyph="▲"); print()
                app.run(host=config.HOST, port=config.PORT, debug=False,
                        threaded=True, use_reloader=False)
        else:
            app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG,
                    threaded=True, use_reloader=False)
    except KeyboardInterrupt:
        pass
    finally:
        print("\n  " + col("■ Arrêt en cours…", YELLOW, BOLD))
        # Lève les quarantaines pour ne pas laisser de règles pare-feu
        # orphelines qui bloqueraient encore des actifs après l'arrêt.
        if config.RELEASE_QUARANTINE_ON_EXIT:
            released = RESPONDER.release_all()
            if released:
                print("  " + col(f"{released} quarantaine(s) levée(s).", GREY))
        BROADCASTER.stop()
        if config.DEMO_MODE:
            DEMO.stop()
        else:
            MONITOR.stop()
        DB.save_all()
        DB.audit("SHUTDOWN", "Arrêt propre de la plateforme")
        print("  " + col("● Inventaire et alertes sauvegardés. À bientôt.", GREEN) + "\n")


if __name__ == "__main__":
    sys.exit(main() or 0)
