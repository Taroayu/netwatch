# -*- coding: utf-8 -*-
"""
================================================================================
 NetWatch Enterprise — config.py
--------------------------------------------------------------------------------
 Configuration globale de l'application : chemins, intervalles, seuils de
 détection, taxonomie des actifs et bases de signatures utilisées par le moteur
 de résolution/typage.

 Toutes les valeurs sont surchargeables par variables d'environnement afin de
 permettre un déploiement multi-environnement (poste analyste, VM de labo,
 serveur de collecte) sans modifier le code.
================================================================================
"""

import os

# ==============================================================================
# 1. IDENTITÉ APPLICATIVE
# ==============================================================================

APP_NAME = "NetWatch"
APP_EDITION = "Enterprise / Pro-SecOps"
APP_VERSION = "3.0.0"
APP_CODENAME = "SENTINEL"


def _env(key: str, default):
    """Lecture d'une variable d'environnement typée d'après la valeur par défaut."""
    raw = os.environ.get(f"NETWATCH_{key}")
    if raw is None:
        return default
    if isinstance(default, bool):
        return raw.strip().lower() in ("1", "true", "yes", "on", "oui")
    if isinstance(default, int):
        try:
            return int(raw)
        except ValueError:
            return default
    if isinstance(default, float):
        try:
            return float(raw)
        except ValueError:
            return default
    return raw


# ==============================================================================
# 2. CHEMINS / PERSISTANCE
# ==============================================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Mode démonstration : données simulées, sans accès réseau (défini tôt car il
# change le dossier de données pour ne JAMAIS écraser un inventaire réel).
DEMO_MODE = _env("DEMO", False)

_DEFAULT_DATA = os.path.join(BASE_DIR, "data_demo" if DEMO_MODE else "data")
DATA_DIR = _env("DATA_DIR", _DEFAULT_DATA)

# Inventaire persistant des actifs connus (libellés, criticité, historique).
KNOWN_DEVICES_FILE = os.path.join(DATA_DIR, "known_devices.json")

# Journal des alertes de sécurité (persisté pour survivre aux redémarrages).
ALERTS_FILE = os.path.join(DATA_DIR, "alerts.json")

# Journal d'audit append-only (traçabilité SOC).
AUDIT_LOG_FILE = os.path.join(DATA_DIR, "netwatch_audit.log")

# Nombre maximum d'alertes conservées en base (rotation FIFO).
MAX_ALERTS = _env("MAX_ALERTS", 800)

# Nombre de points conservés pour les séries temporelles du dashboard.
TIMELINE_POINTS = _env("TIMELINE_POINTS", 60)


# ==============================================================================
# 3. RÉSEAU & CADENCE DE COLLECTE
# ==============================================================================

# Plage à scanner. Laisser vide («») pour auto-détection du /24 local.
TARGET_NETWORK = _env("TARGET_NETWORK", "")

# Interface Scapy à utiliser. Laisser vide pour la route par défaut.
NETWORK_INTERFACE = _env("IFACE", "")

# Intervalle entre deux balayages ARP actifs (secondes).
SCAN_INTERVAL = _env("SCAN_INTERVAL", 25)

# Délai d'attente des réponses ARP lors d'un balayage actif (secondes).
ARP_TIMEOUT = _env("ARP_TIMEOUT", 3)

# Taille des lots d'adresses envoyés par srp() — évite de saturer la pile réseau.
ARP_BATCH_SIZE = _env("ARP_BATCH_SIZE", 128)

# Délai (secondes) sans réponse au-delà duquel un actif est déclaré hors ligne.
OFFLINE_AFTER = _env("OFFLINE_AFTER", 180)

# Activation du sniffer ARP passif (détection temps réel de l'empoisonnement).
ENABLE_PASSIVE_SNIFFER = _env("ENABLE_SNIFFER", True)

# Activation de la sonde TCP légère (affinage du typage d'actifs).
ENABLE_PORT_PROBE = _env("ENABLE_PORT_PROBE", True)
PORT_PROBE_TIMEOUT = _env("PORT_PROBE_TIMEOUT", 0.45)
PORT_PROBE_WORKERS = _env("PORT_PROBE_WORKERS", 24)

# Activation de la résolution DNS inverse (hostname).
ENABLE_REVERSE_DNS = _env("ENABLE_REVERSE_DNS", True)
DNS_TIMEOUT = _env("DNS_TIMEOUT", 1.2)

# --- Réponse active (mise en quarantaine) -------------------------------------
# Autorise le bouton « Isoler » : NetWatch pose une règle sur le PARE-FEU LOCAL
# du poste de supervision pour couper le trafic entre lui et un actif suspect.
# NetWatch ne configure JAMAIS un autre équipement et n'émet JAMAIS d'ARP forgé.
# Mettre à 0 (NETWATCH_ENABLE_RESPONSE=0) pour une posture strictement passive.
ENABLE_ACTIVE_RESPONSE = _env("ENABLE_RESPONSE", True)

# Lever automatiquement toutes les quarantaines à l'arrêt du service ?
# Recommandé : évite de laisser des règles pare-feu orphelines après un crash.
RELEASE_QUARANTINE_ON_EXIT = _env("RELEASE_ON_EXIT", True)


# ==============================================================================
# 4. SEUILS DU MOTEUR DE DÉTECTION
# ==============================================================================

# Nombre d'adresses IP simultanées pour une même MAC avant alerte
# (signature classique d'un attaquant en Man-in-the-Middle).
MAC_MULTI_IP_THRESHOLD = _env("MAC_MULTI_IP_THRESHOLD", 2)

# Nombre de réponses ARP gratuites par minute et par MAC avant alerte
# (signature d'un flood ARP / outil d'empoisonnement type ettercap, bettercap).
GRATUITOUS_ARP_RATE = _env("GRATUITOUS_ARP_RATE", 25)

# Fenêtre glissante d'analyse du débit ARP (secondes).
ARP_RATE_WINDOW = _env("ARP_RATE_WINDOW", 60)

# Anti-spam : durée minimale entre deux alertes identiques (secondes).
ALERT_COOLDOWN = _env("ALERT_COOLDOWN", 90)

# Un conflit d'association IP/MAC n'est retenu que si l'ancienne association
# a été observée il y a moins de N secondes (évite les faux positifs DHCP).
BINDING_CONFLICT_WINDOW = _env("BINDING_CONFLICT_WINDOW", 900)


# ==============================================================================
# 5. SERVEUR WEB
# ==============================================================================

HOST = _env("HOST", "127.0.0.1")
PORT = _env("PORT", 5000)
DEBUG = _env("DEBUG", False)

# Ouvre le navigateur au démarrage (désactivable via --no-browser).
OPEN_BROWSER = _env("OPEN_BROWSER", True)
# (DEMO_MODE est défini plus haut, section 2, car il modifie DATA_DIR.)


# ==============================================================================
# 5b. AUTHENTIFICATION & SESSION
# ==============================================================================
# NetWatch expose des actions sensibles (isoler un actif, arrêter le moteur,
# purger les alertes). L'accès est donc protégé par un mot de passe et une
# session signée, avec jeton anti-CSRF sur toutes les requêtes mutantes.

# Activation globale de l'authentification. La désactiver (0) n'est à réserver
# qu'à un poste de développement isolé.
AUTH_ENABLED = _env("AUTH_ENABLED", True)

# Mot de passe de la console. S'il est laissé vide, NetWatch en génère un
# aléatoire à chaque démarrage et l'affiche dans la console (aucun mot de passe
# par défaut n'est jamais utilisé).
AUTH_PASSWORD = _env("PASSWORD", "")

# Clé de signature des sessions. Vide = générée puis persistée dans DATA_DIR
# (les sessions survivent alors aux redémarrages).
SECRET_KEY = _env("SECRET_KEY", "")
SECRET_KEY_FILE = os.path.join(DATA_DIR, "secret.key")

# Durée de validité d'une session (heures).
SESSION_HOURS = _env("SESSION_HOURS", 12)

# Cookie « Secure » : à activer lorsque la console est servie en HTTPS
# (sinon le cookie ne serait pas émis sur une connexion http locale).
# Laissé vide (None) => auto : activé dès que le TLS est configuré.
_COOKIE_SECURE_RAW = os.environ.get("NETWATCH_COOKIE_SECURE")

# --- TLS / HTTPS --------------------------------------------------------------
# Chemins du certificat et de la clé privée. S'ils sont renseignés (et que les
# fichiers existent), la console est servie en HTTPS. Un certificat auto-signé
# peut être généré via `python tools/generate_cert.py`.
TLS_CERT_FILE = _env("TLS_CERT", "")
TLS_KEY_FILE = _env("TLS_KEY", "")


def tls_enabled() -> bool:
    """Vrai si un certificat ET une clé valides sont configurés."""
    return bool(TLS_CERT_FILE and TLS_KEY_FILE
                and os.path.exists(TLS_CERT_FILE) and os.path.exists(TLS_KEY_FILE))


# Résolution finale du cookie Secure : choix explicite, sinon auto d'après TLS.
if _COOKIE_SECURE_RAW is not None:
    SESSION_COOKIE_SECURE = _COOKIE_SECURE_RAW.strip().lower() in (
        "1", "true", "yes", "on", "oui")
else:
    SESSION_COOKIE_SECURE = tls_enabled()

# --- Rotation du journal d'audit ---------------------------------------------
# Taille maximale d'un fichier d'audit avant rotation, et nombre d'archives.
AUDIT_MAX_BYTES = _env("AUDIT_MAX_BYTES", 5 * 1024 * 1024)   # 5 Mo
AUDIT_BACKUPS = _env("AUDIT_BACKUPS", 5)


# ==============================================================================
# 5c. EXPORT D'ALERTES (intégration SIEM)
# ==============================================================================
# NetWatch peut transmettre chaque nouvelle alerte à des systèmes externes.
# Tout est optionnel et best-effort (envoi non bloquant dans un fil dédié).

# Sévérité minimale déclenchant un envoi : "info", "warning" ou "critical".
NOTIFY_MIN_SEVERITY = _env("NOTIFY_MIN_SEVERITY", "warning")

# Webhook générique : reçoit un POST JSON par alerte (Slack/Teams/n8n/SIEM…).
WEBHOOK_URL = _env("WEBHOOK_URL", "")
WEBHOOK_TIMEOUT = _env("WEBHOOK_TIMEOUT", 4.0)

# Syslog (RFC 3164, UDP) : hôte/port d'un collecteur (ex. Graylog, rsyslog).
SYSLOG_HOST = _env("SYSLOG_HOST", "")
SYSLOG_PORT = _env("SYSLOG_PORT", 514)

# Cadence de rafraîchissement du front-end (millisecondes) — repli par sondage.
UI_REFRESH_MS = _env("UI_REFRESH_MS", 3000)

# Intervalle de poussée du flux temps réel Server-Sent Events (secondes).
STREAM_INTERVAL = _env("STREAM_INTERVAL", 2.0)

# Nombre maximal de clients temps réel simultanés. Chaque flux SSE mobilise un
# thread du serveur ; cette borne garantit qu'il reste toujours des threads
# disponibles pour l'API REST.
MAX_STREAM_CLIENTS = _env("MAX_STREAM_CLIENTS", 16)

# Nombre de threads du serveur de production (Waitress).
SERVER_THREADS = _env("SERVER_THREADS", 32)


# ==============================================================================
# 6. TAXONOMIE DES SÉVÉRITÉS
# ==============================================================================

SEV_CRITICAL = "critical"
SEV_WARNING = "warning"
SEV_INFO = "info"
SEV_SECURE = "secure"

SEVERITY_WEIGHT = {
    SEV_CRITICAL: 100,
    SEV_WARNING: 50,
    SEV_INFO: 10,
    SEV_SECURE: 0,
}


# ==============================================================================
# 7. TAXONOMIE DES ACTIFS
# ==============================================================================
# Chaque catégorie porte : libellé FR, icône (glyphe unicode, zéro dépendance),
# couleur d'accent utilisée par le front-end, et criticité métier par défaut.

ASSET_TYPES = {
    "gateway": {
        "label": "Passerelle / Routeur",
        "icon": "◈",
        "color": "#7c5cff",
        "criticality": "high",
    },
    "network": {
        "label": "Infrastructure réseau",
        "icon": "⬡",
        "color": "#8b7bff",
        "criticality": "high",
    },
    "server": {
        "label": "Serveur / NAS",
        "icon": "▤",
        "color": "#00d4ff",
        "criticality": "high",
    },
    "workstation_win": {
        "label": "Poste de travail Windows",
        "icon": "◰",
        "color": "#4da3ff",
        "criticality": "medium",
    },
    "workstation_mac": {
        "label": "Poste de travail Apple",
        "icon": "◔",
        "color": "#b0b8c9",
        "criticality": "medium",
    },
    "workstation_linux": {
        "label": "Poste de travail Linux",
        "icon": "◆",
        "color": "#ffb020",
        "criticality": "medium",
    },
    "mobile": {
        "label": "Périphérique mobile",
        "icon": "▯",
        "color": "#2ee6a8",
        "criticality": "low",
    },
    "printer": {
        "label": "Imprimante / MFP",
        "icon": "⎙",
        "color": "#9aa5b8",
        "criticality": "low",
    },
    "camera": {
        "label": "Caméra / Vidéosurveillance",
        "icon": "◉",
        "color": "#ff6b8b",
        "criticality": "high",
    },
    "iot": {
        "label": "IoT / Domotique",
        "icon": "✦",
        "color": "#ffd166",
        "criticality": "medium",
    },
    "media": {
        "label": "TV / Média / Console",
        "icon": "▶",
        "color": "#ff9f45",
        "criticality": "low",
    },
    "virtual": {
        "label": "Machine virtuelle / Conteneur",
        "icon": "❑",
        "color": "#6ee7ff",
        "criticality": "medium",
    },
    "unknown": {
        "label": "Actif non identifié",
        "icon": "❓",
        "color": "#64748b",
        "criticality": "medium",
    },
}


# ==============================================================================
# 8. BASE DE SIGNATURES CONSTRUCTEURS (typage par fabricant OUI)
# ==============================================================================
# Le fabricant réel est obtenu via manuf / mac-vendor-lookup (dizaines de
# milliers de préfixes). Cette table ne sert qu'à *classer* le fabricant obtenu
# dans une catégorie d'actif. Recherche par sous-chaîne, insensible à la casse.

VENDOR_SIGNATURES = [
    # --- Infrastructure réseau ------------------------------------------------
    ("network", [
        "cisco", "juniper", "arista", "mikrotik", "ubiquiti", "ubnt", "tp-link",
        "tplink", "netgear", "d-link", "dlink", "zyxel", "aruba", "ruckus",
        "extreme networks", "fortinet", "sonicwall", "watchguard", "pfsense",
        "netonix", "edgecore", "huawei technolog", "zte corporation",
        "sagemcom", "technicolor", "arcadyan", "avm gmbh", "freebox", "sercomm",
        "actiontec", "askey", "compal broadband", "hitron", "cambium",
        "alcatel-lucent", "adtran", "allied telesis", "brocade", "h3c",
        "ruijie", "tenda", "totolink", "engenius", "draytek", "peplink",
        "meraki", "openwrt", "eero", "linksys", "belkin", "buffalo.inc",
    ]),
    # --- Serveurs / NAS / stockage -------------------------------------------
    ("server", [
        "supermicro", "dell inc", "hewlett packard", "hp enterprise", "hpe",
        "ibm", "lenovo enterprise", "quanta", "inspur", "fujitsu", "nec ",
        "synology", "qnap", "western digital", "netapp", "asustor", "terramaster",
        "seagate", "buffalo", "drobo", "thecus", "tyan", "gigabyte technolog",
        "asrock rack", "intel corporate", "broadcom", "mellanox", "emulex",
        "hewlett-packard",
    ]),
    # --- Postes Apple ---------------------------------------------------------
    ("workstation_mac", [
        "apple",
    ]),
    # --- Postes / portables ---------------------------------------------------
    ("workstation_win", [
        "micro-star", "msi", "asustek", "acer", "toshiba", "clevo", "razer",
        "framework computer", "system76", "medion", "packard bell", "sony",
        "panasonic", "wistron", "pegatron", "compal electronics", "inventec",
        "foxconn", "hon hai", "liteon", "azurewave", "chicony", "elitegroup",
        "biostar", "colorful", "msi computer",
    ]),
    # --- Mobiles --------------------------------------------------------------
    ("mobile", [
        "samsung electro", "xiaomi", "oneplus", "oppo", "vivo mobile", "realme",
        "motorola mobility", "google, inc", "nothing technology", "honor device",
        "guangdong oppo", "shenzhen transsion", "tecno", "infinix", "wiko",
        "fairphone", "blackberry", "htc corporation", "lg electronics",
        "murata manufacturing", "sunitec", "shanghai wind", "meizu",
    ]),
    # --- Imprimantes ----------------------------------------------------------
    ("printer", [
        "brother", "canon", "epson", "seiko epson", "ricoh", "kyocera", "xerox",
        "lexmark", "oki electric", "sharp corporation", "konica minolta",
        "zebra technolog", "dymo", "star micronics", "toshiba tec",
    ]),
    # --- Caméras / vidéosurveillance -----------------------------------------
    ("camera", [
        "hangzhou hikvision", "hikvision", "dahua", "axis communication",
        "mobotix", "vivotek", "reolink", "amcrest", "foscam", "uniview",
        "arlo", "ring", "wyze", "eufy", "annke", "swann", "lorex", "tiandy",
        "geovision", "bosch security",
    ]),
    # --- IoT / domotique ------------------------------------------------------
    ("iot", [
        "espressif", "tuya", "sonoff", "itead", "shelly", "allterco",
        "philips lighting", "signify", "lifx", "nest labs", "ecobee", "netatmo",
        "somfy", "legrand", "schneider electric", "siemens", "honeywell",
        "tado", "aqara", "lumi united", "broadlink", "ikea of sweden",
        "sengled", "wemo", "raspberry pi", "arduino", "particle industries",
        "texas instruments", "nordic semiconductor", "silicon laborator",
        "seeed technolog", "u-blox", "telink", "realtek semiconductor",
        "amazon technolog", "withings", "fitbit", "garmin", "polar electro",
        "netvox", "heltec",
    ]),
    # --- Média / TV / consoles -----------------------------------------------
    ("media", [
        "roku", "sonos", "bose", "denon", "yamaha", "harman", "sonance",
        "nintendo", "sony interactive", "microsoft corporation", "vizio",
        "tcl technolog", "hisense", "skyworth", "loewe", "devialet", "chromecast",
        "sagem", "humax", "kaon", "dish network", "directv", "nvidia",
    ]),
]

# --- OUI de virtualisation (matériel non physique) ----------------------------
VIRTUAL_OUI = {
    "00:05:69": "VMware, Inc.",
    "00:0c:29": "VMware, Inc.",
    "00:1c:14": "VMware, Inc.",
    "00:50:56": "VMware, Inc.",
    "08:00:27": "Oracle VirtualBox",
    "0a:00:27": "Oracle VirtualBox (Host-Only)",
    "00:15:5d": "Microsoft Hyper-V",
    "00:03:ff": "Microsoft Virtual PC",
    "52:54:00": "QEMU / KVM",
    "00:16:3e": "Xen / Citrix Hypervisor",
    "00:1c:42": "Parallels Desktop",
    "02:42:ac": "Docker (bridge)",
    "00:0f:4b": "Oracle VM Server",
    "00:e0:4c": "Realtek (adaptateur virtuel fréquent)",
    "00:ff": "Adaptateur TAP/TUN Windows",
}

# --- Signatures de virtualisation par nom de fabricant ------------------------
VIRTUAL_VENDOR_HINTS = [
    "vmware", "virtualbox", "oracle vm", "qemu", "kvm", "xen", "parallels",
    "hyper-v", "docker", "proxmox", "nutanix", "citrix", "openstack", "bhyve",
]


# ==============================================================================
# 9. SIGNATURES PAR NOM D'HÔTE (DNS / NetBIOS / mDNS)
# ==============================================================================
# Appliquées après le fabricant : le hostname est souvent plus discriminant.

HOSTNAME_SIGNATURES = [
    ("gateway", ["gateway", "router", "livebox", "freebox", "bbox", "sfrbox",
                 "fritz.box", "openwrt", "pfsense", "opnsense", "_gw"]),
    ("network", ["switch", "ap-", "-ap", "accesspoint", "unifi", "wifi",
                 "repeater", "extender", "mesh"]),
    ("server", ["srv", "server", "nas", "esxi", "proxmox", "vcenter", "dc01",
                "ad-", "sql", "docker", "kube", "k8s", "synology", "diskstation",
                "qnap", "truenas", "unraid", "backup", "vault"]),
    ("workstation_win", ["desktop-", "laptop-", "pc-", "win-", "workstation"]),
    ("workstation_mac", ["macbook", "imac", "macmini", "macpro", "mac-",
                         "-mbp", "-mba"]),
    ("workstation_linux", ["ubuntu", "debian", "fedora", "archlinux", "linux",
                           "kali", "mint", "manjaro", "centos", "rocky"]),
    ("mobile", ["iphone", "ipad", "ipod", "android", "galaxy", "pixel",
                "redmi", "huawei-p", "oneplus", "-phone", "sm-"]),
    ("printer", ["printer", "imprimante", "brw", "npi", "hpprint", "epson",
                 "canon", "mfp", "scan"]),
    ("camera", ["cam", "ipcam", "camera", "doorbell", "nvr", "dvr", "hikvision",
                "dahua", "reolink"]),
    ("iot", ["esp", "shelly", "tasmota", "sonoff", "tuya", "hue", "bridge",
             "thermostat", "sensor", "plug", "switch-", "homeassistant",
             "raspberry", "raspberrypi", "pi-hole", "pihole"]),
    ("media", ["tv", "chromecast", "roku", "shield", "appletv", "firetv",
               "sonos", "playstation", "ps5", "ps4", "xbox", "switch-nx",
               "bravia", "samsungtv"]),
    ("virtual", ["vm-", "-vm", "virtual", "vbox", "hyperv", "lxc", "ct-"]),
]


# ==============================================================================
# 10. SIGNATURES COMPORTEMENTALES (ports TCP ouverts)
# ==============================================================================
# Sonde légère, non intrusive (connect scan sur un jeu réduit de ports).

PROBE_PORTS = [22, 23, 53, 80, 139, 443, 445, 515, 554, 631, 1883, 3389,
               5000, 5060, 8006, 8080, 8443, 9100, 32400]

PORT_SIGNATURES = {
    9100: ("printer", 60, "Port RAW/JetDirect"),
    515: ("printer", 55, "Protocole LPD"),
    631: ("printer", 45, "IPP/CUPS"),
    554: ("camera", 60, "Flux RTSP"),
    3389: ("workstation_win", 55, "Bureau à distance RDP"),
    445: ("workstation_win", 30, "Partage SMB"),
    139: ("workstation_win", 20, "NetBIOS"),
    22: ("server", 30, "SSH"),
    5000: ("server", 20, "Interface NAS"),
    8006: ("server", 55, "Console Proxmox"),
    32400: ("media", 55, "Serveur Plex"),
    1883: ("iot", 55, "Courtier MQTT"),
    53: ("network", 40, "Service DNS"),
    23: ("network", 25, "Telnet (héritage)"),
    5060: ("iot", 35, "Téléphonie SIP"),
    8443: ("network", 15, "Administration HTTPS"),
    8080: ("network", 10, "Administration HTTP"),
    80: ("iot", 5, "Interface web"),
    443: ("iot", 5, "Interface web sécurisée"),
}


# ==============================================================================
# 11. CATALOGUE DES TYPES D'ALERTES
# ==============================================================================

ALERT_TYPES = {
    "arp_poisoning": {
        "label": "Empoisonnement de cache ARP",
        "severity": SEV_CRITICAL,
        "mitre": "T1557.002 — Adversary-in-the-Middle: ARP Cache Poisoning",
    },
    "gateway_impersonation": {
        "label": "Usurpation de la passerelle",
        "severity": SEV_CRITICAL,
        "mitre": "T1557.002 — Adversary-in-the-Middle",
    },
    "mac_multi_ip": {
        "label": "MAC associée à plusieurs IP",
        "severity": SEV_CRITICAL,
        "mitre": "T1557.002 — Adversary-in-the-Middle",
    },
    "arp_flood": {
        "label": "Flood de réponses ARP gratuites",
        "severity": SEV_WARNING,
        "mitre": "T1498 — Network Denial of Service",
    },
    "new_device": {
        "label": "Nouvel actif détecté",
        "severity": SEV_WARNING,
        "mitre": "T1200 — Hardware Additions",
    },
    "mac_randomized": {
        "label": "Adresse MAC aléatoire / privée",
        "severity": SEV_INFO,
        "mitre": "T1036 — Masquerading",
    },
    "ip_conflict": {
        "label": "Conflit d'adressage IP",
        "severity": SEV_WARNING,
        "mitre": "—",
    },
    "device_offline": {
        "label": "Actif passé hors ligne",
        "severity": SEV_INFO,
        "mitre": "—",
    },
    "device_online": {
        "label": "Actif de retour en ligne",
        "severity": SEV_INFO,
        "mitre": "—",
    },
    "vendor_change": {
        "label": "Changement de fabricant sur une IP",
        "severity": SEV_WARNING,
        "mitre": "T1036 — Masquerading",
    },
    "quarantine": {
        "label": "Actif mis en quarantaine",
        "severity": SEV_WARNING,
        "mitre": "Réponse active — endiguement (containment)",
    },
    "quarantine_release": {
        "label": "Quarantaine levée",
        "severity": SEV_INFO,
        "mitre": "Réponse active — restauration",
    },
    "system": {
        "label": "Événement système",
        "severity": SEV_INFO,
        "mitre": "—",
    },
}
