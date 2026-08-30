# -*- coding: utf-8 -*-
"""
================================================================================
 NetWatch Enterprise — core/resolver.py
--------------------------------------------------------------------------------
 Moteur d'identification et de typage des actifs.

 Deux étages :

   1) RÉSOLUTION FABRICANT (OUI)
      Interrogation d'une base locale de plusieurs dizaines de milliers de
      préfixes IEEE, via (par ordre de préférence) :
         a. `manuf`            — base Wireshark embarquée, 100 % hors-ligne
         b. `netaddr`          — registre IEEE complet embarqué dans le paquet
                                 (≈ 35 000 OUI + 4 500 IAB), 100 % hors-ligne,
                                 installation par roue binaire sans compilation
         c. `mac-vendor-lookup`— base IEEE mise en cache localement
         d. table de repli minimale embarquée (résilience totale)
      Au moins un backend hors-ligne est donc toujours disponible, y compris
      sur un poste totalement isolé du réseau Internet (air-gap).
      Le résolveur gère explicitement les cas particuliers qui faussent
      l'inventaire d'un SOC :
         - MAC localement administrées / aléatoires (anti-tracking iOS/Android)
         - MAC multicast / broadcast
         - matériel virtuel (VMware, VirtualBox, Hyper-V, QEMU, Xen, Docker…)

   2) TYPAGE INTELLIGENT DE L'ACTIF
      Moteur de score combinant trois sources de preuve indépendantes :
         - le fabricant OUI            (poids fort, mais faillible)
         - le nom d'hôte DNS/NetBIOS   (poids très fort quand présent)
         - les indices comportementaux (ports TCP ouverts, rôle de passerelle)
      Le résultat expose non seulement la catégorie retenue mais aussi le
      niveau de confiance et la liste des preuves — indispensable pour qu'un
      analyste puisse contester la classification.
================================================================================
"""

import asyncio
import inspect
import socket
import threading

import config

# ------------------------------------------------------------------------------
# Chargement opportuniste des bases OUI
# ------------------------------------------------------------------------------

def _await_if_needed(value):
    """
    Résout une valeur éventuellement asynchrone en contexte synchrone.

    Les versions récentes de `mac-vendor-lookup` exposent une API asyncio :
    `lookup()` / `load_vendors()` renvoient alors des *coroutines*. Appelées
    telles quelles depuis notre code synchrone, elles ne sont jamais attendues
    (« coroutine was never awaited ») et, pire, l'objet coroutine — toujours
    « vrai » — pouvait être renvoyé à la place du nom du fabricant.

    Ce sas exécute la coroutine dans une boucle jetable pour en récupérer le
    résultat, et garantit dans tous les cas qu'elle est consommée (aucun
    avertissement résiduel). Les valeurs déjà synchrones sont renvoyées telles
    quelles.
    """
    if not inspect.iscoroutine(value):
        return value
    try:
        return asyncio.run(value)
    except Exception:
        # Boucle déjà active, ou erreur d'exécution : on ferme proprement la
        # coroutine pour ne laisser aucun avertissement, et on abandonne ce
        # backend (netaddr / repli prennent le relais).
        try:
            value.close()
        except Exception:
            pass
        return None


_MANUF_PARSER = None
_MANUF_AVAILABLE = False
try:  # `manuf` embarque la base Wireshark : aucune connexion requise.
    try:
        from manuf import MacParser as _MacParser          # manuf >= 1.1
    except ImportError:                                     # pragma: no cover
        from manuf.manuf import MacParser as _MacParser     # manuf < 1.1
    _MANUF_PARSER = _MacParser()
    _MANUF_AVAILABLE = True
except Exception:                                           # pragma: no cover
    _MANUF_AVAILABLE = False

_NETADDR_EUI = None
_NETADDR_AVAILABLE = False
try:  # `netaddr` embarque le registre IEEE complet : hors-ligne, sans compilation.
    from netaddr import EUI as _NETADDR_EUI
    from netaddr.core import NotRegisteredError as _NotRegisteredError
    _NETADDR_AVAILABLE = True
except Exception:                                           # pragma: no cover
    _NETADDR_AVAILABLE = False
    _NotRegisteredError = Exception

_MACLOOKUP = None
_MACLOOKUP_ASYNC = None
_MACLOOKUP_AVAILABLE = False
try:
    from mac_vendor_lookup import MacLookup as _MacLookup
    _MACLOOKUP = _MacLookup()
    # IMPORTANT : le wrapper synchrone `MacLookup.lookup` exécute la coroutine
    # sur une UNIQUE boucle asyncio partagée (`self.loop.run_until_complete`).
    # Appelé depuis plusieurs threads (notre enrichissement est parallélisé),
    # il entre en conflit sur cette boucle, échoue, et laisse fuir la coroutine
    # interne (« coroutine AsyncMacLookup.lookup was never awaited »).
    # On pilote donc directement l'API ASYNCHRONE sous-jacente, chaque appel
    # utilisant sa propre boucle jetable via `_await_if_needed` (thread-safe).
    _MACLOOKUP_ASYNC = getattr(_MACLOOKUP, "async_lookup", None)
    try:
        _loader = _MACLOOKUP_ASYNC if _MACLOOKUP_ASYNC is not None else _MACLOOKUP
        _await_if_needed(_loader.load_vendors())
    except Exception:
        pass
    _MACLOOKUP_AVAILABLE = True
except Exception:                                           # pragma: no cover
    _MACLOOKUP_AVAILABLE = False


# ------------------------------------------------------------------------------
# Table de repli : utilisée uniquement si aucune bibliothèque n'est installée.
# ------------------------------------------------------------------------------

_FALLBACK_OUI = {
    "00:1a:11": "Google, Inc.", "3c:5a:b4": "Google, Inc.",
    "f4:f5:d8": "Google, Inc.", "d8:eb:46": "Google, Inc.",
    "00:1b:63": "Apple, Inc.", "a4:5e:60": "Apple, Inc.",
    "f0:18:98": "Apple, Inc.", "dc:a9:04": "Apple, Inc.",
    "ac:bc:32": "Apple, Inc.", "68:ab:1e": "Apple, Inc.",
    "00:16:6c": "Samsung Electronics", "5c:0a:5b": "Samsung Electronics",
    "8c:77:12": "Samsung Electronics", "e8:50:8b": "Samsung Electronics",
    "00:1d:0f": "TP-Link Technologies", "50:c7:bf": "TP-Link Technologies",
    "b0:be:76": "TP-Link Technologies", "a4:2b:b0": "TP-Link Technologies",
    "00:0c:42": "Routerboard / MikroTik", "48:8f:5a": "Routerboard / MikroTik",
    "00:1e:c2": "Apple, Inc.", "00:26:bb": "Apple, Inc.",
    "00:11:32": "Synology Incorporated", "00:08:9b": "ICP Electronics",
    "24:5e:be": "QNAP Systems, Inc.", "00:1c:c0": "Intel Corporate",
    "3c:97:0e": "Wistron InfoComm", "d4:6d:6d": "Intel Corporate",
    "b8:27:eb": "Raspberry Pi Foundation", "dc:a6:32": "Raspberry Pi Trading",
    "e4:5f:01": "Raspberry Pi Trading", "24:0a:c4": "Espressif Inc.",
    "84:f3:eb": "Espressif Inc.", "cc:50:e3": "Espressif Inc.",
    "00:17:88": "Philips Lighting BV", "ec:b5:fa": "Philips Lighting BV",
    "44:65:0d": "Amazon Technologies", "fc:65:de": "Amazon Technologies",
    "00:04:4b": "NVIDIA Corporation", "00:1f:a7": "Sony Interactive Ent.",
    "7c:bb:8a": "Nintendo Co., Ltd.", "00:50:f2": "Microsoft Corporation",
    "00:1d:d8": "Microsoft Corporation", "00:23:24": "G-PRO Computer",
    "00:90:4c": "Epigram / Broadcom", "00:1e:8f": "Canon Inc.",
    "00:80:77": "Brother Industries", "00:00:48": "Seiko Epson Corp.",
    "00:21:5a": "Hewlett Packard", "3c:d9:2b": "Hewlett Packard",
    "00:14:38": "Hewlett Packard", "d0:67:e5": "Dell Inc.",
    "18:66:da": "Dell Inc.", "00:1e:4f": "Dell Inc.",
    "00:0e:8f": "Cisco Systems", "00:1a:a1": "Cisco Systems",
    "d4:ca:6d": "Routerboard / MikroTik", "44:d9:e7": "Ubiquiti Networks",
    "fc:ec:da": "Ubiquiti Networks", "04:18:d6": "Ubiquiti Networks",
    "c0:56:e3": "Hangzhou Hikvision", "bc:ad:28": "Hangzhou Hikvision",
    "e0:50:8b": "Zhejiang Dahua Technology",
}


# ==============================================================================
#  RÉSULTAT DE RÉSOLUTION
# ==============================================================================

class MacIdentity:
    """Structure décrivant l'identité matérielle déduite d'une adresse MAC."""

    __slots__ = ("mac", "oui", "vendor", "source", "is_virtual",
                 "is_randomized", "is_multicast", "is_broadcast", "notes")

    def __init__(self, mac):
        self.mac = mac
        self.oui = mac[:8] if len(mac) >= 8 else mac
        self.vendor = "Fabricant inconnu"
        self.source = "none"
        self.is_virtual = False
        self.is_randomized = False
        self.is_multicast = False
        self.is_broadcast = False
        self.notes = []

    def as_dict(self):
        return {
            "mac": self.mac,
            "oui": self.oui,
            "vendor": self.vendor,
            "vendor_source": self.source,
            "is_virtual": self.is_virtual,
            "is_randomized": self.is_randomized,
            "notes": list(self.notes),
        }


# ==============================================================================
#  RÉSOLVEUR PRINCIPAL
# ==============================================================================

class AssetResolver:
    """
    Résolveur fabricant + moteur de typage d'actifs.

    Thread-safe et doté d'un cache mémoire : le typage est appelé à chaque
    cycle de scan pour tous les actifs, il doit rester très peu coûteux.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._vendor_cache = {}
        self._dns_cache = {}

    # -------------------------------------------------------------- BACKENDS
    @staticmethod
    def backends() -> dict:
        """État des bases OUI disponibles (affiché dans le bandeau système)."""
        names = []
        if _MANUF_AVAILABLE:
            names.append("manuf (OUI Wireshark)")
        if _NETADDR_AVAILABLE:
            names.append("netaddr (registre IEEE hors-ligne)")
        if _MACLOOKUP_AVAILABLE:
            names.append("mac-vendor-lookup (IEEE)")
        if not names:
            names.append("table de repli embarquée")
        return {
            "manuf": _MANUF_AVAILABLE,
            "netaddr": _NETADDR_AVAILABLE,
            "mac_vendor_lookup": _MACLOOKUP_AVAILABLE,
            "engines": names,
        }

    # ------------------------------------------------------- IDENTITÉ MATÉRIELLE
    def identify(self, mac: str) -> MacIdentity:
        """Résout le fabricant et les particularités d'une adresse MAC."""
        mac = (mac or "").lower()
        with self._lock:
            cached = self._vendor_cache.get(mac)
        if cached:
            return cached

        identity = MacIdentity(mac)

        try:
            first_octet = int(mac.split(":")[0], 16)
        except (ValueError, IndexError):
            first_octet = 0

        # --- Cas dégénérés --------------------------------------------------
        if mac in ("ff:ff:ff:ff:ff:ff",):
            identity.is_broadcast = True
            identity.vendor = "Diffusion (broadcast)"
            identity.source = "reserved"
            return self._cache(mac, identity)

        if first_octet & 0x01:
            identity.is_multicast = True
            identity.notes.append("Adresse multicast (bit I/G positionné)")

        # --- Matériel virtuel : test prioritaire ----------------------------
        for prefix, vendor in config.VIRTUAL_OUI.items():
            if mac.startswith(prefix):
                identity.vendor = vendor
                identity.source = "virtual-oui"
                identity.is_virtual = True
                identity.notes.append("Interface virtuelle / hyperviseur")
                return self._cache(mac, identity)

        # --- MAC localement administrée (bit U/L) ---------------------------
        # Signature des MAC aléatoires iOS 14+/Android 10+ (anti-tracking Wi-Fi)
        # et des interfaces logicielles (bridges, conteneurs, VPN).
        locally_administered = bool(first_octet & 0x02)

        # --- Interrogation des bases OUI ------------------------------------
        vendor, source = self._lookup_vendor(mac)
        if vendor:
            identity.vendor = vendor
            identity.source = source
            low = vendor.lower()
            if any(hint in low for hint in config.VIRTUAL_VENDOR_HINTS):
                identity.is_virtual = True
                identity.notes.append("Fabricant associé à de la virtualisation")

        if locally_administered:
            identity.is_randomized = True
            identity.notes.append(
                "Adresse localement administrée : MAC aléatoire (mode "
                "anti-tracking) ou usurpation possible"
            )
            if not vendor:
                identity.vendor = "MAC privée / aléatoire"
                identity.source = "locally-administered"

        if not vendor and not locally_administered:
            identity.vendor = "Fabricant inconnu"
            identity.source = "none"
            identity.notes.append("Préfixe OUI absent des bases consultées")

        return self._cache(mac, identity)

    def _cache(self, mac, identity):
        with self._lock:
            self._vendor_cache[mac] = identity
        return identity

    @staticmethod
    def _lookup_vendor(mac: str):
        """Consulte successivement les backends disponibles."""
        # 1) manuf — base Wireshark, hors-ligne, la plus riche.
        if _MANUF_AVAILABLE:
            try:
                vendor = _MANUF_PARSER.get_manuf_long(mac) or _MANUF_PARSER.get_manuf(mac)
                if vendor:
                    return vendor, "manuf"
            except Exception:
                pass
        # 2) netaddr — registre IEEE complet embarqué (OUI + IAB), hors-ligne.
        if _NETADDR_AVAILABLE:
            try:
                registration = _NETADDR_EUI(mac).oui.registration()
                organisation = getattr(registration, "org", None)
                if organisation is None and hasattr(registration, "get"):
                    organisation = registration.get("org")
                organisation = (organisation or "").strip()
                if organisation:
                    return organisation, "netaddr"
            except Exception:
                pass
        # 3) mac-vendor-lookup — base IEEE mise en cache.
        if _MACLOOKUP_AVAILABLE:
            try:
                # API asynchrone + boucle jetable par appel (cf. bloc d'import) :
                # évite la boucle partagée du wrapper synchrone, non thread-safe.
                target = _MACLOOKUP_ASYNC if _MACLOOKUP_ASYNC is not None else _MACLOOKUP
                vendor = _await_if_needed(target.lookup(mac))
                if isinstance(vendor, str) and vendor.strip():
                    return vendor.strip(), "mac-vendor-lookup"
            except Exception:
                pass
        # 4) table de repli embarquée.
        vendor = _FALLBACK_OUI.get(mac[:8])
        if vendor:
            return vendor, "fallback"
        return None, "none"

    # ----------------------------------------------------------- DNS INVERSE
    def reverse_dns(self, ip: str):
        """
        Résolution DNS inverse bornée dans le temps.

        Le hostname est la source de preuve la plus discriminante du moteur de
        typage ; on accepte donc un léger coût réseau, avec cache permanent.
        """
        if not config.ENABLE_REVERSE_DNS or not ip:
            return None
        with self._lock:
            if ip in self._dns_cache:
                return self._dns_cache[ip]

        hostname = None
        previous_timeout = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(config.DNS_TIMEOUT)
            hostname = socket.gethostbyaddr(ip)[0]
            # On retire le suffixe de domaine local, peu informatif.
            for suffix in (".local", ".lan", ".home", ".localdomain", ".home.arpa"):
                if hostname.lower().endswith(suffix):
                    hostname = hostname[: -len(suffix)]
                    break
        except Exception:
            hostname = None
        finally:
            socket.setdefaulttimeout(previous_timeout)

        with self._lock:
            self._dns_cache[ip] = hostname
        return hostname

    # =========================================================================
    #  MOTEUR DE TYPAGE D'ACTIFS
    # =========================================================================

    def classify(self, mac: str, ip: str = None, hostname: str = None,
                 open_ports=None, is_gateway: bool = False,
                 is_local_host: bool = False) -> dict:
        """
        Détermine la catégorie d'un actif par agrégation de preuves pondérées.

        Retourne un dictionnaire directement fusionnable dans l'inventaire.
        """
        identity = self.identify(mac)
        vendor_low = (identity.vendor or "").lower()
        host_low = (hostname or "").lower()
        open_ports = list(open_ports or [])

        scores = {}
        evidence = []

        def bump(category, points, reason):
            if category not in config.ASSET_TYPES:
                return
            scores[category] = scores.get(category, 0) + points
            evidence.append({"source": reason[0], "detail": reason[1],
                             "weight": points, "type": category})

        # ---- Preuve 1 : rôle réseau (déterministe, poids maximal) -----------
        if is_gateway:
            bump("gateway", 150, ("Topologie", "Adresse IP de la passerelle par défaut"))
        if is_local_host:
            bump("workstation_win", 40, ("Topologie", "Machine hébergeant la sonde NetWatch"))

        # ---- Preuve 2 : virtualisation --------------------------------------
        if identity.is_virtual:
            bump("virtual", 90, ("Matériel", f"OUI de virtualisation — {identity.vendor}"))

        # ---- Preuve 3 : fabricant OUI ---------------------------------------
        resolved_sources = ("manuf", "netaddr", "mac-vendor-lookup", "fallback",
                            "virtual-oui")
        if vendor_low and identity.source in resolved_sources:
            for category, keywords in config.VENDOR_SIGNATURES:
                for keyword in keywords:
                    if keyword in vendor_low:
                        bump(category, 60, ("Fabricant OUI", f"« {identity.vendor} »"))
                        break

        # ---- Preuve 4 : nom d'hôte (très discriminant) -----------------------
        if host_low:
            for category, keywords in config.HOSTNAME_SIGNATURES:
                for keyword in keywords:
                    if keyword in host_low:
                        bump(category, 85, ("Nom d'hôte", f"« {hostname} » contient « {keyword} »"))
                        break

        # ---- Preuve 5 : indices comportementaux (ports TCP) ------------------
        for port in open_ports:
            signature = config.PORT_SIGNATURES.get(port)
            if signature:
                category, weight, description = signature
                bump(category, weight, ("Service exposé", f"tcp/{port} — {description}"))

        # ---- Preuve 6 : MAC aléatoire → très probablement un mobile ---------
        if identity.is_randomized and not identity.is_virtual and not is_gateway:
            bump("mobile", 45, ("Matériel",
                                "MAC aléatoire : signature d'un terminal mobile "
                                "en mode anti-tracking"))

        # ---- Arbitrage -------------------------------------------------------
        if scores:
            ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
            asset_type, best = ranked[0]
            runner_up = ranked[1][1] if len(ranked) > 1 else 0

            # La confiance combine deux dimensions indépendantes :
            #   - la MARGE : à quel point la catégorie gagnante domine la
            #     suivante (une preuve unique donne une marge de 1,0) ;
            #   - la FORCE : le poids absolu des preuves accumulées (une
            #     bannière web seule ne vaut pas un OUI + un nom d'hôte).
            margin = best / (best + runner_up) if (best + runner_up) else 1.0
            strength = min(1.0, best / 100.0)
            confidence = int(min(99, 100 * margin * (0.40 + 0.60 * strength)))
            confidence = max(confidence, 10)
        else:
            asset_type = "unknown"
            confidence = 0
            evidence.append({"source": "Moteur", "detail": "Aucune preuve exploitable",
                             "weight": 0, "type": "unknown"})

        meta = config.ASSET_TYPES[asset_type]

        # ---- Drapeaux de posture --------------------------------------------
        flags = []
        if identity.is_randomized:
            flags.append("MAC_ALEATOIRE")
        if identity.is_virtual:
            flags.append("VIRTUEL")
        if identity.source == "none":
            flags.append("OUI_INCONNU")
        if is_gateway:
            flags.append("PASSERELLE")
        if not hostname:
            flags.append("SANS_NOM_DHOTE")

        return {
            "vendor": identity.vendor,
            "vendor_source": identity.source,
            "is_virtual": identity.is_virtual,
            "is_randomized": identity.is_randomized,
            "asset_type": asset_type,
            "type_label": meta["label"],
            "type_icon": meta["icon"],
            "type_color": meta["color"],
            "type_confidence": confidence,
            "type_evidence": evidence[:8],
            "criticality": meta["criticality"],
            "is_gateway": is_gateway,
            "is_local_host": is_local_host,
            "open_ports": open_ports,
            "flags": flags,
            "hostname": hostname,
        }

    # ---------------------------------------------------------- SCORE DE RISQUE
    @staticmethod
    def risk_score(device: dict, open_alerts: list) -> int:
        """
        Score de risque 0–100 par actif, consommé par la colonne « Risque ».

        Combine la posture intrinsèque (inconnu, non approuvé, MAC aléatoire,
        criticité métier) et les alertes ouvertes le concernant.
        """
        score = 0

        if not device.get("trusted"):
            score += 12
        if device.get("flags") and "OUI_INCONNU" in device["flags"]:
            score += 15
        if device.get("is_randomized"):
            score += 10
        if not device.get("hostname"):
            score += 5
        if device.get("criticality") == "high":
            score += 12
        elif device.get("criticality") == "critical":
            score += 20

        mac = device.get("mac")
        for alert in open_alerts:
            if alert.get("mac") != mac or alert.get("acknowledged"):
                continue
            if alert["severity"] == config.SEV_CRITICAL:
                score += 40
            elif alert["severity"] == config.SEV_WARNING:
                score += 15
            else:
                score += 4

        return max(0, min(100, score))
