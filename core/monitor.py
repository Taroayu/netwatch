# -*- coding: utf-8 -*-
"""
================================================================================
 NetWatch Enterprise — core/monitor.py
--------------------------------------------------------------------------------
 Moteur de collecte et de détection.

 Architecture à trois fils d'exécution indépendants :

   [1] SCANNER ACTIF   — émet des requêtes ARP (who-has) sur toute la plage
                         locale à intervalle régulier, construit l'inventaire,
                         déclenche le typage d'actifs et la sonde de services.

   [2] SNIFFER PASSIF  — capture en continu le trafic ARP de la couche 2 et
                         détecte en temps réel les anomalies d'association
                         IP/MAC : empoisonnement de cache, usurpation de
                         passerelle, flood de réponses gratuites.

   [3] SUPERVISEUR     — recalcule les états en ligne/hors ligne, alimente la
                         série temporelle du dashboard et purge les fenêtres
                         glissantes.

 Toute la détection repose sur un principe simple mais redoutablement efficace
 en environnement réel : une association IP ↔ MAC est censée être stable. Une
 mutation de cette association, hors renouvellement DHCP légitime, est la
 signature canonique d'une attaque de type Adversary-in-the-Middle (ARP
 spoofing / ARP cache poisoning — MITRE ATT&CK T1557.002).
================================================================================
"""

import ipaddress
import socket
import threading
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor

import config
from .database import Database, now_ts, iso

# ------------------------------------------------------------------------------
# Import Scapy — l'application doit démarrer même sans pilote de capture,
# afin d'afficher un diagnostic clair dans l'interface plutôt qu'une pile
# d'exceptions dans la console.
# ------------------------------------------------------------------------------
SCAPY_AVAILABLE = True
SCAPY_ERROR = None
try:
    from scapy.all import ARP, Ether, srp, sniff, conf, get_if_hwaddr
    conf.verb = 0
except Exception as exc:                                    # pragma: no cover
    SCAPY_AVAILABLE = False
    SCAPY_ERROR = str(exc)
    ARP = Ether = srp = sniff = conf = get_if_hwaddr = None


# ==============================================================================
#  STRUCTURE INTERNE : association IP ↔ MAC observée
# ==============================================================================

class Binding:
    """Association IP/MAC observée sur le fil, avec son historique."""

    __slots__ = ("ip", "mac", "first_seen", "last_seen", "hits")

    def __init__(self, ip, mac):
        self.ip = ip
        self.mac = mac
        self.first_seen = now_ts()
        self.last_seen = now_ts()
        self.hits = 1

    def touch(self):
        self.last_seen = now_ts()
        self.hits += 1


# ==============================================================================
#  MONITEUR RÉSEAU
# ==============================================================================

class NetworkMonitor:
    """Orchestrateur de la collecte ARP et du moteur de détection."""

    # ------------------------------------------------------------------ INIT
    def __init__(self, db: Database, resolver):
        self.db = db
        self.resolver = resolver

        self._stop_event = threading.Event()
        self._threads = []
        self._lock = threading.RLock()
        self._scan_now = threading.Event()

        # Table d'associations IP → Binding (vérité terrain du moteur).
        self.bindings = {}

        # Table inverse MAC → ensemble d'IP revendiquées.
        self.mac_to_ips = defaultdict(set)

        # Fenêtres glissantes de débit ARP par MAC (détection de flood).
        self.arp_rate = defaultdict(lambda: deque(maxlen=512))

        # Contexte réseau résolu au démarrage.
        self.iface = None
        self.local_ip = None
        self.local_mac = None
        self.gateway_ip = None
        self.gateway_mac = None
        self.cidr = None
        self.target_hosts = []

        self.running = False
        self.last_error = None
        self.sniffer_active = False
        self.demo = False          # positionné à True par le simulateur de démo

        self._detect_network()

    # =========================================================================
    #  DÉCOUVERTE DU CONTEXTE RÉSEAU
    # =========================================================================

    def _detect_network(self):
        """Résout interface, IP locale, passerelle et plage à surveiller."""
        try:
            # --- IP locale : socket UDP « sans envoi » vers une IP publique ---
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.connect(("8.8.8.8", 80))
                self.local_ip = sock.getsockname()[0]
            finally:
                sock.close()
        except Exception:
            self.local_ip = "127.0.0.1"

        if SCAPY_AVAILABLE:
            try:
                # conf.route.route("0.0.0.0") → (interface, ip_source, passerelle)
                iface, out_ip, gateway = conf.route.route("0.0.0.0")
                self.iface = config.NETWORK_INTERFACE or iface
                if out_ip and out_ip != "0.0.0.0":
                    self.local_ip = out_ip
                if gateway and gateway != "0.0.0.0":
                    self.gateway_ip = gateway
            except Exception as exc:
                self.last_error = f"Résolution de route impossible : {exc}"
            try:
                self.local_mac = Database.normalize_mac(get_if_hwaddr(self.iface))
            except Exception:
                self.local_mac = None

        # --- Plage à surveiller ------------------------------------------------
        try:
            if config.TARGET_NETWORK:
                network = ipaddress.ip_network(config.TARGET_NETWORK, strict=False)
            else:
                network = ipaddress.ip_network(f"{self.local_ip}/24", strict=False)
            self.cidr = str(network)
            hosts = list(network.hosts())
            # Garde-fou : on refuse de balayer plus de 4096 adresses.
            self.target_hosts = [str(h) for h in hosts[:4096]]
        except Exception as exc:
            self.cidr = None
            self.target_hosts = []
            self.last_error = f"Plage réseau invalide : {exc}"

        if not self.gateway_ip and self.cidr:
            # Repli heuristique : première adresse utilisable de la plage.
            self.gateway_ip = self.target_hosts[0] if self.target_hosts else None

    def network_info(self) -> dict:
        """Contexte réseau exposé au dashboard."""
        return {
            "interface": str(self.iface) if self.iface else "—",
            "local_ip": self.local_ip or "—",
            "local_mac": self.local_mac or "—",
            "gateway_ip": self.gateway_ip or "—",
            "gateway_mac": self.gateway_mac or "—",
            "cidr": self.cidr or "—",
            "host_count": len(self.target_hosts),
            "scapy": SCAPY_AVAILABLE,
            "scapy_error": SCAPY_ERROR,
            "sniffer": self.sniffer_active,
            "running": self.running,
            "last_error": self.last_error,
            "engines": self.resolver.backends()["engines"],
            "demo": self.demo,
        }

    # =========================================================================
    #  CYCLE DE VIE
    # =========================================================================

    def start(self):
        """Démarre les fils de collecte (idempotent)."""
        if self.running:
            return False
        self._stop_event.clear()
        self.running = True

        self._threads = [
            threading.Thread(target=self._scan_loop, name="nw-scanner", daemon=True),
            threading.Thread(target=self._supervisor_loop, name="nw-supervisor", daemon=True),
        ]
        if config.ENABLE_PASSIVE_SNIFFER and SCAPY_AVAILABLE:
            self._threads.append(
                threading.Thread(target=self._sniff_loop, name="nw-sniffer", daemon=True)
            )

        for thread in self._threads:
            thread.start()

        self.db.audit("ENGINE", f"Surveillance démarrée sur {self.cidr} "
                                f"(interface {self.iface})")
        self.db.add_alert("system", "Moteur de surveillance démarré",
                          f"Plage {self.cidr} — interface {self.iface}",
                          severity=config.SEV_INFO,
                          dedup_key=f"engine-start:{now_ts() // 60}")
        return True

    def stop(self):
        """Arrête proprement les fils de collecte."""
        if not self.running:
            return False
        self._stop_event.set()
        self.running = False
        self.sniffer_active = False
        self.db.audit("ENGINE", "Surveillance arrêtée")
        self.db.save_all()
        return True

    def request_scan(self):
        """Déclenche un balayage immédiat sans attendre le prochain cycle."""
        self._scan_now.set()

    # =========================================================================
    #  [1] BOUCLE DE SCAN ACTIF
    # =========================================================================

    def _scan_loop(self):
        while not self._stop_event.is_set():
            try:
                self.run_scan()
            except Exception as exc:                        # pragma: no cover
                self.last_error = f"Erreur de balayage : {exc}"
                self.db.audit("ERROR", self.last_error)
            # Attente interruptible : réactivité immédiate au bouton « Scanner ».
            self._scan_now.wait(timeout=config.SCAN_INTERVAL)
            self._scan_now.clear()

    def run_scan(self):
        """Exécute un balayage ARP complet et met à jour l'inventaire."""
        if not SCAPY_AVAILABLE or not self.target_hosts:
            return []

        started = now_ts()
        discovered = self._arp_sweep()
        duration = round(now_ts() - started, 2)

        self.db.stats["scan_count"] += 1
        self.db.stats["last_scan_at"] = iso()
        self.db.stats["last_scan_duration"] = duration

        self._process_scan_results(discovered)
        # Écriture debouncée : on marque l'inventaire modifié ; le superviseur
        # le persistera au prochain cycle (évite une réécriture complète du
        # fichier à chaque scan).
        self.db.mark_devices_dirty()
        return discovered

    def _arp_sweep(self):
        """
        Émet les requêtes ARP par lots et collecte les réponses.

        Retourne une liste de tuples (ip, mac) normalisés.
        """
        found = []
        batch_size = max(16, config.ARP_BATCH_SIZE)

        for index in range(0, len(self.target_hosts), batch_size):
            if self._stop_event.is_set():
                break
            batch = self.target_hosts[index:index + batch_size]
            try:
                packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=batch)
                answered, _ = srp(
                    packet,
                    timeout=config.ARP_TIMEOUT,
                    verbose=0,
                    iface=self.iface,
                    inter=0.002,
                )
                for _sent, received in answered:
                    ip = received.psrc
                    mac = Database.normalize_mac(received.hwsrc)
                    if mac and ip:
                        found.append((ip, mac))
            except Exception as exc:                        # pragma: no cover
                self.last_error = f"srp() a échoué : {exc}"
                self.db.audit("ERROR", self.last_error)
                break

        # L'hôte local ne répond jamais à ses propres requêtes ARP :
        # on l'injecte manuellement pour un inventaire exhaustif.
        if self.local_ip and self.local_mac:
            found.append((self.local_ip, self.local_mac))

        return found

    # ---------------------------------------------------------- TRAITEMENT
    def _process_scan_results(self, discovered):
        """Analyse un jeu de résultats de balayage : anomalies + inventaire."""
        by_ip = defaultdict(set)
        by_mac = defaultdict(set)
        for ip, mac in discovered:
            by_ip[ip].add(mac)
            by_mac[mac].add(ip)

        # --- Anomalie A : une IP répond avec plusieurs MAC ---------------------
        # C'est la signature la plus franche d'un empoisonnement en cours.
        for ip, macs in by_ip.items():
            if len(macs) > 1:
                listing = ", ".join(sorted(macs))
                severity_type = ("gateway_impersonation" if ip == self.gateway_ip
                                 else "arp_poisoning")
                self.db.add_alert(
                    severity_type,
                    f"Réponses ARP contradictoires pour {ip}",
                    f"{len(macs)} adresses MAC distinctes revendiquent {ip} : {listing}. "
                    f"Signature caractéristique d'une attaque Man-in-the-Middle.",
                    ip=ip,
                    dedup_key=f"multi-mac:{ip}",
                    evidence={"ip": ip, "macs": sorted(macs)},
                )

        # --- Anomalie B : une MAC revendique plusieurs IP ---------------------
        for mac, ips in by_mac.items():
            if mac == self.local_mac:
                continue
            if len(ips) >= config.MAC_MULTI_IP_THRESHOLD + 1:
                listing = ", ".join(sorted(ips))
                self.db.add_alert(
                    "mac_multi_ip",
                    f"L'adresse {mac} revendique {len(ips)} adresses IP",
                    f"IP concernées : {listing}. Un attaquant en position "
                    f"d'intercepteur répond typiquement pour plusieurs victimes.",
                    mac=mac,
                    dedup_key=f"multi-ip:{mac}",
                    evidence={"mac": mac, "ips": sorted(ips)},
                )

        # --- Mise à jour de l'inventaire --------------------------------------
        to_probe = []
        for ip, mac in discovered:
            record, is_new = self.db.upsert_device(mac, ip=ip)
            if record is None:
                continue

            self.db.mark_seen(mac)
            self._record_binding(ip, mac, source="scan")

            # Enrichissement : DNS inverse + typage.
            needs_enrich = (
                is_new
                or not record.get("type_label")
                or record.get("asset_type") == "unknown"
                or record.get("ip") != ip
                or now_ts() - record.get("_enriched_at", 0) > 900
            )
            if needs_enrich:
                to_probe.append((mac, ip, is_new))

            if is_new:
                self._on_new_device(record, ip, mac)

        # Enrichissement parallélisé (DNS + sonde TCP) : hors du chemin critique.
        if to_probe:
            self._enrich_batch(to_probe)

        # --- Mémorise la MAC de la passerelle (référence de confiance) ---------
        if self.gateway_ip and self.gateway_ip in by_ip:
            macs = by_ip[self.gateway_ip]
            if len(macs) == 1:
                candidate = next(iter(macs))
                if self.gateway_mac and candidate != self.gateway_mac:
                    self.db.add_alert(
                        "gateway_impersonation",
                        "Changement de l'adresse MAC de la passerelle",
                        f"La passerelle {self.gateway_ip} est passée de "
                        f"{self.gateway_mac} à {candidate}. Sauf remplacement "
                        f"matériel planifié, il s'agit d'une usurpation.",
                        ip=self.gateway_ip, mac=candidate,
                        dedup_key=f"gw-change:{self.gateway_ip}:{candidate}",
                        evidence={"previous": self.gateway_mac, "current": candidate},
                    )
                self.gateway_mac = candidate

    # ------------------------------------------------------------ NOUVEL ACTIF
    def _on_new_device(self, record, ip, mac):
        identity = self.resolver.identify(mac)
        self.db.add_alert(
            "new_device",
            f"Nouvel actif détecté : {ip}",
            f"MAC {mac} — fabricant identifié : {identity.vendor}. "
            f"Actif absent de l'inventaire de référence.",
            mac=mac, ip=ip,
            dedup_key=f"new:{mac}",
            evidence={"vendor": identity.vendor, "source": identity.source},
        )
        if identity.is_randomized:
            self.db.add_alert(
                "mac_randomized",
                f"Adresse MAC aléatoire sur {ip}",
                "Bit « localement administré » positionné : terminal mobile en "
                "mode anti-tracking, interface virtuelle, ou usurpation "
                "délibérée d'identité matérielle.",
                mac=mac, ip=ip,
                dedup_key=f"rand:{mac}",
            )

    # -------------------------------------------------------- ENRICHISSEMENT
    def _enrich_batch(self, targets):
        """Résout hostname + ports ouverts puis relance le typage."""
        workers = max(4, min(config.PORT_PROBE_WORKERS, len(targets) * 2))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            list(pool.map(lambda item: self._enrich_one(*item), targets))

    def _enrich_one(self, mac, ip, is_new):
        try:
            hostname = self.resolver.reverse_dns(ip)
            ports = self._probe_ports(ip) if config.ENABLE_PORT_PROBE else []
            classification = self.resolver.classify(
                mac, ip=ip, hostname=hostname, open_ports=ports,
                is_gateway=(ip == self.gateway_ip),
                is_local_host=(ip == self.local_ip),
            )
            classification["_enriched_at"] = now_ts()
            record, _ = self.db.upsert_device(mac, **classification)
            if record is not None:
                record["risk_score"] = self.resolver.risk_score(
                    record, self.db.all_alerts()
                )
        except Exception:                                    # pragma: no cover
            pass

    @staticmethod
    def _probe_ports(ip):
        """
        Sonde TCP « connect » ultra-légère sur un jeu réduit de ports.

        Non intrusive (aucun paquet malformé, aucun envoi de charge utile) :
        il s'agit d'une simple tentative d'établissement de session, comme le
        ferait n'importe quel client légitime.
        """
        open_ports = []
        for port in config.PROBE_PORTS:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(config.PORT_PROBE_TIMEOUT)
            try:
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
            except Exception:
                pass
            finally:
                try:
                    sock.close()
                except Exception:
                    pass
        return open_ports

    # =========================================================================
    #  [2] SNIFFER ARP PASSIF
    # =========================================================================

    def _sniff_loop(self):
        """
        Capture ARP en continu.

        La capture est découpée en tranches de quelques secondes afin que
        l'arrêt du service soit immédiat (sniff() n'est pas interruptible).
        """
        self.sniffer_active = True
        while not self._stop_event.is_set():
            try:
                sniff(
                    filter="arp",
                    prn=self._on_arp_packet,
                    store=0,
                    timeout=5,
                    iface=self.iface,
                )
            except Exception as exc:                        # pragma: no cover
                self.sniffer_active = False
                self.last_error = (
                    f"Capture passive indisponible ({exc}). "
                    f"Vérifiez Npcap/libpcap et les privilèges administrateur."
                )
                self.db.audit("ERROR", self.last_error)
                # On retente périodiquement plutôt que de tuer le fil.
                self._stop_event.wait(30)
        self.sniffer_active = False

    def _on_arp_packet(self, packet):
        """Callback appelé pour chaque trame ARP capturée."""
        try:
            if ARP not in packet:
                return
            arp = packet[ARP]
            self.db.stats["packets_seen"] += 1

            src_ip = arp.psrc
            src_mac = Database.normalize_mac(arp.hwsrc)
            if not src_ip or not src_mac or src_ip == "0.0.0.0":
                return
            if src_mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                return

            is_reply = (arp.op == 2)
            is_gratuitous = is_reply and arp.psrc == arp.pdst

            # Comptabilisation du débit (détection de flood).
            if is_reply:
                window = self.arp_rate[src_mac]
                window.append(now_ts())
                self._check_arp_flood(src_mac, src_ip, window)

            self._record_binding(src_ip, src_mac,
                                 source="gratuitous" if is_gratuitous else "sniff")
        except Exception:                                    # pragma: no cover
            pass

    # -------------------------------------------------- MOTEUR DE CORRÉLATION
    def _record_binding(self, ip, mac, source="sniff"):
        """
        Enregistre une association IP↔MAC et détecte les mutations suspectes.

        C'est le cœur de la détection d'ARP spoofing.
        """
        with self._lock:
            previous = self.bindings.get(ip)

            if previous is None:
                self.bindings[ip] = Binding(ip, mac)
                self.mac_to_ips[mac].add(ip)
                return

            if previous.mac == mac:
                previous.touch()
                self.mac_to_ips[mac].add(ip)
                return

            # --- Mutation d'association détectée ------------------------------
            age = now_ts() - previous.last_seen
            old_mac = previous.mac

            # Remplacement de l'association (l'observation la plus récente
            # fait foi pour la suite de la corrélation).
            self.bindings[ip] = Binding(ip, mac)
            self.mac_to_ips[mac].add(ip)
            self.mac_to_ips[old_mac].discard(ip)

            # Une association trop ancienne relève probablement d'un bail DHCP
            # renouvelé : on ne lève pas d'alerte pour limiter le bruit.
            if age > config.BINDING_CONFLICT_WINDOW:
                return

        # --- Qualification de l'alerte (hors verrou) --------------------------
        old_identity = self.resolver.identify(old_mac)
        new_identity = self.resolver.identify(mac)
        vendor_note = ""
        if old_identity.vendor != new_identity.vendor:
            vendor_note = (f" Le fabricant change également : "
                           f"« {old_identity.vendor} » → « {new_identity.vendor} ».")

        if ip == self.gateway_ip:
            self.db.add_alert(
                "gateway_impersonation",
                f"USURPATION DE PASSERELLE — {ip}",
                f"L'adresse MAC associée à la passerelle est passée de {old_mac} "
                f"à {mac} en {int(age)} s.{vendor_note} Tout le trafic sortant "
                f"peut être intercepté. Isoler l'hôte {mac} immédiatement.",
                ip=ip, mac=mac,
                dedup_key=f"gw-poison:{ip}:{mac}",
                evidence={"previous_mac": old_mac, "current_mac": mac,
                          "delta_seconds": int(age), "source": source},
            )
        else:
            self.db.add_alert(
                "arp_poisoning",
                f"Empoisonnement de cache ARP sur {ip}",
                f"L'association {ip} ↔ {old_mac} a été remplacée par "
                f"{ip} ↔ {mac} après seulement {int(age)} s.{vendor_note} "
                f"Trame observée : {source}.",
                ip=ip, mac=mac,
                dedup_key=f"poison:{ip}:{mac}",
                evidence={"previous_mac": old_mac, "current_mac": mac,
                          "delta_seconds": int(age), "source": source},
            )

        # --- Corrélation secondaire : la MAC intercepte-t-elle plusieurs IP ? --
        with self._lock:
            claimed = set(self.mac_to_ips.get(mac, ()))
        if len(claimed) > config.MAC_MULTI_IP_THRESHOLD:
            self.db.add_alert(
                "mac_multi_ip",
                f"{mac} usurpe {len(claimed)} adresses IP",
                "Une même carte réseau répond pour plusieurs hôtes du segment : "
                "position d'intercepteur confirmée. IP revendiquées : "
                + ", ".join(sorted(claimed)[:12]),
                mac=mac,
                dedup_key=f"multi-ip-live:{mac}",
                evidence={"ips": sorted(claimed)},
            )

    def _check_arp_flood(self, mac, ip, window):
        """Détecte un débit anormal de réponses ARP (outil d'empoisonnement)."""
        cutoff = now_ts() - config.ARP_RATE_WINDOW
        while window and window[0] < cutoff:
            window.popleft()
        if len(window) >= config.GRATUITOUS_ARP_RATE:
            self.db.add_alert(
                "arp_flood",
                f"Débit ARP anormal depuis {mac}",
                f"{len(window)} réponses ARP en {config.ARP_RATE_WINDOW} s "
                f"(seuil : {config.GRATUITOUS_ARP_RATE}). Comportement typique "
                f"d'un outil d'empoisonnement automatisé (ettercap, bettercap, "
                f"arpspoof) maintenant sa position par réémission continue.",
                mac=mac, ip=ip,
                dedup_key=f"flood:{mac}",
                evidence={"rate": len(window), "window": config.ARP_RATE_WINDOW},
            )

    # =========================================================================
    #  [3] SUPERVISEUR
    # =========================================================================

    def _supervisor_loop(self):
        """Recalcule les états, alimente la série temporelle, purge les caches."""
        while not self._stop_event.is_set():
            try:
                for record, is_online in self.db.refresh_online_states():
                    if is_online:
                        self.db.add_alert(
                            "device_online",
                            f"Retour en ligne : {record.get('label') or record.get('ip')}",
                            f"{record.get('mac')} répond de nouveau aux requêtes ARP.",
                            mac=record.get("mac"), ip=record.get("ip"),
                            dedup_key=f"online:{record.get('mac')}",
                        )
                    else:
                        self.db.add_alert(
                            "device_offline",
                            f"Actif hors ligne : {record.get('label') or record.get('ip')}",
                            f"{record.get('mac')} est muet depuis plus de "
                            f"{config.OFFLINE_AFTER} s.",
                            mac=record.get("mac"), ip=record.get("ip"),
                            dedup_key=f"offline:{record.get('mac')}",
                        )

                # Recalcul des scores de risque (via l'API publique de la base,
                # sans manipuler son verrou interne).
                open_alerts = [a for a in self.db.all_alerts() if not a["acknowledged"]]
                self.db.update_risk_scores(self.resolver.risk_score, open_alerts)

                # Persistance debouncée de l'inventaire (au plus une écriture
                # par cycle du superviseur, et seulement si quelque chose a
                # changé).
                self.db.flush_devices()

                self.db.push_timeline_point()
            except Exception as exc:                        # pragma: no cover
                self.db.audit("ERROR", f"Superviseur : {exc}")
            self._stop_event.wait(10)

    # =========================================================================
    #  ÉTAT CONSOLIDÉ
    # =========================================================================

    def snapshot_bindings(self) -> list:
        """Table d'associations IP↔MAC observées (vue « ARP table » du SOC)."""
        with self._lock:
            return sorted(
                [
                    {
                        "ip": b.ip,
                        "mac": b.mac,
                        "hits": b.hits,
                        "first_seen": iso(b.first_seen),
                        "last_seen": iso(b.last_seen),
                    }
                    for b in self.bindings.values()
                ],
                key=lambda item: tuple(int(x) for x in item["ip"].split("."))
                if item["ip"].count(".") == 3 and item["ip"].replace(".", "").isdigit()
                else (0, 0, 0, 0),
            )
