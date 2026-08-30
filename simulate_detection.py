# -*- coding: utf-8 -*-
"""
================================================================================
 NetWatch Enterprise — simulate_detection.py
--------------------------------------------------------------------------------
 BANC DE TEST DE LA DÉTECTION  (validation de l'architecture de protection)

 ┌────────────────────────────────────────────────────────────────────────┐
 │  CE SCRIPT N'EST PAS UN OUTIL D'ATTAQUE.                                  │
 │                                                                          │
 │  Il n'émet AUCUNE trame sur le réseau. Il ne bloque, ne coupe et ne      │
 │  perturbe aucun appareil. Il se contente de fabriquer des paquets ARP    │
 │  synthétiques EN MÉMOIRE et de les passer directement aux fonctions de   │
 │  détection de NetWatch (le même chemin que le sniffer emprunte), afin de │
 │  vérifier que le moteur lève bien les bonnes alertes.                    │
 │                                                                          │
 │  Autrement dit : on teste l'IDS en lui présentant des entrées connues,  │
 │  comme un test unitaire — pas en attaquant un vrai réseau.               │
 │                                                                          │
 │  Aucun privilège n'est requis (rien n'est envoyé). Le script travaille  │
 │  dans un dossier de données temporaire et ne touche pas à ton inventaire │
 │  de production.                                                           │
 └────────────────────────────────────────────────────────────────────────┘

 Usage :
     python simulate_detection.py            # joue tous les scénarios
     python simulate_detection.py --list     # liste les scénarios
     python simulate_detection.py 2 4        # joue les scénarios 2 et 4
================================================================================
"""

import os
import sys
import tempfile

# --- Isolation : dossier de données jetable, sniffer et sondes désactivés -----
_TMP = tempfile.mkdtemp(prefix="netwatch_sim_")
os.environ.setdefault("NETWATCH_DATA_DIR", _TMP)
os.environ.setdefault("NETWATCH_ENABLE_SNIFFER", "0")
os.environ.setdefault("NETWATCH_ENABLE_PORT_PROBE", "0")
os.environ.setdefault("NETWATCH_ENABLE_REVERSE_DNS", "0")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config
from core.database import Database
from core.resolver import AssetResolver
from core.monitor import NetworkMonitor, SCAPY_AVAILABLE

try:
    from scapy.all import ARP, Ether
except Exception:                                            # pragma: no cover
    ARP = Ether = None


# ==============================================================================
#  ENVIRONNEMENT DE TEST
# ==============================================================================

# Topologie fictive du réseau simulé.
GATEWAY_IP = "192.168.10.1"
GATEWAY_MAC = "3c:5a:b4:aa:aa:aa"      # « vraie » passerelle (fabricant Google)
LOCAL_IP = "192.168.10.50"
LOCAL_MAC = "dc:a6:32:bb:bb:bb"        # poste de supervision
ATTACKER_MAC = "00:11:22:de:ad:01"     # carte de l'attaquant simulé


def build_engine():
    """Instancie le moteur SANS démarrer aucun thread réseau."""
    db = Database()
    resolver = AssetResolver()
    monitor = NetworkMonitor(db, resolver)
    # On force la topologie simulée (indépendante de la machine de test).
    monitor.gateway_ip = GATEWAY_IP
    monitor.gateway_mac = GATEWAY_MAC
    monitor.local_ip = LOCAL_IP
    monitor.local_mac = LOCAL_MAC
    # On amorce l'inventaire avec la passerelle légitime.
    monitor._process_scan_results([(GATEWAY_IP, GATEWAY_MAC), (LOCAL_IP, LOCAL_MAC)])
    return db, monitor


def make_arp(op, src_ip, src_mac, dst_ip=None, dst_mac="ff:ff:ff:ff:ff:ff"):
    """
    Fabrique un paquet ARP EN MÉMOIRE (jamais envoyé).

    op=1 : requête (who-has)     op=2 : réponse (is-at)
    """
    return Ether(src=src_mac, dst=dst_mac) / ARP(
        op=op, psrc=src_ip, hwsrc=src_mac,
        pdst=dst_ip or src_ip, hwdst=dst_mac,
    )


def alert_types_since(db, marker):
    """Types d'alertes apparus depuis un marqueur (id de la dernière alerte)."""
    types = []
    for alert in db.all_alerts():
        if alert["id"] == marker:
            break
        types.append(alert["type"])
    return types


# ==============================================================================
#  SCÉNARIOS
# ==============================================================================
# Chaque scénario reçoit (db, monitor), rejoue une séquence d'événements ARP
# et déclare le(s) type(s) d'alerte qu'il DOIT provoquer.

def scenario_gateway_impersonation(db, monitor):
    """L'attaquant se fait passer pour la passerelle (usurpation du défaut)."""
    # La passerelle est déjà connue avec sa vraie MAC ; l'attaquant annonce
    # maintenant « 192.168.10.1 est à MA carte ».
    monitor._record_binding(GATEWAY_IP, GATEWAY_MAC, source="sniff")
    monitor._on_arp_packet(make_arp(2, GATEWAY_IP, ATTACKER_MAC, LOCAL_IP, LOCAL_MAC))
    return {"gateway_impersonation"}


def scenario_host_poisoning(db, monitor):
    """Empoisonnement du cache pour un hôte quelconque (MITM ciblé)."""
    victim = "192.168.10.60"
    monitor._record_binding(victim, "b8:27:eb:00:00:60", source="sniff")
    monitor._on_arp_packet(make_arp(2, victim, ATTACKER_MAC, LOCAL_IP, LOCAL_MAC))
    return {"arp_poisoning"}


def scenario_multi_mac_same_ip(db, monitor):
    """Deux MAC revendiquent la même IP dans un même balayage."""
    ip = "192.168.10.70"
    monitor._process_scan_results([(ip, "a4:5e:60:00:00:70"),
                                   (ip, ATTACKER_MAC)])
    return {"arp_poisoning"}


def scenario_mac_multi_ip(db, monitor):
    """Une seule MAC répond pour plusieurs IP (position d'intercepteur)."""
    intruder = "00:11:22:de:ad:99"
    monitor._process_scan_results([
        ("192.168.10.81", intruder),
        ("192.168.10.82", intruder),
        ("192.168.10.83", intruder),
        ("192.168.10.84", intruder),
    ])
    return {"mac_multi_ip"}


def scenario_arp_flood(db, monitor):
    """Débit anormal de réponses ARP gratuites (outil d'empoisonnement)."""
    flooder_ip = "192.168.10.90"
    flooder_mac = "00:11:22:de:ad:f0"
    # On dépasse volontairement le seuil GRATUITOUS_ARP_RATE.
    for _ in range(config.GRATUITOUS_ARP_RATE + 5):
        monitor._on_arp_packet(make_arp(2, flooder_ip, flooder_mac))
    return {"arp_flood"}


def scenario_baseline_legit(db, monitor):
    """Trafic parfaitement légitime : NE DOIT lever AUCUNE alerte critique."""
    ip = "192.168.10.120"
    mac = "f0:18:98:00:01:20"
    monitor._process_scan_results([(ip, mac)])
    # Réannonce cohérente (même association) — comportement normal.
    monitor._on_arp_packet(make_arp(2, ip, mac))
    return set()   # aucune alerte critique/warning de poisoning attendue


SCENARIOS = [
    ("Usurpation de la passerelle",      scenario_gateway_impersonation),
    ("Empoisonnement d'un hôte (MITM)",  scenario_host_poisoning),
    ("Deux MAC pour une même IP",        scenario_multi_mac_same_ip),
    ("Une MAC pour plusieurs IP",        scenario_mac_multi_ip),
    ("Flood de réponses ARP",            scenario_arp_flood),
    ("Trafic légitime (contrôle)",       scenario_baseline_legit),
]

# Alertes considérées comme « signaux d'attaque » pour le scénario de contrôle.
ATTACK_ALERTS = {"gateway_impersonation", "arp_poisoning", "mac_multi_ip",
                 "arp_flood"}


# ==============================================================================
#  EXÉCUTION
# ==============================================================================

C_OK, C_KO, C_DIM, C_HEAD, C_RESET = (
    "\033[92m", "\033[91m", "\033[90m", "\033[96m", "\033[0m"
)


def run(indices):
    if not SCAPY_AVAILABLE or ARP is None:
        print(f"{C_KO}Scapy est requis pour fabriquer les paquets de test "
              f"(aucun n'est envoyé). Installez : pip install scapy{C_RESET}")
        return 1

    print(f"\n{C_HEAD}NetWatch — banc de test de la détection{C_RESET}")
    print(f"{C_DIM}Paquets synthétiques en mémoire — aucune trame émise sur "
          f"le réseau.{C_RESET}")
    print(f"{C_DIM}Dossier de données temporaire : {_TMP}{C_RESET}\n")

    passed = failed = 0

    for idx in indices:
        name, func = SCENARIOS[idx]
        # Moteur neuf par scénario : isolation totale, pas d'effet de bord.
        db, monitor = build_engine()
        marker = db.all_alerts()[0]["id"] if db.all_alerts() else None

        expected = func(db, monitor)
        fired = set(alert_types_since(db, marker))

        if idx == SCENARIOS.index(("Trafic légitime (contrôle)",
                                   scenario_baseline_legit)):
            # Le contrôle réussit s'il ne déclenche AUCUN signal d'attaque.
            unexpected = fired & ATTACK_ALERTS
            ok = not unexpected
            detail = ("aucune alerte d'attaque (correct)" if ok
                      else f"faux positif : {', '.join(sorted(unexpected))}")
        else:
            ok = expected.issubset(fired)
            got = ", ".join(sorted(fired & ATTACK_ALERTS)) or "rien"
            detail = f"attendu {sorted(expected)} → détecté : {got}"

        tag = f"{C_OK}✓ RÉUSSI{C_RESET}" if ok else f"{C_KO}✗ ÉCHEC {C_RESET}"
        print(f"  [{idx + 1}] {tag}  {name}")
        print(f"        {C_DIM}{detail}{C_RESET}")
        passed += ok
        failed += not ok

    print(f"\n  {C_HEAD}Bilan{C_RESET} : "
          f"{C_OK}{passed} réussi(s){C_RESET}, "
          f"{C_KO if failed else C_DIM}{failed} échec(s){C_RESET}\n")
    return 0 if failed == 0 else 2


def main():
    args = [a for a in sys.argv[1:] if a not in ("-h", "--help")]

    if "--list" in args:
        print("\nScénarios disponibles :")
        for i, (name, _) in enumerate(SCENARIOS):
            print(f"  {i + 1}. {name}")
        print()
        return 0

    if any(a in ("-h", "--help") for a in sys.argv[1:]):
        print(__doc__)
        return 0

    if args:
        try:
            indices = [int(a) - 1 for a in args]
            for i in indices:
                if not 0 <= i < len(SCENARIOS):
                    raise ValueError
        except ValueError:
            print("Argument invalide. Utilisez --list pour voir les scénarios.")
            return 1
    else:
        indices = list(range(len(SCENARIOS)))

    return run(indices)


if __name__ == "__main__":
    sys.exit(main())
