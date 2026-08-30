/* ==========================================================================
   NetWatch Console — bandeau de diagnostic
   --------------------------------------------------------------------------
   Affiche le message de diagnostic le plus prioritaire (Scapy, privilèges,
   sniffer, pare-feu de réponse active…). Rien n'est rendu si tout va bien.
   ========================================================================== */

import type { AppState } from '../api/types';

interface Diag {
  level: 'critical' | 'warning' | 'info';
  message: string;
}

function diagnose(s: AppState, privileged: boolean): Diag | null {
  const { network, responder } = s;
  // En mode démonstration, les données sont simulées : on n'affiche aucun
  // avertissement Scapy/privilèges (non pertinents).
  if (s.demo || network.demo) {
    return {
      level: 'info',
      message:
        'Mode démonstration — données simulées, aucun accès réseau. ' +
        'Lancez sans --demo (en administrateur/root, avec Npcap) pour surveiller votre réseau réel.',
    };
  }
  if (!network.scapy) {
    return {
      level: 'critical',
      message: `Scapy est indisponible (${network.scapy_error ?? 'import impossible'}). Installez les dépendances : pip install -r requirements.txt`,
    };
  }
  if (!privileged) {
    return {
      level: 'critical',
      message:
        "Privilèges insuffisants : la capture ARP nécessite un lancement en administrateur (Windows, avec Npcap installé) ou en root (Linux/macOS). Sans cela, l'inventaire restera vide.",
    };
  }
  if (!network.sniffer && network.running) {
    return {
      level: 'warning',
      message:
        "Le sniffer passif est inactif : la détection temps réel de l'empoisonnement ARP est dégradée. Seul le balayage actif fonctionne.",
    };
  }
  if (network.last_error) {
    return { level: 'warning', message: network.last_error };
  }
  if (responder.enabled && !responder.backend_ok) {
    return {
      level: 'warning',
      message: `Réponse active dégradée : ${responder.note}. Le bouton « Isoler » enregistrera la quarantaine mais ne bloquera rien.`,
    };
  }
  return null;
}

export function SysBar({ snapshot }: { snapshot: AppState }) {
  const diag = diagnose(snapshot, snapshot.privileged);
  if (!diag) return null;
  return (
    <div className="sysbar" data-level={diag.level}>
      <span className="sysbar__ico" aria-hidden="true">{diag.level === 'info' ? '★' : '⚠'}</span>
      <span>{diag.message}</span>
    </div>
  );
}
