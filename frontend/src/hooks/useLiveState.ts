/* ==========================================================================
   NetWatch Console — flux temps réel
   --------------------------------------------------------------------------
   Le backend pousse un instantané complet de l'état via Server-Sent Events
   (`/api/stream`). SSE est ici le bon choix — plus robuste qu'un WebSocket
   pour ce besoin :
     • le flux est unidirectionnel (serveur → console), exactement notre cas ;
     • reconnexion automatique native du navigateur en cas de coupure ;
     • transporté en HTTP simple, il traverse proxies et pare-feux sans
       négociation particulière ;
     • aucun serveur asynchrone dédié requis côté Flask.
   Les ACTIONS (isoler, acquitter, renommer…) restent, elles, de simples
   requêtes REST.

   Repli : si le navigateur ou l'environnement bloque SSE, on bascule
   automatiquement sur un sondage périodique de `/api/state`.
   ========================================================================== */

import { useEffect } from 'react';
import { fetchState } from '../api/client';
import { useStore } from '../store/useStore';
import type { AppState } from '../api/types';

const POLL_INTERVAL = 3000;
const SSE_GRACE = 6000; // délai avant de déclarer SSE défaillant

export function useLiveState(active: boolean): void {
  const setSnapshot = useStore((s) => s.setSnapshot);
  const setConnected = useStore((s) => s.setConnected);

  useEffect(() => {
    if (!active) return;                 // ne se connecte qu'une fois authentifié
    let source: EventSource | null = null;
    let pollTimer: number | null = null;
    let graceTimer: number | null = null;
    let gotFirstMessage = false;
    let disposed = false;

    const apply = (raw: string) => {
      try {
        const data = JSON.parse(raw) as AppState;
        if (!disposed) {
          setSnapshot(data);
          setConnected(true);
        }
      } catch {
        /* trame incomplète : ignorée, la suivante corrigera */
      }
    };

    const startPolling = () => {
      if (pollTimer !== null || disposed) return;
      const tick = async () => {
        try {
          const data = await fetchState();
          if (!disposed) {
            setSnapshot(data);
            setConnected(true);
          }
        } catch {
          if (!disposed) setConnected(false);
        }
      };
      void tick();
      pollTimer = window.setInterval(tick, POLL_INTERVAL);
    };

    const startStream = () => {
      try {
        source = new EventSource('/api/stream');
      } catch {
        startPolling();
        return;
      }

      source.onmessage = (event) => {
        gotFirstMessage = true;
        apply(event.data);
      };

      source.onerror = () => {
        setConnected(false);
        // Si aucun message n'est jamais arrivé, SSE est probablement bloqué :
        // on abandonne le flux et on passe au sondage.
        if (!gotFirstMessage) {
          source?.close();
          source = null;
          startPolling();
        }
        // Sinon, EventSource se reconnecte tout seul.
      };

      // Filet de sécurité : si rien n'est reçu dans le délai de grâce,
      // on démarre aussi le sondage (sans fermer le flux).
      graceTimer = window.setTimeout(() => {
        if (!gotFirstMessage) startPolling();
      }, SSE_GRACE);
    };

    startStream();

    return () => {
      disposed = true;
      source?.close();
      if (pollTimer !== null) window.clearInterval(pollTimer);
      if (graceTimer !== null) window.clearTimeout(graceTimer);
    };
  }, [active, setSnapshot, setConnected]);
}
