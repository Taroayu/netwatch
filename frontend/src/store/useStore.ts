/* ==========================================================================
   NetWatch Console — état applicatif global (Zustand)
   --------------------------------------------------------------------------
   Un magasin unique et minimal :
     • `snapshot`  : dernier instantané reçu du backend (via SSE) ;
     • `connected` : état du flux temps réel ;
     • préférences d'affichage (tri, filtres, recherche, modale) ;
     • file de notifications (toasts).
   Séparer l'état serveur (snapshot) des préférences UI évite les rendus
   inutiles et garde la logique lisible.
   ========================================================================== */

import { create } from 'zustand';
import type { Alert, AppState, Device, Severity } from '../api/types';

/**
 * Recalcule côté client les métriques dépendant des alertes (pour un rendu
 * instantané après acquittement, sans attendre le prochain instantané SSE).
 * Reproduit fidèlement la logique du backend (compute_metrics).
 */
function withAlertMetrics(snap: AppState, alerts: Alert[]): AppState {
  const open = alerts.filter((a) => !a.acknowledged);
  const critical = open.filter((a) => a.severity === 'critical').length;
  const warning = open.filter((a) => a.severity === 'warning').length;
  const randomized = snap.metrics.randomized;
  const posture = Math.max(0, 100 - Math.min(100, critical * 30 + warning * 8 + randomized * 2));

  let level: Severity = 'secure';
  let label = 'RÉSEAU NOMINAL';
  if (critical) {
    level = 'critical';
    label = 'COMPROMISSION PROBABLE';
  } else if (warning) {
    level = 'warning';
    label = 'VIGILANCE RENFORCÉE';
  }

  const byMac: Record<string, number> = {};
  for (const a of open) if (a.mac) byMac[a.mac] = (byMac[a.mac] ?? 0) + 1;
  const devices = snap.devices.map((d) => ({ ...d, alert_count: byMac[d.mac] ?? 0 }));

  return {
    ...snap,
    alerts,
    devices,
    metrics: {
      ...snap.metrics,
      alerts_open: open.length,
      alerts_critical: critical,
      alerts_warning: warning,
      posture,
      threat_level: level,
      threat_label: label,
    },
  };
}

export type SortDir = 'asc' | 'desc';
export type StateFilter =
  | ''
  | 'online'
  | 'offline'
  | 'suspect'
  | 'untrusted'
  | 'new'
  | 'quarantined';
export type AlertFilter = '' | Severity | 'open';
export type ToastKind = 'ok' | 'warn' | 'error';

export interface Toast {
  id: number;
  kind: ToastKind;
  message: string;
}

interface StoreState {
  /* --- Authentification --- */
  authChecked: boolean;   // le statut initial a-t-il été récupéré ?
  authEnabled: boolean;
  authed: boolean;
  setAuth: (patch: Partial<{ authChecked: boolean; authEnabled: boolean; authed: boolean }>) => void;

  /* --- Données serveur --- */
  snapshot: AppState | null;
  connected: boolean;
  lastUpdate: number | null;
  setSnapshot: (snapshot: AppState) => void;
  setConnected: (connected: boolean) => void;

  /* --- Mises à jour optimistes (rendu instantané avant confirmation SSE) --- */
  ackAlertLocal: (id: string) => void;
  ackAllLocal: () => void;
  patchDeviceLocal: (mac: string, patch: Partial<Device>) => void;
  removeDeviceLocal: (mac: string) => void;

  /* --- Préférences d'affichage --- */
  sortKey: string;
  sortDir: SortDir;
  search: string;
  filterType: string;
  filterState: StateFilter;
  alertFilter: AlertFilter;
  setSort: (key: string) => void;
  setSearch: (value: string) => void;
  setFilterType: (value: string) => void;
  setFilterState: (value: StateFilter) => void;
  setAlertFilter: (value: AlertFilter) => void;

  /* --- Modale d'édition --- */
  modalMac: string | null;
  openModal: (mac: string) => void;
  closeModal: () => void;

  /* --- Notifications --- */
  toasts: Toast[];
  pushToast: (message: string, kind?: ToastKind) => void;
  dismissToast: (id: number) => void;
}

let toastSeq = 0;

export const useStore = create<StoreState>((set) => ({
  authChecked: false,
  authEnabled: true,
  authed: false,
  setAuth: (patch) => set(patch),

  snapshot: null,
  connected: false,
  lastUpdate: null,
  setSnapshot: (snapshot) => set({ snapshot, lastUpdate: Date.now() }),
  setConnected: (connected) => set({ connected }),

  ackAlertLocal: (id) =>
    set((s) => {
      if (!s.snapshot) return {};
      const now = new Date().toISOString();
      const alerts = s.snapshot.alerts.map((a) =>
        a.id === id && !a.acknowledged
          ? { ...a, acknowledged: true, acknowledged_at: now }
          : a,
      );
      return { snapshot: withAlertMetrics(s.snapshot, alerts) };
    }),
  ackAllLocal: () =>
    set((s) => {
      if (!s.snapshot) return {};
      const now = new Date().toISOString();
      const alerts = s.snapshot.alerts.map((a) =>
        a.acknowledged ? a : { ...a, acknowledged: true, acknowledged_at: now },
      );
      return { snapshot: withAlertMetrics(s.snapshot, alerts) };
    }),
  patchDeviceLocal: (mac, patch) =>
    set((s) => {
      if (!s.snapshot) return {};
      const devices = s.snapshot.devices.map((d) =>
        d.mac === mac ? { ...d, ...patch } : d,
      );
      return { snapshot: { ...s.snapshot, devices } };
    }),
  removeDeviceLocal: (mac) =>
    set((s) => {
      if (!s.snapshot) return {};
      const devices = s.snapshot.devices.filter((d) => d.mac !== mac);
      return { snapshot: { ...s.snapshot, devices } };
    }),

  sortKey: 'risk_score',
  sortDir: 'desc',
  search: '',
  filterType: '',
  filterState: '',
  alertFilter: '',
  setSort: (key) =>
    set((s) => {
      if (s.sortKey === key) {
        return { sortDir: s.sortDir === 'asc' ? 'desc' : 'asc' };
      }
      const ascFirst = ['display_name', 'ip', 'mac', 'vendor', 'type_label'];
      return { sortKey: key, sortDir: ascFirst.includes(key) ? 'asc' : 'desc' };
    }),
  setSearch: (search) => set({ search }),
  setFilterType: (filterType) => set({ filterType }),
  setFilterState: (filterState) => set({ filterState }),
  setAlertFilter: (alertFilter) => set({ alertFilter }),

  modalMac: null,
  openModal: (mac) => set({ modalMac: mac }),
  closeModal: () => set({ modalMac: null }),

  toasts: [],
  pushToast: (message, kind = 'ok') =>
    set((s) => ({ toasts: [...s.toasts, { id: ++toastSeq, kind, message }] })),
  dismissToast: (id) =>
    set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })),
}));
