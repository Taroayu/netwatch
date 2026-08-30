/* ==========================================================================
   NetWatch Console — contrat d'API typé
   --------------------------------------------------------------------------
   Ces types reflètent exactement la charge utile renvoyée par le backend
   Flask (`/api/state` et le flux `/api/stream`). Les avoir typés de bout en
   bout est précisément ce qui élimine la classe de bugs « champ mal orthographié
   / type inattendu » qui affecte le JavaScript écrit à la main.
   ========================================================================== */

export type Severity = 'critical' | 'warning' | 'info' | 'secure';
export type Criticality = 'low' | 'medium' | 'high' | 'critical';

/** Une preuve produite par le moteur de typage d'actifs. */
export interface TypeEvidence {
  source: string;
  detail: string;
  weight: number;
  type: string;
}

/** Une mutation d'adresse IP dans l'historique d'un actif. */
export interface IpHistoryEntry {
  ip: string;
  at: string;
}

/** Un actif de l'inventaire. */
export interface Device {
  mac: string;
  ip: string;
  hostname: string | null;
  vendor: string;
  vendor_source: string;
  asset_type: string;
  type_label: string;
  type_icon?: string;
  type_color?: string;
  type_confidence: number;
  type_evidence: TypeEvidence[];
  label: string | null;
  notes: string;
  criticality: Criticality;
  trusted: boolean;
  is_gateway: boolean;
  is_local_host: boolean;
  is_virtual: boolean;
  is_randomized: boolean;
  open_ports: number[];
  first_seen: number;
  last_seen: number;
  seen_count: number;
  ip_history: IpHistoryEntry[];
  online: boolean;
  risk_score: number;
  flags: string[];
  quarantined: boolean;
  quarantined_at: string | null;
  quarantine_enforced: boolean;
  /* Champs de présentation injectés par le backend. */
  display_name: string;
  first_seen_iso: string;
  last_seen_iso: string;
  alert_count: number;
}

/** Une alerte de sécurité. */
export interface Alert {
  id: string;
  ts: number;
  time: string;
  type: string;
  type_label: string;
  mitre: string;
  severity: Severity;
  title: string;
  detail: string;
  mac: string | null;
  ip: string | null;
  evidence: Record<string, unknown>;
  acknowledged: boolean;
  acknowledged_at: string | null;
}

/** Agrégats consommés par les tuiles KPI. */
export interface Metrics {
  total: number;
  online: number;
  offline: number;
  untrusted: number;
  virtual: number;
  randomized: number;
  new_24h: number;
  alerts_open: number;
  alerts_critical: number;
  alerts_warning: number;
  posture: number;
  threat_level: Severity;
  threat_label: string;
  distribution: Record<string, number>;
  scan_count: number;
  packets_seen: number;
  last_scan_at: string | null;
  last_scan_duration: number | null;
  uptime: number;
}

export interface TimelinePoint {
  t: string;
  online: number;
  total: number;
  critical: number;
}

export interface NetworkInfo {
  interface: string;
  local_ip: string;
  local_mac: string;
  gateway_ip: string;
  gateway_mac: string;
  cidr: string;
  host_count: number;
  scapy: boolean;
  scapy_error: string | null;
  sniffer: boolean;
  running: boolean;
  last_error: string | null;
  engines: string[];
  demo?: boolean;
}

export interface ResponderStatus {
  enabled: boolean;
  backend_ok: boolean;
  note: string;
  platform: string;
}

export interface AssetTypeMeta {
  label: string;
  icon: string;
  color: string;
  criticality: Criticality;
}

export interface AppInfo {
  name: string;
  edition: string;
  version: string;
  codename: string;
}

/** Instantané complet de l'état de la plateforme. */
export interface AppState {
  ok: boolean;
  server_time: string;
  devices: Device[];
  alerts: Alert[];
  metrics: Metrics;
  timeline: TimelinePoint[];
  network: NetworkInfo;
  responder: ResponderStatus;
  demo?: boolean;
  privileged: boolean;
  asset_types: Record<string, AssetTypeMeta>;
  app: AppInfo;
}

/** État d'authentification renvoyé par /api/auth/status. */
export interface AuthStatus {
  ok: boolean;
  auth_enabled: boolean;
  authenticated: boolean;
  csrf: string | null;
}

/** Payload de mise à jour d'un actif (modale d'édition). */
export interface DeviceUpdate {
  label?: string;
  criticality?: Criticality;
  notes?: string;
  trusted?: boolean;
  asset_type?: string;
}
