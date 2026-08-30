/* ==========================================================================
   NetWatch Console — client API
   --------------------------------------------------------------------------
   Couche unique d'accès au backend Flask. Toute action passe par ici, avec
   une gestion d'erreur homogène : les composants n'écrivent jamais de `fetch`
   à la main.
   ========================================================================== */

import type { AppState, AuthStatus, Device, DeviceUpdate } from './types';

/** Erreur applicative portant le message renvoyé par l'API. */
export class ApiError extends Error {
  status?: number;
  constructor(message: string, status?: number) {
    super(message);
    this.status = status;
  }
}

/* --- Jeton CSRF et gestion de la perte de session ------------------------- */

let csrfToken = '';
export function setCsrfToken(token: string): void {
  csrfToken = token || '';
}

let onUnauthorized: (() => void) | null = null;
/** Enregistre le comportement à adopter quand l'API renvoie 401 (session
 *  expirée) : typiquement, revenir à l'écran de connexion. */
export function setUnauthorizedHandler(fn: () => void): void {
  onUnauthorized = fn;
}

const MUTATING = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const method = (init?.method ?? 'GET').toUpperCase();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...((init?.headers as Record<string, string>) ?? {}),
  };
  // Jeton anti-CSRF sur toute requête mutante (ignoré par le serveur pour le
  // login, qui établit précisément la session).
  if (MUTATING.has(method) && csrfToken) headers['X-CSRF-Token'] = csrfToken;

  const response = await fetch(path, {
    credentials: 'same-origin', // envoie le cookie de session
    headers,
    ...init,
  });

  if (response.status === 401) {
    onUnauthorized?.();
    throw new ApiError('Session expirée — reconnectez-vous.', 401);
  }

  const isJson = response.headers.get('content-type')?.includes('application/json');
  const payload = isJson ? await response.json() : null;

  if (!response.ok) {
    const message =
      (payload && (payload.error as string)) || `Erreur HTTP ${response.status}`;
    throw new ApiError(message, response.status);
  }
  return payload as T;
}

/* ---------------------------------------------------------- AUTHENTIFICATION */

export const fetchAuthStatus = () => request<AuthStatus>('/api/auth/status');

export const login = (password: string) =>
  request<{ ok: boolean; csrf: string }>('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ password }),
  });

export const logout = () => request<{ ok: boolean }>('/api/auth/logout', { method: 'POST' });

/* ------------------------------------------------------------------ ÉTAT */

export const fetchState = () => request<AppState>('/api/state');

/* --------------------------------------------------------------- ACTIONS */

export const updateDevice = (mac: string, patch: DeviceUpdate) =>
  request<{ ok: boolean; device: Device }>(
    `/api/device/${encodeURIComponent(mac)}`,
    { method: 'POST', body: JSON.stringify(patch) },
  );

export const forgetDevice = (mac: string) =>
  request<{ ok: boolean }>(`/api/device/${encodeURIComponent(mac)}`, {
    method: 'DELETE',
  });

export const quarantineDevice = (mac: string) =>
  request<{ ok: boolean; enforced: boolean; detail: string; device: Device }>(
    `/api/device/${encodeURIComponent(mac)}/quarantine`,
    { method: 'POST' },
  );

export const releaseDevice = (mac: string) =>
  request<{ ok: boolean; detail: string; device: Device }>(
    `/api/device/${encodeURIComponent(mac)}/release`,
    { method: 'POST' },
  );

export const ackAlert = (id: string) =>
  request<{ ok: boolean }>(`/api/alerts/${encodeURIComponent(id)}/ack`, {
    method: 'POST',
  });

export const ackAllAlerts = () =>
  request<{ ok: boolean; count: number }>('/api/alerts/ack-all', {
    method: 'POST',
  });

export const clearAlerts = () =>
  request<{ ok: boolean; count: number }>('/api/alerts/clear', {
    method: 'POST',
  });

export type EngineAction = 'start' | 'stop' | 'scan';

export const controlEngine = (action: EngineAction) =>
  request<{ ok: boolean; running?: boolean; queued?: boolean }>(
    `/api/control/${action}`,
    { method: 'POST' },
  );

/* ---------------------------------------------------------------- EXPORT */

export const exportUrl = (fmt: 'csv' | 'json') => `/api/export/${fmt}`;
