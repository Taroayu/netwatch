import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  updateDevice,
  fetchState,
  setCsrfToken,
  setUnauthorizedHandler,
  ApiError,
} from '../api/client';

function mockFetch(status: number, body: unknown) {
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    headers: { get: () => 'application/json' },
    json: async () => body,
  });
}

describe('client API', () => {
  beforeEach(() => {
    setCsrfToken('');
  });

  it("ajoute l'en-tête X-CSRF-Token sur les requêtes mutantes", async () => {
    const f = mockFetch(200, { ok: true, device: {} });
    vi.stubGlobal('fetch', f);
    setCsrfToken('jeton-secret');
    await updateDevice('aa:bb:cc:dd:ee:ff', { label: 'X' });
    const [, init] = f.mock.calls[0]!;
    expect(init.method).toBe('POST');
    expect(init.headers['X-CSRF-Token']).toBe('jeton-secret');
    expect(init.credentials).toBe('same-origin');
  });

  it("n'ajoute pas de jeton sur un GET", async () => {
    const f = mockFetch(200, { ok: true, devices: [] });
    vi.stubGlobal('fetch', f);
    setCsrfToken('jeton-secret');
    await fetchState();
    const [, init] = f.mock.calls[0]!;
    expect(init.headers['X-CSRF-Token']).toBeUndefined();
  });

  it('déclenche le gestionnaire 401 et lève une ApiError', async () => {
    const f = mockFetch(401, { error: 'nope' });
    vi.stubGlobal('fetch', f);
    const onUnauth = vi.fn();
    setUnauthorizedHandler(onUnauth);
    await expect(fetchState()).rejects.toBeInstanceOf(ApiError);
    expect(onUnauth).toHaveBeenCalledOnce();
  });

  it("propage le message d'erreur de l'API", async () => {
    const f = mockFetch(400, { error: 'Format non supporté' });
    vi.stubGlobal('fetch', f);
    await expect(fetchState()).rejects.toThrow('Format non supporté');
  });
});
