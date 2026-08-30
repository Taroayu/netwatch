/* ==========================================================================
   NetWatch Console — écran de connexion
   ========================================================================== */

import { useState } from 'react';
import { login, setCsrfToken } from '../api/client';
import { useStore } from '../store/useStore';

export function Login() {
  const setAuth = useStore((s) => s.setAuth);
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!password || busy) return;
    setBusy(true);
    setError(null);
    try {
      const res = await login(password);
      setCsrfToken(res.csrf);
      setAuth({ authed: true });
    } catch (err) {
      setError((err as Error).message || 'Connexion refusée.');
      setPassword('');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login">
      <form className="login__card glass" onSubmit={submit}>
        <div className="login__brand">
          <div className="logo" aria-hidden="true">
            <svg viewBox="0 0 48 48" role="img">
              <defs>
                <linearGradient id="lg-login" x1="0" y1="0" x2="1" y2="1">
                  <stop offset="0%" stopColor="#fff" />
                  <stop offset="100%" stopColor="#fff" />
                </linearGradient>
              </defs>
              <path
                d="M24 3 6 10v13c0 11 7.6 19.4 18 22 10.4-2.6 18-11 18-22V10L24 3z"
                fill="none"
                stroke="url(#lg-login)"
                strokeWidth="2.4"
              />
              <path
                d="M15 24l6 6 12-13"
                fill="none"
                stroke="url(#lg-login)"
                strokeWidth="3"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
          </div>
          <h1>NetWatch</h1>
          <p>Console de supervision réseau — accès protégé</p>
        </div>

        <label className="field field--full">
          <span>Mot de passe</span>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Mot de passe de la console"
            autoFocus
            autoComplete="current-password"
          />
        </label>

        {error && <p className="login__error">{error}</p>}

        <button type="submit" className="btn btn--primary login__submit" disabled={busy}>
          {busy ? 'Connexion…' : 'Se connecter'}
        </button>

        <p className="login__hint">
          Mot de passe défini par <code>NETWATCH_PASSWORD</code>, ou généré au
          démarrage et affiché dans la console du serveur.
        </p>
      </form>
    </div>
  );
}
