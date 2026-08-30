/* ==========================================================================
   NetWatch Console — composant racine
   --------------------------------------------------------------------------
   Orchestre le flux temps réel, la mise en page du centre opérationnel et
   les notifications d'alertes critiques.
   ========================================================================== */

import { useEffect, useRef } from 'react';
import { useLiveState } from './hooks/useLiveState';
import { useStore } from './store/useStore';
import { fetchAuthStatus, setCsrfToken, setUnauthorizedHandler } from './api/client';
import { Login } from './components/Login';
import { Skeleton } from './components/Skeleton';
import { TopBar } from './components/TopBar';
import { SysBar } from './components/SysBar';
import { KpiGrid } from './components/KpiGrid';
import { TrendChart } from './components/TrendChart';
import { AssetTable } from './components/AssetTable';
import { Donut } from './components/Donut';
import { AlertFeed } from './components/AlertFeed';
import { AssetModal } from './components/AssetModal';
import { Toasts } from './components/Toasts';
import { Clock } from './components/Clock';

export default function App() {
  const authChecked = useStore((s) => s.authChecked);
  const authEnabled = useStore((s) => s.authEnabled);
  const authed = useStore((s) => s.authed);
  const setAuth = useStore((s) => s.setAuth);

  const snapshot = useStore((s) => s.snapshot);
  const pushToast = useStore((s) => s.pushToast);
  const seenAlerts = useRef<Set<string> | null>(null);

  // Le flux temps réel ne démarre qu'une fois la session établie.
  useLiveState(authed);

  // Vérification initiale de l'authentification + gestion des expirations (401).
  useEffect(() => {
    setUnauthorizedHandler(() => {
      setCsrfToken('');
      setAuth({ authed: false });
      seenAlerts.current = null;
    });
    fetchAuthStatus()
      .then((s) => {
        if (s.authenticated && s.csrf) setCsrfToken(s.csrf);
        setAuth({
          authChecked: true,
          authEnabled: s.auth_enabled,
          authed: s.authenticated,
        });
      })
      .catch(() => setAuth({ authChecked: true }));
  }, [setAuth]);

  // Notifie les nouvelles alertes critiques/avertissement dès leur apparition.
  useEffect(() => {
    if (!snapshot) return;
    if (seenAlerts.current === null) {
      // Premier instantané : on mémorise sans notifier (évite un flot au démarrage).
      seenAlerts.current = new Set(snapshot.alerts.map((a) => a.id));
      return;
    }
    for (const alert of snapshot.alerts) {
      if (seenAlerts.current.has(alert.id)) continue;
      seenAlerts.current.add(alert.id);
      if (alert.acknowledged) continue;
      if (alert.severity === 'critical') pushToast(alert.title, 'error');
      else if (alert.severity === 'warning') pushToast(alert.title, 'warn');
    }
  }, [snapshot, pushToast]);

  // Titre d'onglet dynamique.
  useEffect(() => {
    const crit = snapshot?.metrics.alerts_critical ?? 0;
    document.title = crit
      ? `(${crit}) ⛊ NetWatch — MENACE ACTIVE`
      : 'NetWatch — Enterprise / Pro-SecOps';
  }, [snapshot?.metrics.alerts_critical]);

  // Attente de la vérification d'auth initiale.
  if (!authChecked) {
    return (
      <div className="boot">
        <div className="boot__spinner" />
        <p>Initialisation…</p>
      </div>
    );
  }

  // Session requise et non établie → écran de connexion.
  if (authEnabled && !authed) {
    return <Login />;
  }

  // Chargement des données : squelette épousant la mise en page (perception
  // de rapidité), plutôt qu'un spinner.
  if (!snapshot) {
    return <Skeleton />;
  }

  return (
    <>
      <a className="skip-link" href="#contenu">Aller au contenu principal</a>
      <TopBar snapshot={snapshot} />
      <SysBar snapshot={snapshot} />
      <TrendChart timeline={snapshot.timeline} />
      <KpiGrid metrics={snapshot.metrics} />

      <main className="workspace" id="contenu" tabIndex={-1}>
        <AssetTable snapshot={snapshot} />
        <aside className="sidecol">
          <Donut snapshot={snapshot} />
          <AlertFeed snapshot={snapshot} />
        </aside>
      </main>

      <AssetModal snapshot={snapshot} />
      <Toasts />

      <footer className="footer">
        <span>
          {snapshot.app.name} {snapshot.app.edition} — outil défensif de supervision réseau.
        </span>
        <Clock />
      </footer>
    </>
  );
}
