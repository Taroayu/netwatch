/* ==========================================================================
   NetWatch Console — barre supérieure (identité, contexte réseau, contrôles)
   ========================================================================== */

import { useEffect, useRef, useState } from 'react';
import { useStore } from '../store/useStore';
import {
  controlEngine,
  exportUrl,
  ackAllAlerts,
  clearAlerts,
  logout,
  setCsrfToken,
} from '../api/client';
import type { AppState } from '../api/types';
import { ThemeToggle } from './ThemeToggle';

export function TopBar({ snapshot }: { snapshot: AppState }) {
  const pushToast = useStore((s) => s.pushToast);
  const connected = useStore((s) => s.connected);
  const authEnabled = useStore((s) => s.authEnabled);
  const setAuth = useStore((s) => s.setAuth);
  const ackAllLocal = useStore((s) => s.ackAllLocal);
  const [menuOpen, setMenuOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  const { network, metrics, app } = snapshot;

  useEffect(() => {
    const onClick = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setMenuOpen(false);
      }
    };
    document.addEventListener('click', onClick);
    return () => document.removeEventListener('click', onClick);
  }, []);

  const toggle = async () => {
    setBusy(true);
    try {
      await controlEngine(network.running ? 'stop' : 'start');
      pushToast(network.running ? 'Moteur arrêté.' : 'Moteur démarré.', 'ok');
    } catch (e) {
      pushToast((e as Error).message, 'error');
    } finally {
      setBusy(false);
    }
  };

  const scan = async () => {
    try {
      await controlEngine('scan');
      pushToast('Balayage ARP demandé.', 'ok');
    } catch (e) {
      pushToast((e as Error).message, 'error');
    }
  };

  const menuAction = async (act: string) => {
    setMenuOpen(false);
    try {
      if (act === 'export-csv') window.location.href = exportUrl('csv');
      else if (act === 'export-json') window.location.href = exportUrl('json');
      else if (act === 'ack-all') {
        ackAllLocal(); // rendu instantané
        const r = await ackAllAlerts();
        pushToast(`${r.count} alerte(s) acquittée(s).`, 'ok');
      } else if (act === 'clear-alerts') {
        const r = await clearAlerts();
        pushToast(`${r.count} alerte(s) purgée(s).`, 'ok');
      } else if (act === 'logout') {
        await logout();
        setCsrfToken('');
        setAuth({ authed: false });
        pushToast('Déconnecté.', 'ok');
      }
    } catch (e) {
      pushToast((e as Error).message, 'error');
    }
  };

  return (
    <header className="topbar glass">
      <div className="topbar__brand">
        <div className="logo" aria-hidden="true">
          <svg viewBox="0 0 48 48" role="img">
            <defs>
              <linearGradient id="lg" x1="0" y1="0" x2="1" y2="1">
                <stop offset="0%" stopColor="#00e5ff" />
                <stop offset="100%" stopColor="#7c5cff" />
              </linearGradient>
            </defs>
            <path
              d="M24 3 6 10v13c0 11 7.6 19.4 18 22 10.4-2.6 18-11 18-22V10L24 3z"
              fill="none"
              stroke="url(#lg)"
              strokeWidth="2.4"
            />
            <path
              d="M15 24l6 6 12-13"
              fill="none"
              stroke="url(#lg)"
              strokeWidth="3"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </div>
        <div className="brand-text">
          <h1>
            {app.name}
            <span className="brand-text__edition">{app.edition}</span>
          </h1>
          <p className="brand-text__meta">
            v{app.version} · <span className="codename">{app.codename}</span> ·{' '}
            <span>{network.engines.join(' · ')}</span>
            {snapshot.demo && <span className="demo-badge" style={{ marginLeft: 8 }}>Démo</span>}
          </p>
        </div>
      </div>

      <div className="topbar__context">
        <ContextChip k="Segment" v={network.cidr} />
        <ContextChip k="Passerelle" v={network.gateway_ip} title={network.gateway_mac} />
        <ContextChip k="Interface" v={network.interface} className="hide-md" />
        <ContextChip k="Sonde" v={network.local_ip} title={network.local_mac} className="hide-md" />
        <ContextChip
          k="Flux"
          v={connected ? 'temps réel' : 'reconnexion…'}
          className="hide-sm"
        />
      </div>

      <div className="topbar__actions">
        <div className="threat-pill" data-level={metrics.threat_level}>
          <span className="threat-pill__dot" />
          <span className="threat-pill__label">{metrics.threat_label}</span>
        </div>
        <button className="btn btn--ghost" onClick={scan} title="Balayage immédiat">
          <span className="btn__ico">⟳</span> Scanner
        </button>
        <button
          className={`btn btn--primary ${busy ? 'is-busy' : ''}`}
          onClick={toggle}
          title="Démarrer / arrêter le moteur"
        >
          <span className="btn__ico">{network.running ? '◼' : '▶'}</span>{' '}
          {network.running ? 'Arrêter' : 'Démarrer'}
        </button>
        <ThemeToggle />
        <div className="menu" ref={menuRef}>
          <button
            className="btn btn--icon"
            onClick={(e) => {
              e.stopPropagation();
              setMenuOpen((o) => !o);
            }}
            aria-label="Plus d'actions"
          >
            ⋯
          </button>
          {menuOpen && (
            <div className="menu__panel">
              <button onClick={() => menuAction('export-csv')}>
                Exporter l'inventaire (CSV)
              </button>
              <button onClick={() => menuAction('export-json')}>
                Exporter le dossier complet (JSON)
              </button>
              <button onClick={() => menuAction('ack-all')}>
                Acquitter toutes les alertes
              </button>
              <button className="danger" onClick={() => menuAction('clear-alerts')}>
                Purger le journal d'alertes
              </button>
              {authEnabled && (
                <button onClick={() => menuAction('logout')}>Se déconnecter</button>
              )}
            </div>
          )}
        </div>
      </div>
    </header>
  );
}

function ContextChip({
  k,
  v,
  title,
  className = '',
}: {
  k: string;
  v: string;
  title?: string;
  className?: string;
}) {
  return (
    <div className={`ctx-chip ${className}`}>
      <span className="ctx-chip__k">{k}</span>
      <span className="ctx-chip__v" title={title || v}>
        {v}
      </span>
    </div>
  );
}
