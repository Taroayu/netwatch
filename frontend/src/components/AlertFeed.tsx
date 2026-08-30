/* ==========================================================================
   NetWatch Console — flux de menaces
   ========================================================================== */

import { useMemo } from 'react';
import { useStore } from '../store/useStore';
import { ackAlert } from '../api/client';
import { shortTime } from '../utils/format';
import { SeverityBadge } from './ui';
import type { AppState } from '../api/types';
import type { AlertFilter } from '../store/useStore';

const FILTERS: { key: AlertFilter; label: string }[] = [
  { key: '', label: 'Tout' },
  { key: 'critical', label: 'Critique' },
  { key: 'warning', label: 'Alerte' },
  { key: 'open', label: 'Non acquittées' },
];

export function AlertFeed({ snapshot }: { snapshot: AppState }) {
  const alertFilter = useStore((s) => s.alertFilter);
  const setAlertFilter = useStore((s) => s.setAlertFilter);
  const openModal = useStore((s) => s.openModal);
  const pushToast = useStore((s) => s.pushToast);
  const ackAlertLocal = useStore((s) => s.ackAlertLocal);

  const { alerts, metrics } = snapshot;

  const list = useMemo(() => {
    if (alertFilter === 'open') return alerts.filter((a) => !a.acknowledged);
    if (alertFilter) return alerts.filter((a) => a.severity === alertFilter);
    return alerts;
  }, [alerts, alertFilter]);

  const onAck = async (id: string) => {
    ackAlertLocal(id); // rendu instantané ; le flux SSE confirmera ensuite
    try {
      await ackAlert(id);
    } catch (e) {
      pushToast((e as Error).message, 'error');
    }
  };

  return (
    <section className="panel glass panel--alerts">
      <header className="panel__head panel__head--tight">
        <div>
          <h2>Flux de menaces</h2>
          <p className="panel__sub">
            {metrics.alerts_open} alerte(s) ouverte(s) — {metrics.alerts_critical}{' '}
            critique(s), {metrics.alerts_warning} avertissement(s)
          </p>
        </div>
        <div className="seg" role="tablist">
          {FILTERS.map((f) => (
            <button
              key={f.key || 'all'}
              className={alertFilter === f.key ? 'is-active' : ''}
              onClick={() => setAlertFilter(f.key)}
            >
              {f.label}
            </button>
          ))}
        </div>
      </header>

      <ol className="alert-feed">
        {list.length === 0 && (
          <li className="empty">Aucun événement ne correspond à ce filtre.</li>
        )}
        {list.slice(0, 120).map((a) => (
          <li
            key={a.id}
            className={`alert ${a.acknowledged ? 'is-ack' : ''}`}
            data-sev={a.severity}
            onClick={() => a.mac && openModal(a.mac)}
            onKeyDown={(e) => {
              if (a.mac && (e.key === 'Enter' || e.key === ' ')) {
                e.preventDefault();
                openModal(a.mac);
              }
            }}
            tabIndex={a.mac ? 0 : undefined}
            role={a.mac ? 'button' : undefined}
            aria-label={a.mac ? `${a.title} — ouvrir la fiche de l'actif` : undefined}
          >
            <div className="alert__head">
              <span className="alert__title">{a.title}</span>
              <SeverityBadge severity={a.severity} />
            </div>
            <p className="alert__detail">{a.detail}</p>
            <div className="alert__meta">
              <span>{shortTime(a.time)}</span>
              {(a.ip || a.mac) && <span>{[a.ip, a.mac].filter(Boolean).join(' · ')}</span>}
              <span className="alert__mitre">{a.mitre}</span>
              {a.acknowledged ? (
                <span style={{ marginLeft: 'auto' }}>✓ acquittée</span>
              ) : (
                <button
                  className="alert__ack"
                  style={{ marginLeft: 'auto' }}
                  onClick={(e) => {
                    e.stopPropagation();
                    void onAck(a.id);
                  }}
                >
                  Acquitter
                </button>
              )}
            </div>
          </li>
        ))}
      </ol>
    </section>
  );
}
