/* ==========================================================================
   NetWatch Console — anneau de répartition du parc
   ========================================================================== */

import { useMemo } from 'react';
import { useStore } from '../store/useStore';
import type { AppState } from '../api/types';

const RADIUS = 46;
const CIRCUM = 2 * Math.PI * RADIUS;

export function Donut({ snapshot }: { snapshot: AppState }) {
  const filterType = useStore((s) => s.filterType);
  const setFilterType = useStore((s) => s.setFilterType);

  const entries = useMemo(() => {
    const dist = snapshot.metrics.distribution || {};
    return Object.entries(dist)
      .map(([key, count]) => {
        const meta = snapshot.asset_types[key];
        return {
          key,
          count,
          label: meta?.label ?? key,
          color: meta?.color ?? '#64748b',
          icon: meta?.icon ?? '•',
        };
      })
      .filter((e) => e.count > 0)
      .sort((a, b) => b.count - a.count);
  }, [snapshot.metrics.distribution, snapshot.asset_types]);

  const total = entries.reduce((sum, e) => sum + e.count, 0);

  let offset = 0;
  const arcs = entries.map((e) => {
    const length = (e.count / total) * CIRCUM;
    const arc = (
      <circle
        key={e.key}
        cx="60"
        cy="60"
        r={RADIUS}
        fill="none"
        stroke={e.color}
        strokeWidth="13"
        strokeDasharray={`${length - 1.6} ${CIRCUM - length + 1.6}`}
        strokeDashoffset={-offset}
        style={{ filter: `drop-shadow(0 0 5px ${e.color}55)` }}
      >
        <title>{`${e.label} : ${e.count}`}</title>
      </circle>
    );
    offset += length;
    return arc;
  });

  return (
    <section className="panel glass panel--donut">
      <header className="panel__head panel__head--tight">
        <h2>Répartition du parc</h2>
      </header>
      <div className="donut-wrap">
        <svg id="donut" viewBox="0 0 120 120" role="img" aria-label="Répartition par catégorie">
          <circle cx="60" cy="60" r={RADIUS} fill="none" stroke="rgba(126,152,214,.10)" strokeWidth="13" />
          {total > 0 && arcs}
        </svg>
        <div className="donut-center">
          <span>{total}</span>
          <small>actifs</small>
        </div>
      </div>
      <ul className="legend">
        {total === 0 && (
          <li className="empty" style={{ justifyContent: 'center' }}>
            Aucun actif inventorié
          </li>
        )}
        {entries.map((e) => (
          <li
            key={e.key}
            title="Filtrer sur cette catégorie"
            onClick={() => setFilterType(filterType === e.key ? '' : e.key)}
          >
            <span className="legend__swatch" style={{ background: e.color }} />
            <span className="legend__label">
              {e.icon} {e.label}
            </span>
            <span className="legend__count">{e.count}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}
