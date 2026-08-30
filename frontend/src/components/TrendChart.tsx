/* ==========================================================================
   NetWatch Console — courbe de tendance
   --------------------------------------------------------------------------
   Exploite la série temporelle déjà collectée par le backend (actifs en ligne
   et alertes critiques au fil du temps). Deux séries au maximum (charge
   cognitive), couleurs = sens (accent pour la présence, rouge pour la menace),
   tracé sobre sans grille. Accessible : résumé textuel via aria-label.
   ========================================================================== */

import { useMemo } from 'react';
import type { TimelinePoint } from '../api/types';

const W = 100;   // repère interne ; le SVG s'étire en largeur (viewBox)
const H = 34;

export function TrendChart({ timeline }: { timeline: TimelinePoint[] }) {
  const { area, lineOnline, lineCrit, maxTotal, maxCritical, last, count } = useMemo(() => {
    const pts = timeline ?? [];
    if (pts.length < 2) {
      return {
        area: '', lineOnline: '', lineCrit: '',
        maxTotal: 0, maxCritical: 0, last: null, count: pts.length,
      };
    }
    const maxTotal = Math.max(1, ...pts.map((p) => p.total));
    const maxCritical = Math.max(1, ...pts.map((p) => p.critical));
    const x = (i: number) => (i / (pts.length - 1)) * W;
    const yOnline = (v: number) => H - (v / maxTotal) * H;
    const yCrit = (v: number) => H - (v / maxCritical) * H;

    const onlinePts = pts.map((p, i) => `${x(i).toFixed(2)},${yOnline(p.online).toFixed(2)}`);
    const critPts = pts.map((p, i) => `${x(i).toFixed(2)},${yCrit(p.critical).toFixed(2)}`);

    return {
      area: `M0,${H} L${onlinePts.join(' L')} L${W},${H} Z`,
      lineOnline: `M${onlinePts.join(' L')}`,
      lineCrit: `M${critPts.join(' L')}`,
      maxTotal,
      maxCritical,
      last: pts[pts.length - 1] ?? null,
      count: pts.length,
    };
  }, [timeline]);

  const summary = last
    ? `Tendance : ${last.online} actifs en ligne sur ${last.total}, ` +
      `${last.critical} alerte(s) critique(s) au dernier relevé.`
    : 'Tendance : données insuffisantes pour le moment.';

  return (
    <section className="panel glass trend" aria-label={summary}>
      <div className="trend__head">
        <div>
          <h2>Tendance</h2>
          <p className="panel__sub">{count} derniers relevés temps réel</p>
        </div>
        <div className="trend__legend" aria-hidden="true">
          <span className="trend__key trend__key--online">Actifs en ligne</span>
          <span className="trend__key trend__key--crit">Alertes critiques</span>
        </div>
      </div>

      {count < 2 ? (
        <p className="trend__empty">Collecte en cours — la courbe apparaîtra après quelques relevés.</p>
      ) : (
        <div className="trend__plot">
          <svg
            viewBox={`0 0 ${W} ${H}`}
            preserveAspectRatio="none"
            role="img"
            aria-label={summary}
          >
            <path className="trend__area" d={area} />
            <path
              className="trend__line trend__line--online"
              d={lineOnline}
              fill="none"
              vectorEffect="non-scaling-stroke"
            />
            <path
              className="trend__line trend__line--crit"
              d={lineCrit}
              fill="none"
              vectorEffect="non-scaling-stroke"
            />
          </svg>
          {last && (
            <div className="trend__now">
              <span className="trend__now-online">{last.online}/{maxTotal}</span>
              <span className="trend__now-crit">{last.critical} crit.</span>
              <span className="trend__now-sub">
                pic critiques&nbsp;: {maxCritical}
              </span>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
