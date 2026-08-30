/* ==========================================================================
   NetWatch Console — grille des indicateurs clés (KPI)
   ========================================================================== */

import type { Metrics } from '../api/types';

/** Couleur de la posture : rouge (faible) → ambre → vert (saine). */
function postureColor(score: number): string {
  if (score < 40) return 'var(--critical)';
  if (score < 75) return 'var(--warning)';
  return 'var(--secure)';
}

export function KpiGrid({ metrics }: { metrics: Metrics }) {
  // Ordre pensé pour le schéma de lecture en « F » : l'information de sécurité
  // la plus décisive (menace, posture) occupe le haut-gauche, là où l'œil se
  // pose en premier ; l'inventaire et la télémétrie suivent.
  return (
    <section className="kpi-grid" aria-label="Indicateurs clés">
      <Kpi
        accent="red"
        title="Alertes critiques"
        icon="⛊"
        value={metrics.alerts_critical}
        hot={metrics.alerts_critical > 0}
      >
        <span>{metrics.alerts_warning}</span> avertissements ouverts
      </Kpi>

      <article className="kpi glass" data-accent="violet">
        <header>
          <h2>Posture de sécurité</h2>
          <span className="kpi__ico" aria-hidden="true">⌾</span>
        </header>
        <p className="kpi__value" style={{ color: postureColor(metrics.posture) }}>
          {metrics.posture}
          <small>/100</small>
        </p>
        <div className="posture-bar">
          <i
            style={{
              width: `${metrics.posture}%`,
              background: postureColor(metrics.posture),
            }}
          />
        </div>
      </article>

      <Kpi accent="cyan" title="Actifs inventoriés" icon="▦" value={metrics.total}>
        <span>{metrics.new_24h}</span> nouveaux sur 24 h
      </Kpi>

      <Kpi accent="green" title="En ligne" icon="◉" value={metrics.online}>
        <span>{metrics.offline}</span> hors ligne
      </Kpi>

      <Kpi accent="amber" title="Anomalies matérielles" icon="⌁" value={metrics.randomized}>
        <span>{metrics.virtual}</span> actifs virtualisés
      </Kpi>

      <Kpi accent="slate" title="Collecte" icon="⇅" value={metrics.scan_count}>
        <span>{metrics.packets_seen.toLocaleString('fr-FR')}</span> trames ARP analysées
      </Kpi>
    </section>
  );
}

function Kpi({
  accent,
  title,
  icon,
  value,
  hot,
  children,
}: {
  accent: string;
  title: string;
  icon: string;
  value: number;
  hot?: boolean;
  children: React.ReactNode;
}) {
  return (
    <article className={`kpi glass ${hot ? 'is-hot' : ''}`} data-accent={accent}>
      <header>
        <h2>{title}</h2>
        <span className="kpi__ico" aria-hidden="true">{icon}</span>
      </header>
      <p className="kpi__value">{value}</p>
      <p className="kpi__sub">{children}</p>
    </article>
  );
}
