/* ==========================================================================
   NetWatch Console — primitives d'interface réutilisables
   ========================================================================== */

import type { Severity } from '../api/types';

const SEV_CLASS: Record<Severity, string> = {
  critical: 'soc-critical',
  warning: 'soc-warning',
  info: 'soc-info',
  secure: 'soc-secure',
};

const SEV_LABEL: Record<Severity, string> = {
  critical: 'Critique',
  warning: 'Alerte',
  info: 'Information',
  secure: 'Nominal',
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`badge ${SEV_CLASS[severity]}`}>{SEV_LABEL[severity]}</span>;
}

export function StatusDot({ online }: { online: boolean }) {
  return (
    <span className={`status ${online ? 'status--online' : 'status--offline'}`}>
      <span className="status__dot" />
      {online ? 'En ligne' : 'Hors ligne'}
    </span>
  );
}

export function RiskBar({ score }: { score: number }) {
  const cls = score >= 60 ? 'risk--high' : score >= 30 ? 'risk--mid' : 'risk--low';
  return (
    <div className={`risk ${cls}`}>
      <span className="risk__bar">
        <i style={{ width: `${Math.min(100, score)}%` }} />
      </span>
      <span className="risk__val">{score}</span>
    </div>
  );
}

export function Flag({
  tone,
  children,
}: {
  tone: 'critical' | 'warning' | 'info' | 'secure' | 'neutral';
  children: React.ReactNode;
}) {
  return <span className={`badge badge--flag soc-${tone}`}>{children}</span>;
}
