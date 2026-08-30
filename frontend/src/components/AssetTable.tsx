/* ==========================================================================
   NetWatch Console — inventaire des actifs (tri, filtres, actions)
   ========================================================================== */

import { useMemo } from 'react';
import { useStore } from '../store/useStore';
import {
  updateDevice,
  quarantineDevice,
  releaseDevice,
} from '../api/client';
import { relativeTime, ipToNumber, vendorSourceLabel } from '../utils/format';
import { StatusDot, RiskBar, Flag } from './ui';
import type { AppState, Device } from '../api/types';

// `cls` porte aussi les classes de masquage responsive, IDENTIQUES à celles des
// cellules correspondantes, afin que l'en-tête et le corps se cachent ensemble
// (sinon les colonnes se désalignent sur écran moyen).
const COLUMNS: { key: string; label: string; sortable: boolean; cls?: string }[] = [
  { key: 'online', label: 'État', sortable: true, cls: 'col-state' },
  { key: 'display_name', label: 'Actif', sortable: true },
  { key: 'ip', label: 'Adresse IP', sortable: true },
  { key: 'mac', label: 'Adresse MAC', sortable: true, cls: 'hide-sm' },
  { key: 'vendor', label: 'Fabricant (OUI)', sortable: true, cls: 'hide-md' },
  { key: 'type_label', label: 'Catégorie', sortable: true, cls: 'hide-sm' },
  { key: 'risk_score', label: 'Risque', sortable: true, cls: 'col-risk' },
  { key: 'last_seen', label: 'Dernière vue', sortable: true, cls: 'hide-md' },
  { key: 'actions', label: 'Actions', sortable: false, cls: 'col-actions' },
];

function isSuspect(d: Device): boolean {
  return (
    d.alert_count > 0 ||
    d.is_randomized ||
    d.flags.includes('OUI_INCONNU') ||
    d.risk_score >= 40
  );
}

export function AssetTable({ snapshot }: { snapshot: AppState }) {
  const {
    sortKey,
    sortDir,
    search,
    filterType,
    filterState,
    setSort,
    setSearch,
    setFilterType,
    setFilterState,
    openModal,
    pushToast,
    patchDeviceLocal,
  } = useStore();

  const devices = snapshot.devices;

  // Macs portant au moins une alerte CRITIQUE non acquittée : seules ces lignes
  // sont mises en évidence (le fond de ligne est réservé au sens le plus fort).
  const criticalMacs = useMemo(() => {
    const set = new Set<string>();
    for (const a of snapshot.alerts) {
      if (a.severity === 'critical' && !a.acknowledged && a.mac) set.add(a.mac);
    }
    return set;
  }, [snapshot.alerts]);

  const rows = useMemo(() => {
    const query = search.trim().toLowerCase();
    const dayAgo = Date.now() / 1000 - 86400;

    const filtered = devices.filter((d) => {
      if (filterType && d.asset_type !== filterType) return false;
      switch (filterState) {
        case 'online': if (!d.online) return false; break;
        case 'offline': if (d.online) return false; break;
        case 'suspect': if (!isSuspect(d)) return false; break;
        case 'untrusted': if (d.trusted) return false; break;
        case 'new': if (d.first_seen < dayAgo) return false; break;
        case 'quarantined': if (!d.quarantined) return false; break;
      }
      if (!query) return true;
      const hay = [d.display_name, d.label, d.hostname, d.ip, d.mac, d.vendor, d.type_label, d.notes]
        .filter(Boolean)
        .join(' ')
        .toLowerCase();
      return hay.includes(query);
    });

    const dir = sortDir === 'asc' ? 1 : -1;
    const sorted = [...filtered].sort((a, b) => {
      let va: string | number | boolean = a[sortKey as keyof Device] as never;
      let vb: string | number | boolean = b[sortKey as keyof Device] as never;
      if (sortKey === 'ip') {
        va = ipToNumber(a.ip);
        vb = ipToNumber(b.ip);
      }
      if (typeof va === 'boolean') va = va ? 1 : 0;
      if (typeof vb === 'boolean') vb = vb ? 1 : 0;
      if (typeof va === 'string' || typeof vb === 'string') {
        return String(va ?? '').localeCompare(String(vb ?? ''), 'fr', {
          numeric: true,
          sensitivity: 'base',
        }) * dir;
      }
      return ((va ?? 0) - (vb ?? 0)) * dir;
    });
    return sorted;
  }, [devices, search, filterType, filterState, sortKey, sortDir]);

  const toggleTrust = async (d: Device) => {
    const next = !d.trusted;
    patchDeviceLocal(d.mac, { trusted: next }); // instantané
    try {
      await updateDevice(d.mac, { trusted: next });
      pushToast(next ? 'Actif approuvé.' : 'Approbation retirée.', 'ok');
    } catch (e) {
      patchDeviceLocal(d.mac, { trusted: d.trusted }); // rollback si échec
      pushToast((e as Error).message, 'error');
    }
  };

  const quarantine = async (d: Device) => {
    const ok = window.confirm(
      `Isoler « ${d.display_name || d.ip} » ?\n\n` +
        `NetWatch va poser une règle sur le pare-feu LOCAL de ce poste pour couper ` +
        `tout trafic entre lui et ${d.ip} (${d.mac}).\n\n` +
        `• Action réversible d'un clic.\n` +
        `• NetWatch ne configure que sa propre machine : aucune trame ARP forgée.\n` +
        `• Pour une isolation à l'échelle du réseau, appliquez un filtrage MAC ` +
        `ou une coupure de port sur le switch / la passerelle.`,
    );
    if (!ok) return;
    patchDeviceLocal(d.mac, { quarantined: true }); // instantané
    try {
      const r = await quarantineDevice(d.mac);
      patchDeviceLocal(d.mac, { quarantined: true, quarantine_enforced: r.enforced });
      pushToast(
        r.enforced
          ? 'Actif isolé : règle pare-feu locale appliquée.'
          : 'Quarantaine enregistrée (pare-feu local indisponible).',
        r.enforced ? 'ok' : 'warn',
      );
    } catch (e) {
      patchDeviceLocal(d.mac, { quarantined: false }); // rollback
      pushToast((e as Error).message, 'error');
    }
  };

  const release = async (d: Device) => {
    patchDeviceLocal(d.mac, { quarantined: false, quarantine_enforced: false }); // instantané
    try {
      await releaseDevice(d.mac);
      pushToast('Quarantaine levée.', 'ok');
    } catch (e) {
      patchDeviceLocal(d.mac, { quarantined: true }); // rollback
      pushToast((e as Error).message, 'error');
    }
  };

  return (
    <section className="panel glass panel--assets">
      <header className="panel__head">
        <div>
          <h2>Inventaire des actifs</h2>
          <p className="panel__sub">
            {snapshot.metrics.total} actifs · {snapshot.metrics.online} en ligne ·{' '}
            {snapshot.metrics.last_scan_at
              ? `dernier balayage ${relativeTime(snapshot.metrics.last_scan_at)}`
              : 'aucun balayage effectué'}
          </p>
        </div>
        <div className="panel__tools">
          <div className="search">
            <span className="search__ico">⌕</span>
            <input
              type="search"
              placeholder="Rechercher IP, MAC, nom, fabricant…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              autoComplete="off"
              spellCheck={false}
            />
          </div>
          <select
            className="select"
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            aria-label="Filtrer par type"
          >
            <option value="">Tous les types</option>
            {Object.entries(snapshot.asset_types).map(([key, meta]) => (
              <option key={key} value={key}>
                {meta.icon} {meta.label}
              </option>
            ))}
          </select>
          <select
            className="select"
            value={filterState}
            onChange={(e) => setFilterState(e.target.value as never)}
            aria-label="Filtrer par état"
          >
            <option value="">Tous les états</option>
            <option value="online">En ligne</option>
            <option value="offline">Hors ligne</option>
            <option value="suspect">Suspects uniquement</option>
            <option value="untrusted">Non approuvés</option>
            <option value="new">Nouveaux (24 h)</option>
            <option value="quarantined">Isolés</option>
          </select>
        </div>
      </header>

      <div className="table-wrap">
        <table className="assets">
          <thead>
            <tr>
              {COLUMNS.map((c) => {
                const active = c.sortable && sortKey === c.key;
                const ariaSort = c.sortable
                  ? active
                    ? sortDir === 'asc'
                      ? 'ascending'
                      : 'descending'
                    : 'none'
                  : undefined;
                return (
                  <th key={c.key} className={c.cls} aria-sort={ariaSort} scope="col">
                    {c.sortable ? (
                      <button
                        type="button"
                        className="th-sort"
                        onClick={() => setSort(c.key)}
                      >
                        {c.label}
                        <span className="th-sort__arrow" aria-hidden="true">
                          {active ? (sortDir === 'asc' ? '↑' : '↓') : ''}
                        </span>
                      </button>
                    ) : (
                      c.label
                    )}
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr className="empty">
                <td colSpan={9}>
                  {devices.length
                    ? 'Aucun actif ne correspond aux filtres appliqués.'
                    : 'Aucun actif découvert — le premier balayage est en cours.'}
                </td>
              </tr>
            )}
            {rows.map((d) => {
              const canQ = !d.is_gateway && !d.is_local_host && !d.trusted;
              return (
                <tr
                  key={d.mac}
                  className={[
                    criticalMacs.has(d.mac) ? 'is-critical' : '',
                    d.quarantined ? 'is-quarantined' : '',
                  ]
                    .filter(Boolean)
                    .join(' ')}
                  onClick={() => openModal(d.mac)}
                >
                  <td>
                    <StatusDot online={d.online} />
                  </td>
                  <td>
                    <div className="asset-cell">
                      <span
                        className="asset-cell__icon"
                        style={{ color: d.type_color || '#8b9ab5' }}
                        aria-hidden="true"
                      >
                        {d.type_icon || '❓'}
                      </span>
                      <div style={{ minWidth: 0 }}>
                        {/* Bouton réel : ouvre la fiche au clic ET au clavier
                            (Tab + Entrée), tout en gardant le clic sur la ligne
                            comme confort à la souris. */}
                        <button
                          type="button"
                          className="asset-cell__name"
                          onClick={(e) => {
                            e.stopPropagation();
                            openModal(d.mac);
                          }}
                        >
                          {d.display_name || d.ip}
                        </button>
                        <div className="asset-cell__host">
                          {d.hostname || 'nom d’hôte non résolu'}
                        </div>
                        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginTop: 4 }}>
                          {d.is_gateway && <Flag tone="info">Passerelle</Flag>}
                          {d.is_local_host && <Flag tone="secure">Sonde</Flag>}
                          {d.is_virtual && <Flag tone="neutral">Virtuel</Flag>}
                          {d.is_randomized && <Flag tone="warning">MAC aléatoire</Flag>}
                          {d.trusted && <Flag tone="secure">Approuvé</Flag>}
                          {d.quarantined && <Flag tone="critical">⛔ Isolé</Flag>}
                          {d.alert_count > 0 && (
                            <Flag tone="critical">{d.alert_count} alerte(s)</Flag>
                          )}
                        </div>
                      </div>
                    </div>
                  </td>
                  <td className="ip-cell">{d.ip || '—'}</td>
                  <td className="mac-cell hide-sm">{d.mac}</td>
                  <td className="vendor-cell hide-md">
                    <span className="vendor-cell__name" title={d.vendor}>
                      {d.vendor || 'Inconnu'}
                    </span>
                    <span className="vendor-cell__src">
                      {vendorSourceLabel(d.vendor_source)}
                    </span>
                  </td>
                  <td className="hide-sm">
                    <span className="badge badge--type" style={{ color: d.type_color || '#8b9ab5' }}>
                      <i>{d.type_icon}</i>
                      {d.type_label || 'Inconnu'}
                    </span>
                    <span className="conf">{d.type_confidence}%</span>
                  </td>
                  <td>
                    <RiskBar score={d.risk_score} />
                  </td>
                  <td className="hide-md" title={d.last_seen_iso}>
                    {relativeTime(d.last_seen_iso)}
                  </td>
                  <td className="col-actions">
                    <div className="row-actions" onClick={(e) => e.stopPropagation()}>
                      <button
                        className="icon-btn"
                        title="Éditer"
                        aria-label={`Éditer ${d.display_name || d.ip}`}
                        onClick={() => openModal(d.mac)}
                      >
                        <span aria-hidden="true">✎</span>
                      </button>
                      <button
                        className="icon-btn"
                        title={d.trusted ? 'Retirer de la liste blanche' : 'Approuver'}
                        aria-label={
                          d.trusted
                            ? `Retirer ${d.display_name || d.ip} de la liste blanche`
                            : `Approuver ${d.display_name || d.ip}`
                        }
                        aria-pressed={d.trusted}
                        onClick={() => toggleTrust(d)}
                      >
                        <span aria-hidden="true">{d.trusted ? '★' : '☆'}</span>
                      </button>
                      {d.quarantined ? (
                        <button
                          className="icon-btn is-quarantined"
                          title="Lever l'isolation"
                          aria-label={`Lever l'isolation de ${d.display_name || d.ip}`}
                          onClick={() => release(d)}
                        >
                          <span aria-hidden="true">⛔</span>
                        </button>
                      ) : (
                        <button
                          className="icon-btn"
                          title={
                            canQ
                              ? 'Isoler (pare-feu local)'
                              : 'Isolation impossible (passerelle, sonde ou approuvé)'
                          }
                          aria-label={`Isoler ${d.display_name || d.ip}`}
                          disabled={!canQ}
                          onClick={() => quarantine(d)}
                        >
                          <span aria-hidden="true">⭘</span>
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}
