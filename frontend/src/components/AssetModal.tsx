/* ==========================================================================
   NetWatch Console — modale d'édition / investigation d'un actif
   ========================================================================== */

import { useEffect, useId, useRef, useState } from 'react';
import { useStore } from '../store/useStore';
import {
  updateDevice,
  forgetDevice,
  quarantineDevice,
  releaseDevice,
} from '../api/client';
import type { AppState, Criticality, Device } from '../api/types';

export function AssetModal({ snapshot }: { snapshot: AppState }) {
  const modalMac = useStore((s) => s.modalMac);
  const closeModal = useStore((s) => s.closeModal);
  const pushToast = useStore((s) => s.pushToast);
  const patchDeviceLocal = useStore((s) => s.patchDeviceLocal);
  const removeDeviceLocal = useStore((s) => s.removeDeviceLocal);

  const device = modalMac
    ? snapshot.devices.find((d) => d.mac === modalMac) ?? null
    : null;

  const boxRef = useRef<HTMLDivElement>(null);
  const titleId = useId();
  const subId = useId();

  const [label, setLabel] = useState('');
  const [assetType, setAssetType] = useState('unknown');
  const [criticality, setCriticality] = useState<Criticality>('medium');
  const [notes, setNotes] = useState('');
  const [trusted, setTrusted] = useState(false);

  // Réinitialise le formulaire à l'ouverture d'un nouvel actif.
  useEffect(() => {
    if (device) {
      setLabel(device.label ?? '');
      setAssetType(device.asset_type);
      setCriticality(device.criticality);
      setNotes(device.notes ?? '');
      setTrusted(device.trusted);
    }
  }, [modalMac]); // eslint-disable-line react-hooks/exhaustive-deps

  // Fermeture au clavier (Échap).
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && closeModal();
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [closeModal]);

  // Accessibilité : piège de focus, focus initial, restauration du focus à la
  // fermeture, et verrouillage du défilement de l'arrière-plan.
  useEffect(() => {
    if (!modalMac) return;
    const box = boxRef.current;
    if (!box) return;

    const previouslyFocused = document.activeElement as HTMLElement | null;
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';

    const focusable = (): HTMLElement[] =>
      Array.from(
        box.querySelectorAll<HTMLElement>(
          'a[href], button:not([disabled]), input:not([disabled]), ' +
            'select:not([disabled]), textarea:not([disabled]), ' +
            '[tabindex]:not([tabindex="-1"])',
        ),
      ).filter((el) => el.offsetParent !== null);

    // Focus initial sur le premier champ (à défaut, la boîte elle-même).
    (focusable()[0] ?? box).focus();

    // Le focus ne peut pas sortir de la modale au clavier (Tab / Maj+Tab).
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key !== 'Tab') return;
      const items = focusable();
      if (items.length === 0) {
        e.preventDefault();
        return;
      }
      const first = items[0]!;
      const last = items[items.length - 1]!;
      const active = document.activeElement;
      if (e.shiftKey && (active === first || active === box)) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && active === last) {
        e.preventDefault();
        first.focus();
      }
    };
    box.addEventListener('keydown', onKeyDown);

    return () => {
      box.removeEventListener('keydown', onKeyDown);
      document.body.style.overflow = prevOverflow;
      previouslyFocused?.focus?.();      // restaure le focus à l'élément d'origine
    };
  }, [modalMac]);

  if (!device) return null;

  const save = async () => {
    const mac = device.mac;
    const meta = snapshot.asset_types[assetType];
    // Mise à jour optimiste immédiate + fermeture (aucune attente perceptible).
    patchDeviceLocal(mac, {
      label: label.trim() || null,
      asset_type: assetType,
      type_label: meta?.label ?? device.type_label,
      criticality,
      notes,
      trusted,
      display_name: label.trim() || device.hostname || device.ip || mac,
    });
    closeModal();
    try {
      await updateDevice(mac, {
        label,
        asset_type: assetType,
        criticality,
        notes,
        trusted,
      });
      pushToast('Actif mis à jour.', 'ok');
    } catch (e) {
      pushToast((e as Error).message, 'error');
    }
  };

  const forget = async () => {
    if (!window.confirm(`Retirer « ${device.display_name} » de l'inventaire ?`)) return;
    const mac = device.mac;
    removeDeviceLocal(mac); // disparaît immédiatement de la liste
    closeModal();
    try {
      await forgetDevice(mac);
      pushToast("Actif retiré de l'inventaire.", 'ok');
    } catch (e) {
      pushToast((e as Error).message, 'error');
    }
  };

  const canQuarantine = !device.is_gateway && !device.is_local_host && !device.trusted;

  const toggleQuarantine = async () => {
    const mac = device.mac;
    const wasQuarantined = device.quarantined;
    if (!wasQuarantined) {
      const ok = window.confirm(
        `Isoler « ${device.display_name || device.ip} » ?\n\n` +
          `Blocage du trafic entre ce poste et ${device.ip} au pare-feu local. ` +
          `Réversible, aucune trame ARP forgée.`,
      );
      if (!ok) return;
    }
    patchDeviceLocal(mac, { quarantined: !wasQuarantined }); // instantané
    closeModal();
    try {
      if (wasQuarantined) {
        await releaseDevice(mac);
        pushToast('Quarantaine levée.', 'ok');
      } else {
        const r = await quarantineDevice(mac);
        patchDeviceLocal(mac, { quarantine_enforced: r.enforced });
        pushToast(r.enforced ? 'Actif isolé.' : 'Quarantaine enregistrée.', r.enforced ? 'ok' : 'warn');
      }
    } catch (e) {
      patchDeviceLocal(mac, { quarantined: wasQuarantined }); // rollback
      pushToast((e as Error).message, 'error');
    }
  };

  return (
    <div className="modal">
      <div className="modal__backdrop" onClick={closeModal} aria-hidden="true" />
      <div
        className="modal__box glass"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={subId}
        ref={boxRef}
        tabIndex={-1}
      >
        <header className="modal__head">
          <div>
            <h3 id={titleId}>{device.display_name || device.ip || device.mac}</h3>
            <p className="modal__sub" id={subId}>
              {device.mac} · {device.ip || '—'} · {device.vendor || 'fabricant inconnu'}
            </p>
          </div>
          <button className="btn btn--icon" onClick={closeModal} aria-label="Fermer">
            ✕
          </button>
        </header>

        <div className="modal__body">
          <div className="modal__grid">
            <label className="field">
              <span>Libellé de l'actif</span>
              <input
                type="text"
                value={label}
                onChange={(e) => setLabel(e.target.value)}
                placeholder="ex. Poste comptabilité — Marie"
              />
            </label>
            <label className="field">
              <span>Catégorie</span>
              <select value={assetType} onChange={(e) => setAssetType(e.target.value)}>
                {Object.entries(snapshot.asset_types).map(([key, meta]) => (
                  <option key={key} value={key}>
                    {meta.icon} {meta.label}
                  </option>
                ))}
              </select>
            </label>
            <label className="field">
              <span>Criticité métier</span>
              <select
                value={criticality}
                onChange={(e) => setCriticality(e.target.value as Criticality)}
              >
                <option value="low">Faible</option>
                <option value="medium">Moyenne</option>
                <option value="high">Élevée</option>
                <option value="critical">Vitale</option>
              </select>
            </label>
            <label className="field field--switch">
              <span>Actif approuvé (liste blanche)</span>
              <input
                type="checkbox"
                checked={trusted}
                onChange={(e) => setTrusted(e.target.checked)}
              />
              <i className="switch" aria-hidden="true" />
            </label>
            <label className="field field--full">
              <span>Notes d'investigation</span>
              <textarea
                rows={3}
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                placeholder="Contexte, propriétaire, ticket associé…"
              />
            </label>
          </div>

          <Evidence device={device} />
          <TechSheet device={device} />
        </div>

        <footer className="modal__foot">
          <button className="btn btn--danger-ghost" onClick={forget}>
            Retirer de l'inventaire
          </button>
          <button
            className="btn btn--danger-ghost"
            onClick={toggleQuarantine}
            disabled={!device.quarantined && !canQuarantine}
            title={
              device.quarantined || canQuarantine
                ? ''
                : 'Isolation impossible : passerelle, sonde ou actif approuvé.'
            }
          >
            {device.quarantined ? '⛔ Lever l’isolation' : "Isoler l'appareil"}
          </button>
          <div className="spacer" />
          <button className="btn btn--ghost" onClick={closeModal}>
            Annuler
          </button>
          <button className="btn btn--primary" onClick={save}>
            Enregistrer
          </button>
        </footer>
      </div>
    </div>
  );
}

function Evidence({ device }: { device: Device }) {
  return (
    <section className="evidence">
      <h4>Faisceau de preuves du moteur de typage</h4>
      <ul>
        {device.type_evidence.length === 0 && (
          <li className="empty">Aucune preuve enregistrée pour cet actif.</li>
        )}
        {device.type_evidence.map((e, i) => (
          <li key={i}>
            <span className="ev-src">{e.source}</span>
            <span>{e.detail}</span>
            <span className="ev-weight">+{e.weight}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}

function TechSheet({ device }: { device: Device }) {
  const ports = device.open_ports.length
    ? device.open_ports.map((p) => `tcp/${p}`).join(', ')
    : 'aucun service détecté';
  const quarantine = device.quarantined
    ? `isolé depuis ${device.quarantined_at ?? '—'}` +
      (device.quarantine_enforced ? ' (pare-feu appliqué)' : ' (non appliqué)')
    : 'non isolé';

  const rows: [string, string | number][] = [
    ['Adresse MAC', device.mac],
    ['Préfixe OUI', device.mac.slice(0, 8)],
    ['Fabricant résolu', device.vendor],
    ['Source de résolution', device.vendor_source],
    ['Nom d’hôte (DNS)', device.hostname || 'non résolu'],
    ['Confiance du typage', `${device.type_confidence} %`],
    ['Score de risque', `${device.risk_score} / 100`],
    ['Quarantaine', quarantine],
    ['Services exposés', ports],
    ['Découvert le', device.first_seen_iso],
    ['Dernière observation', device.last_seen_iso],
    ['Occurrences', device.seen_count],
    ['Drapeaux', device.flags.join(', ') || '—'],
    [
      'Historique IP',
      device.ip_history.map((h) => `${h.ip} (${h.at})`).join(' → ') || '—',
    ],
  ];

  return (
    <section className="evidence">
      <h4>Empreinte technique</h4>
      <dl className="kv">
        {rows.map(([k, v]) => (
          <div key={k} style={{ display: 'contents' }}>
            <dt>{k}</dt>
            <dd>{v}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}
