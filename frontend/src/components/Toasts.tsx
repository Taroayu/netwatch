/* ==========================================================================
   NetWatch Console — notifications éphémères (toasts)
   ========================================================================== */

import { useEffect } from 'react';
import { useStore } from '../store/useStore';
import type { ToastKind } from '../store/useStore';

const ICONS: Record<ToastKind, string> = { ok: '✓', warn: '⚠', error: '⛊' };

export function Toasts() {
  const toasts = useStore((s) => s.toasts);
  const dismiss = useStore((s) => s.dismissToast);

  return (
    <div className="toasts" aria-live="polite">
      {toasts.map((t) => (
        <ToastItem key={t.id} id={t.id} kind={t.kind} message={t.message} onDone={dismiss} />
      ))}
    </div>
  );
}

function ToastItem({
  id,
  kind,
  message,
  onDone,
}: {
  id: number;
  kind: ToastKind;
  message: string;
  onDone: (id: number) => void;
}) {
  useEffect(() => {
    const ttl = kind === 'error' ? 7000 : 4200;
    const timer = window.setTimeout(() => onDone(id), ttl);
    return () => window.clearTimeout(timer);
  }, [id, kind, onDone]);

  return (
    <div className={`toast toast--${kind}`} onClick={() => onDone(id)}>
      <span className="toast__ico">{ICONS[kind]}</span>
      <span>{message}</span>
    </div>
  );
}
