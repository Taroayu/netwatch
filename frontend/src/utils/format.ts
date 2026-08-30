/* ==========================================================================
   NetWatch Console — utilitaires de formatage (localisés FR)
   ========================================================================== */

export function relativeTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return '—';
  const delta = Math.max(0, Math.floor((Date.now() - then) / 1000));
  if (delta < 5) return "à l'instant";
  if (delta < 60) return `il y a ${delta} s`;
  if (delta < 3600) return `il y a ${Math.floor(delta / 60)} min`;
  if (delta < 86400) return `il y a ${Math.floor(delta / 3600)} h`;
  return `il y a ${Math.floor(delta / 86400)} j`;
}

export function shortTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleTimeString('fr-FR', { hour12: false });
}

export function duration(seconds: number | null | undefined): string {
  const s = Math.max(0, Math.floor(seconds ?? 0));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  return h ? `${h} h ${String(m).padStart(2, '0')}` : `${m} min`;
}

/** Tri naturel d'une adresse IPv4. */
export function ipToNumber(ip: string): number {
  return ip
    .split('.')
    .reduce((acc, part) => acc * 256 + (parseInt(part, 10) || 0), 0);
}

/** Libellé lisible de la source de résolution du fabricant. */
export function vendorSourceLabel(source: string): string {
  const map: Record<string, string> = {
    manuf: 'OUI Wireshark',
    netaddr: 'Registre IEEE',
    'mac-vendor-lookup': 'OUI IEEE',
    'virtual-oui': 'Hyperviseur',
    'locally-administered': 'MAC privée',
    fallback: 'Base locale',
    none: 'Non résolu',
  };
  return map[source] ?? source;
}
