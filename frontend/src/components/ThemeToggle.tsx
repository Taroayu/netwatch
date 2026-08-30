/* ==========================================================================
   NetWatch Console — bascule de thème clair / sombre
   --------------------------------------------------------------------------
   • Au premier lancement, on suit la préférence système (prefers-color-scheme).
   • Le choix explicite de l'utilisateur est mémorisé (localStorage) et
     réappliqué à chaque visite.
   • Le thème est porté par l'attribut data-theme sur <html> ; seuls les jetons
     CSS changent (aucune duplication de règles).
   Tout accès au stockage est protégé (fenêtre privée, stockage désactivé…).
   ========================================================================== */

import { useEffect, useState } from 'react';

type Theme = 'light' | 'dark';
const STORAGE_KEY = 'netwatch-theme';

function readStored(): Theme | null {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    return v === 'light' || v === 'dark' ? v : null;
  } catch {
    return null;
  }
}

function systemTheme(): Theme {
  try {
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  } catch {
    return 'light';
  }
}

function applyTheme(theme: Theme): void {
  document.documentElement.setAttribute('data-theme', theme);
}

export function ThemeToggle() {
  const [theme, setTheme] = useState<Theme>(() => readStored() ?? systemTheme());

  // Applique le thème au montage et à chaque changement.
  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  // Si l'utilisateur n'a pas fait de choix explicite, on suit les changements
  // de préférence système en direct.
  useEffect(() => {
    if (readStored()) return;
    let mq: MediaQueryList;
    try {
      mq = window.matchMedia('(prefers-color-scheme: dark)');
    } catch {
      return;
    }
    const onChange = (e: MediaQueryListEvent) => setTheme(e.matches ? 'dark' : 'light');
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, []);

  const toggle = () => {
    const next: Theme = theme === 'dark' ? 'light' : 'dark';
    setTheme(next);
    try {
      localStorage.setItem(STORAGE_KEY, next);
    } catch {
      /* stockage indisponible : le thème reste actif pour la session */
    }
  };

  const goingDark = theme === 'light';
  return (
    <button
      className="btn btn--icon"
      onClick={toggle}
      aria-label={goingDark ? 'Activer le thème sombre' : 'Activer le thème clair'}
      title={goingDark ? 'Thème sombre' : 'Thème clair'}
    >
      <span aria-hidden="true">{goingDark ? '☾' : '☀'}</span>
    </button>
  );
}
