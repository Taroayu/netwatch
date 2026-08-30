/* ==========================================================================
   NetWatch Console — point d'entrée
   ========================================================================== */

import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import './styles/theme.css';

// Applique le thème AVANT le premier rendu, pour éviter tout « flash » de thème
// clair chez les utilisateurs en mode sombre. (Exécuté depuis le bundle, donc
// conforme à la CSP `script-src 'self'` — aucun script en ligne requis.)
(function initTheme() {
  try {
    const stored = localStorage.getItem('netwatch-theme');
    const dark = stored
      ? stored === 'dark'
      : window.matchMedia('(prefers-color-scheme: dark)').matches;
    document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light');
  } catch {
    document.documentElement.setAttribute('data-theme', 'light');
  }
})();

const container = document.getElementById('root');
if (!container) throw new Error('Élément racine #root introuvable.');

createRoot(container).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
