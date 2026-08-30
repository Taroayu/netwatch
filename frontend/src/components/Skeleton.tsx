/* ==========================================================================
   NetWatch Console — squelette de chargement (skeleton screen)
   --------------------------------------------------------------------------
   Affiché pendant l'établissement du flux temps réel, à la place d'un simple
   spinner. En épousant la mise en page réelle (tuiles KPI + tableau + colonne
   latérale), il réduit le décalage de contenu et donne une perception de
   rapidité (moins d'anxiété d'attente — recherche en psychologie cognitive).
   Purement décoratif : masqué aux lecteurs d'écran.
   ========================================================================== */

export function Skeleton() {
  return (
    <div className="sk" aria-hidden="true">
      {/* Tuiles KPI */}
      <div className="sk-kpis">
        {Array.from({ length: 6 }).map((_, i) => (
          <div key={i} className="sk-card">
            <div className="sk-line sk-line--label" />
            <div className="sk-line sk-line--value" />
            <div className="sk-line sk-line--sub" />
          </div>
        ))}
      </div>

      {/* Espace de travail : tableau + colonne latérale */}
      <div className="sk-workspace">
        <div className="sk-card sk-panel">
          <div className="sk-line sk-line--title" />
          {Array.from({ length: 8 }).map((_, i) => (
            <div key={i} className="sk-row">
              <span className="sk-dot" />
              <span className="sk-line sk-line--cell" style={{ width: '26%' }} />
              <span className="sk-line sk-line--cell" style={{ width: '18%' }} />
              <span className="sk-line sk-line--cell" style={{ width: '22%' }} />
              <span className="sk-line sk-line--cell" style={{ width: '12%' }} />
            </div>
          ))}
        </div>
        <div className="sk-side">
          <div className="sk-card sk-donut">
            <div className="sk-circle" />
          </div>
          <div className="sk-card sk-panel">
            <div className="sk-line sk-line--title" />
            {Array.from({ length: 4 }).map((_, i) => (
              <div key={i} className="sk-alert">
                <div className="sk-line" style={{ width: '70%' }} />
                <div className="sk-line sk-line--sub" style={{ width: '90%' }} />
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
