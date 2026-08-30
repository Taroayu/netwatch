import { describe, it, expect, beforeEach } from 'vitest';
import { useStore } from '../store/useStore';

const reset = () =>
  useStore.setState({
    sortKey: 'risk_score',
    sortDir: 'desc',
    search: '',
    filterType: '',
    filterState: '',
    alertFilter: '',
    modalMac: null,
    toasts: [],
    authed: false,
  });

describe('useStore', () => {
  beforeEach(reset);

  it('setSort bascule le sens sur la même colonne', () => {
    const { setSort } = useStore.getState();
    setSort('risk_score'); // déjà la colonne courante -> inverse
    expect(useStore.getState().sortDir).toBe('asc');
    setSort('risk_score');
    expect(useStore.getState().sortDir).toBe('desc');
  });

  it('setSort choisit un sens par défaut sensé selon la colonne', () => {
    const { setSort } = useStore.getState();
    setSort('display_name'); // texte -> ascendant
    expect(useStore.getState().sortKey).toBe('display_name');
    expect(useStore.getState().sortDir).toBe('asc');
    setSort('online'); // non-texte -> descendant
    expect(useStore.getState().sortDir).toBe('desc');
  });

  it('gère les toasts (ajout + suppression)', () => {
    const { pushToast } = useStore.getState();
    pushToast('Bonjour', 'ok');
    const t = useStore.getState().toasts;
    expect(t).toHaveLength(1);
    expect(t[0]!.kind).toBe('ok');
    useStore.getState().dismissToast(t[0]!.id);
    expect(useStore.getState().toasts).toHaveLength(0);
  });

  it('ouvre et ferme la modale', () => {
    useStore.getState().openModal('aa:bb:cc:dd:ee:ff');
    expect(useStore.getState().modalMac).toBe('aa:bb:cc:dd:ee:ff');
    useStore.getState().closeModal();
    expect(useStore.getState().modalMac).toBeNull();
  });

  it('setAuth applique un patch partiel', () => {
    useStore.getState().setAuth({ authed: true });
    expect(useStore.getState().authed).toBe(true);
  });
});
