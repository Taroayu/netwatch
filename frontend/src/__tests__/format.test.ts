import { describe, it, expect } from 'vitest';
import {
  relativeTime,
  shortTime,
  duration,
  ipToNumber,
  vendorSourceLabel,
} from '../utils/format';

describe('format', () => {
  it('relativeTime gère les cas vides et récents', () => {
    expect(relativeTime(null)).toBe('—');
    expect(relativeTime(new Date().toISOString())).toBe("à l'instant");
    const old = new Date(Date.now() - 3 * 3600 * 1000).toISOString();
    expect(relativeTime(old)).toContain('il y a 3 h');
  });

  it('shortTime renvoie — pour une date invalide', () => {
    expect(shortTime('pas-une-date')).toBe('—');
  });

  it('duration formlate minutes et heures', () => {
    expect(duration(0)).toBe('0 min');
    expect(duration(90)).toBe('1 min');
    expect(duration(3660)).toBe('1 h 01');
  });

  it('ipToNumber trie correctement les IPv4', () => {
    expect(ipToNumber('192.168.1.10')).toBeGreaterThan(ipToNumber('192.168.1.2'));
    expect(ipToNumber('10.0.0.1')).toBeLessThan(ipToNumber('10.0.1.0'));
  });

  it('vendorSourceLabel traduit les sources connues', () => {
    expect(vendorSourceLabel('netaddr')).toBe('Registre IEEE');
    expect(vendorSourceLabel('inconnu-x')).toBe('inconnu-x');
  });
});
