import { describe, expect, it } from 'vitest';
import { compareVersions, inRange, isVersion } from '../src/version';

describe('compareVersions (PHP version_compare semantics)', () => {
  it.each([
    ['5.3.1', '5.3.2', -1],
    ['5.3.10', '5.3.9', 1],
    ['6.4', '6.4.0', -1],
    ['6.4.0', '6.4', 1],
    ['6.4', '6.4', 0],
    ['6.4-RC1', '6.4', -1],
    ['6.4-beta2', '6.4-RC1', -1],
    ['6.4-alpha', '6.4-beta', -1],
    ['1.0-dev', '1.0-alpha', -1],
    ['1.0pl1', '1.0', 1],
    ['2.0.0', '10.0.0', -1],
    ['3.17.3', '3.17.3', 0],
    ['1.2.3.4', '1.2.3', 1],
  ])('%s vs %s = %i', (a, b, expected) => {
    expect(compareVersions(a, b)).toBe(expected);
    expect(compareVersions(b, a)).toBe(-expected || 0);
  });
});

describe('inRange', () => {
  it('handles inclusive and exclusive bounds', () => {
    expect(inRange('5.3.1', { to: '5.3.1' })).toBe(true);
    expect(inRange('5.3.1', { to: '5.3.1', toInclusive: false })).toBe(false);
    expect(inRange('5.3.2', { to: '5.3.1' })).toBe(false);
    expect(inRange('4.0', { from: '4.0', fromInclusive: false, to: '5.0' })).toBe(false);
    expect(inRange('4.1', { from: '4.0', to: '5.0' })).toBe(true);
  });

  it("treats '*' and missing bounds as open", () => {
    expect(inRange('0.1', { from: '*', to: '1.0' })).toBe(true);
    expect(inRange('99.0', { from: '2.0', to: '*' })).toBe(true);
    expect(inRange('1.0', {})).toBe(true);
  });
});

describe('isVersion', () => {
  it.each(['6.4.2', '5.3', '1.0.0-beta.1', '2023.11.05'])('accepts %s', (v) => expect(isVersion(v)).toBe(true));
  it.each(['', 'trunk', 'latest', 'v1.0', '<script>', '1.0 ; drop', 'x'.repeat(50)])('rejects %s', (v) => expect(isVersion(v)).toBe(false));
});
