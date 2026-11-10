import { describe, expect, it } from 'vitest';
import { ConfigError, loadConfig } from '../src/index';

const base = {
  DATABASE_URL: 'postgres://u:p@localhost:5432/db',
  REDIS_URL: 'redis://localhost:6379/0',
};

describe('loadConfig', () => {
  it('applies safe defaults in development', () => {
    const config = loadConfig(base);
    expect(config.nodeEnv).toBe('development');
    expect(config.api.port).toBe(3000);
    expect(config.api.trustProxyHops).toBe(0);
    expect(config.session.cookieSecure).toBe(true);
    expect(config.web.allowedOrigins).toEqual(['http://localhost:8080']);
  });

  it('reports every missing required value at once', () => {
    try {
      loadConfig({});
      expect.unreachable();
    } catch (err) {
      expect(err).toBeInstanceOf(ConfigError);
      const problems = (err as ConfigError).problems.join('\n');
      expect(problems).toContain('DATABASE_URL is required');
      expect(problems).toContain('REDIS_URL is required');
    }
  });

  it('rejects malformed values', () => {
    expect(() => loadConfig({ ...base, API_PORT: 'eighty' })).toThrow(/API_PORT/);
    expect(() => loadConfig({ ...base, DATABASE_URL: 'mysql://x' })).toThrow(/DATABASE_URL/);
    expect(() => loadConfig({ ...base, COOKIE_SECURE: 'maybe' })).toThrow(/COOKIE_SECURE/);
  });

  it('enforces https and secure cookies in production', () => {
    expect(() => loadConfig({ ...base, NODE_ENV: 'production', WEB_BASE_URL: 'http://example.com' })).toThrow(/https/);
    expect(() =>
      loadConfig({ ...base, NODE_ENV: 'production', WEB_BASE_URL: 'https://example.com', COOKIE_SECURE: 'false' }),
    ).toThrow(/COOKIE_SECURE/);
    expect(loadConfig({ ...base, NODE_ENV: 'production', WEB_BASE_URL: 'https://app.example.com' }).web.baseUrl).toBe(
      'https://app.example.com',
    );
  });

  it('builds the origin allowlist from the web URL plus extras', () => {
    const config = loadConfig({
      ...base,
      WEB_BASE_URL: 'http://localhost:5173/',
      EXTRA_ALLOWED_ORIGINS: 'http://localhost:8080, https://staging.example.com/path',
    });
    expect(config.web.baseUrl).toBe('http://localhost:5173');
    expect(config.web.allowedOrigins).toEqual(['http://localhost:5173', 'http://localhost:8080', 'https://staging.example.com']);
  });

  it('never allows more than 2 requests per second per scanned site', () => {
    expect(loadConfig(base).scan.ratePerSecond).toBe(2);
    expect(() => loadConfig({ ...base, SCAN_RATE_PER_SECOND: '5' })).toThrow(/SCAN_RATE_PER_SECOND/);
  });

  it('requires the scanner User-Agent to name the product', () => {
    expect(loadConfig(base).scanner.userAgent).toMatch(/^SecurityHealthCheck\//);
    expect(() => loadConfig({ ...base, SCANNER_USER_AGENT: 'Mozilla/5.0' })).toThrow(/must name the product/);
  });

  it('refuses private-host allowances in production', () => {
    expect(() =>
      loadConfig({ ...base, NODE_ENV: 'production', WEB_BASE_URL: 'https://app.example.com', SCAN_ALLOW_PRIVATE_HOSTS: 'wordpress.test' }),
    ).toThrow(/SCAN_ALLOW_PRIVATE_HOSTS/);
  });

  it('never allows the instant-upgrade payment stub in production', () => {
    expect(loadConfig(base).payments.provider).toBe('stub');
    expect(loadConfig({ ...base, NODE_ENV: 'production', WEB_BASE_URL: 'https://app.example.com' }).payments.provider).toBe('none');
    expect(() => loadConfig({ ...base, NODE_ENV: 'production', WEB_BASE_URL: 'https://app.example.com', PAYMENTS_PROVIDER: 'stub' })).toThrow(/not allowed in production/);
  });

  it('returns a frozen object', () => {
    expect(Object.isFrozen(loadConfig(base))).toBe(true);
  });
});
