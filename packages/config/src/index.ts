/**
 * The only module that reads process.env. Every service calls loadConfig() once at
 * startup; invalid or missing values stop the process with a clear message instead of
 * failing later at runtime. Secrets never have defaults.
 */

export type NodeEnv = 'development' | 'test' | 'production';
export type LogLevel = 'fatal' | 'error' | 'warn' | 'info' | 'debug' | 'trace' | 'silent';

export interface Config {
  nodeEnv: NodeEnv;
  logLevel: LogLevel;
  databaseUrl: string;
  redisUrl: string;
  api: {
    host: string;
    port: number;
    /** Number of trusted reverse-proxy hops in front of the API (0 = none). */
    trustProxyHops: number;
  };
  web: {
    /** Public base URL of the dashboard, used for links in emails. */
    baseUrl: string;
    /** Origins allowed to make state-changing requests with a session cookie. */
    allowedOrigins: string[];
  };
  session: {
    cookieName: string;
    cookieSecure: boolean;
    ttlHours: number;
  };
  rateLimit: {
    globalPerMinute: number;
    authPerMinute: number;
  };
  mail: {
    transport: 'console';
    from: string;
  };
}

export class ConfigError extends Error {
  constructor(public readonly problems: string[]) {
    super(`Invalid configuration:\n  - ${problems.join('\n  - ')}`);
    this.name = 'ConfigError';
  }
}

type Env = Record<string, string | undefined>;

const LOG_LEVELS: readonly LogLevel[] = ['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent'];
const NODE_ENVS: readonly NodeEnv[] = ['development', 'test', 'production'];

class Reader {
  readonly problems: string[] = [];
  constructor(private readonly env: Env) {}

  private raw(name: string): string | undefined {
    const v = this.env[name];
    return v === undefined || v.trim() === '' ? undefined : v.trim();
  }

  string(name: string, fallback?: string): string {
    const v = this.raw(name) ?? fallback;
    if (v === undefined) {
      this.problems.push(`${name} is required`);
      return '';
    }
    return v;
  }

  oneOf<T extends string>(name: string, allowed: readonly T[], fallback: T): T {
    const v = this.raw(name) ?? fallback;
    if (!(allowed as readonly string[]).includes(v)) {
      this.problems.push(`${name} must be one of: ${allowed.join(', ')}`);
      return fallback;
    }
    return v as T;
  }

  int(name: string, fallback: number, min: number, max: number): number {
    const v = this.raw(name);
    if (v === undefined) return fallback;
    const n = Number(v);
    if (!Number.isInteger(n) || n < min || n > max) {
      this.problems.push(`${name} must be an integer between ${min} and ${max}`);
      return fallback;
    }
    return n;
  }

  bool(name: string, fallback: boolean): boolean {
    const v = this.raw(name);
    if (v === undefined) return fallback;
    if (v === 'true' || v === '1') return true;
    if (v === 'false' || v === '0') return false;
    this.problems.push(`${name} must be true or false`);
    return fallback;
  }

  url(name: string, protocols: string[], fallback?: string): string {
    const v = this.string(name, fallback);
    if (!v) return v;
    try {
      const u = new URL(v);
      if (!protocols.includes(u.protocol)) {
        this.problems.push(`${name} must use one of: ${protocols.join(', ')}`);
      }
    } catch {
      this.problems.push(`${name} must be a valid URL`);
    }
    return v;
  }
}

function originOf(url: string): string | undefined {
  try {
    return new URL(url).origin;
  } catch {
    return undefined;
  }
}

export function loadConfig(env: Env = process.env): Config {
  const r = new Reader(env);
  const nodeEnv = r.oneOf('NODE_ENV', NODE_ENVS, 'development');
  const isProd = nodeEnv === 'production';

  const webBaseUrl = r.url('WEB_BASE_URL', ['http:', 'https:'], isProd ? undefined : 'http://localhost:8080');
  const extraOrigins = (env.EXTRA_ALLOWED_ORIGINS ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

  const allowedOrigins: string[] = [];
  for (const candidate of [webBaseUrl, ...extraOrigins]) {
    const origin = originOf(candidate);
    if (origin) allowedOrigins.push(origin);
    else if (candidate) r.problems.push(`Not a valid origin: ${candidate}`);
  }

  const config: Config = {
    nodeEnv,
    logLevel: r.oneOf('LOG_LEVEL', LOG_LEVELS, isProd ? 'info' : 'debug'),
    databaseUrl: r.url('DATABASE_URL', ['postgres:', 'postgresql:']),
    redisUrl: r.url('REDIS_URL', ['redis:', 'rediss:']),
    api: {
      host: r.string('API_HOST', '0.0.0.0'),
      port: r.int('API_PORT', 3000, 1, 65535),
      trustProxyHops: r.int('TRUST_PROXY_HOPS', 0, 0, 5),
    },
    web: {
      baseUrl: webBaseUrl.replace(/\/+$/, ''),
      allowedOrigins: [...new Set(allowedOrigins)],
    },
    session: {
      cookieName: 'shc_session',
      cookieSecure: r.bool('COOKIE_SECURE', true),
      ttlHours: r.int('SESSION_TTL_HOURS', 24 * 7, 1, 24 * 30),
    },
    rateLimit: {
      globalPerMinute: r.int('RATE_LIMIT_GLOBAL_PER_MINUTE', 300, 10, 100_000),
      authPerMinute: r.int('RATE_LIMIT_AUTH_PER_MINUTE', 10, 1, 10_000),
    },
    mail: {
      transport: r.oneOf('MAIL_TRANSPORT', ['console'] as const, 'console'),
      from: r.string('MAIL_FROM', 'Security Health Check <no-reply@localhost>'),
    },
  };

  if (isProd) {
    if (!config.session.cookieSecure) r.problems.push('COOKIE_SECURE must be true in production');
    if (!config.web.baseUrl.startsWith('https://')) r.problems.push('WEB_BASE_URL must use https in production');
  }

  if (r.problems.length > 0) throw new ConfigError(r.problems);
  return Object.freeze(config);
}
