import { promises as dns } from 'node:dns';
import { NetError } from './errors';

export interface ResolvedAddress {
  address: string;
  family: 4 | 6;
}

/** Resolves a hostname to every address it maps to. */
export type HostResolver = (hostname: string) => Promise<ResolvedAddress[]>;

/** Returns each TXT record with its chunks joined; an empty list when there are none. */
export type TxtResolver = (name: string) => Promise<string[]>;

export const systemHostResolver: HostResolver = async (hostname) => {
  const results = await dns.lookup(hostname, { all: true, verbatim: true });
  return results.map((r) => ({ address: r.address, family: r.family === 6 ? 6 : 4 }));
};

const NOT_FOUND = new Set(['ENODATA', 'ENOTFOUND', 'NXDOMAIN', 'NOTFOUND']);

export function createTxtResolver(options: { servers?: string[]; timeoutMs?: number } = {}): TxtResolver {
  const resolver = new dns.Resolver({ timeout: options.timeoutMs ?? 4000, tries: 2 });
  if (options.servers && options.servers.length > 0) resolver.setServers(options.servers);

  return async (name) => {
    try {
      const records = await resolver.resolveTxt(name);
      return records.map((chunks) => chunks.join(''));
    } catch (err) {
      const code = (err as { code?: string }).code ?? '';
      if (NOT_FOUND.has(code)) return [];
      if (code === 'ETIMEOUT') throw new NetError('timeout', `DNS lookup for ${name} timed out`);
      throw new NetError('dns_failed', `DNS lookup for ${name} failed (${code || 'unknown error'})`);
    }
  };
}
