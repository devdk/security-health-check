export type NetErrorCode =
  | 'invalid_url'
  | 'blocked_scheme'
  | 'blocked_port'
  | 'blocked_address'
  | 'dns_failed'
  | 'timeout'
  | 'connect_failed'
  | 'tls_failed'
  | 'too_many_redirects'
  | 'redirect_blocked'
  | 'response_failed';

export class NetError extends Error {
  constructor(
    public readonly code: NetErrorCode,
    message: string,
    public readonly url?: string,
  ) {
    super(message);
    this.name = 'NetError';
  }
}

/** Translates low-level socket/TLS errors into a small set of stable codes. */
export function toNetError(err: unknown, url: string): NetError {
  if (err instanceof NetError) return err;
  const e = err as { code?: string; name?: string; message?: string };
  const code = e.code ?? '';
  if (e.name === 'AbortError' || code === 'ABORT_ERR' || code === 'ETIMEDOUT' || e.name === 'TimeoutError') {
    return new NetError('timeout', 'The request timed out', url);
  }
  if (/CERT|SSL|TLS/i.test(code)) return new NetError('tls_failed', `TLS error (${code})`, url);
  if (code.startsWith('HPE_')) return new NetError('response_failed', 'The server sent an invalid HTTP response', url);
  return new NetError('connect_failed', `Connection failed${code ? ` (${code})` : ''}`, url);
}
