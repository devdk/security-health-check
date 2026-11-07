/**
 * Minimal JSON-over-HTTPS client for the intel sources. These are fixed, trusted hosts
 * (not user input), so the scanner's SSRF machinery isn't needed; size and time limits are.
 */
export interface JsonResponse {
  status: number;
  json: unknown;
}

export type FetchJson = (url: string, init?: { headers?: Record<string, string>; timeoutMs?: number; maxBytes?: number }) => Promise<JsonResponse>;

export class IntelError extends Error {
  constructor(
    message: string,
    public readonly status?: number,
  ) {
    super(message);
    this.name = 'IntelError';
  }
}

export const USER_AGENT = 'SecurityHealthCheck/0.1 (vulnerability intel sync)';

export const fetchJson: FetchJson = async (url, init = {}) => {
  if (!url.startsWith('https://')) throw new IntelError(`Refusing non-HTTPS intel URL ${url}`);
  const res = await fetch(url, {
    headers: { accept: 'application/json', 'user-agent': USER_AGENT, ...init.headers },
    signal: AbortSignal.timeout(init.timeoutMs ?? 60_000),
    redirect: 'error',
  });
  const maxBytes = init.maxBytes ?? 50 * 1024 * 1024;
  const declared = Number(res.headers.get('content-length') ?? 0);
  if (declared > maxBytes) throw new IntelError(`Response from ${new URL(url).host} is too large (${declared} bytes)`);

  const reader = res.body?.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  if (reader) {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) {
        await reader.cancel();
        throw new IntelError(`Response from ${new URL(url).host} exceeded ${maxBytes} bytes`);
      }
      chunks.push(value);
    }
  }
  const body = Buffer.concat(chunks).toString('utf8');
  let json: unknown = null;
  try {
    json = body.length > 0 ? JSON.parse(body) : null;
  } catch {
    if (res.ok) throw new IntelError(`Invalid JSON from ${new URL(url).host}`, res.status);
  }
  return { status: res.status, json };
};
