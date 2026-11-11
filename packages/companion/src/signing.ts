import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

export const SIGNATURE_SCHEME = 'SHC-HMAC-SHA256-V1';
/** The only signed endpoint. Fixed here and in the plugin, so a proxy rewriting paths can't break it. */
export const REPORTS_PATH = '/api/plugin/reports';
export const MAX_CLOCK_SKEW_SECONDS = 300;

export const SIGNED_HEADERS = {
  keyId: 'x-shc-key-id',
  timestamp: 'x-shc-timestamp',
  nonce: 'x-shc-nonce',
  signature: 'x-shc-signature',
} as const;

export interface SignedRequest {
  method: string;
  path: string;
  /** Unix time in seconds. */
  timestamp: number;
  nonce: string;
  /** The raw request body exactly as sent. */
  body: string | Uint8Array;
}

export const sha256Hex = (data: string | Uint8Array) => createHash('sha256').update(data).digest('hex');

export function stringToSign(req: SignedRequest): string {
  return [SIGNATURE_SCHEME, req.method.toUpperCase(), req.path, String(req.timestamp), req.nonce, sha256Hex(req.body)].join('\n');
}

/** Header value: "v1=" followed by the hex HMAC-SHA256 of stringToSign, keyed with the site key's text. */
export function signRequest(key: string, req: SignedRequest): string {
  return `v1=${createHmac('sha256', key).update(stringToSign(req)).digest('hex')}`;
}

export function verifySignature(key: string, req: SignedRequest, header: string): boolean {
  const expected = Buffer.from(signRequest(key, req));
  const given = Buffer.from(header);
  return expected.length === given.length && timingSafeEqual(expected, given);
}

export const isFresh = (timestamp: number, now: Date = new Date()) => Math.abs(now.getTime() / 1000 - timestamp) <= MAX_CLOCK_SKEW_SECONDS;

export type SignedHeaders = { keyId: string; timestamp: number; nonce: string; signature: string };

/** Reads and shape-checks the four signing headers. Nothing here proves anything yet. */
export function readSignedHeaders(headers: Record<string, string | string[] | undefined>): SignedHeaders | null {
  const one = (name: string) => {
    const v = headers[name];
    return typeof v === 'string' ? v : undefined;
  };
  const keyId = one(SIGNED_HEADERS.keyId);
  const timestamp = one(SIGNED_HEADERS.timestamp);
  const nonce = one(SIGNED_HEADERS.nonce);
  const signature = one(SIGNED_HEADERS.signature);
  if (
    !keyId ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(keyId) ||
    !timestamp ||
    !/^\d{1,12}$/.test(timestamp) ||
    !nonce ||
    !/^[A-Za-z0-9_-]{16,64}$/.test(nonce) ||
    !signature ||
    !/^v1=[0-9a-f]{64}$/.test(signature)
  ) {
    return null;
  }
  return { keyId, timestamp: Number(timestamp), nonce, signature };
}
