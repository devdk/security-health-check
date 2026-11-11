import { createHash, createHmac } from 'node:crypto';

/**
 * A site key is derived from the server secret and the key id, so the server can
 * recompute it to check a signature without ever storing it. Only its hash is kept,
 * which ties the key to the secret that issued it.
 */
export function deriveSiteKey(secret: string, keyId: string): string {
  return createHmac('sha256', secret).update(`shc-site-key/v1:${keyId}`).digest('base64url');
}

export function hashSiteKey(key: string): string {
  return createHash('sha256').update(key).digest('hex');
}
