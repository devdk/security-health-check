import tls, { type DetailedPeerCertificate } from 'node:tls';
import { NetError, toNetError } from './errors';
import type { SafeFetcher } from './safe-fetch';

export interface CertificateInfo {
  subjectCN: string | null;
  issuer: string | null;
  validFrom: string;
  validTo: string;
  daysRemaining: number;
  altNames: string[];
  selfSigned: boolean;
}

export interface TlsInspection {
  /** Negotiated protocol, e.g. TLSv1.3 */
  protocol: string | null;
  /** Chain validates against the system trust store (ignoring hostname). */
  trusted: boolean;
  /** OpenSSL's reason when not trusted, e.g. CERT_HAS_EXPIRED. */
  trustError: string | null;
  hostnameMatches: boolean;
  certificate: CertificateInfo | null;
}

export interface ProbeOptions {
  /** Awaited after DNS resolution, immediately before connecting (rate limiting). */
  beforeConnect?: () => Promise<void>;
}

/** Inspects a site's HTTPS endpoint. Implemented by TlsProber; faked in tests. */
export interface TlsProbe {
  inspect(host: string, options?: ProbeOptions): Promise<TlsInspection>;
  /** True when the server completes a handshake capped at TLS 1.1. */
  acceptsLegacyTls(host: string, options?: ProbeOptions): Promise<boolean>;
}

function describeCertificate(cert: DetailedPeerCertificate): CertificateInfo {
  const validTo = new Date(cert.valid_to);
  const altNames = (cert.subjectaltname ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.startsWith('DNS:'))
    .map((s) => s.slice(4));
  const field = (o: Record<string, string | string[] | undefined> | undefined, k: string) => {
    const v = o?.[k];
    return Array.isArray(v) ? (v[0] ?? null) : (v ?? null);
  };
  const issuer = field(cert.issuer as never, 'O') ?? field(cert.issuer as never, 'CN');
  return {
    subjectCN: field(cert.subject as never, 'CN'),
    issuer,
    validFrom: new Date(cert.valid_from).toISOString(),
    validTo: validTo.toISOString(),
    daysRemaining: Math.floor((validTo.getTime() - Date.now()) / 86_400_000),
    altNames: altNames.slice(0, 20),
    selfSigned: cert.fingerprint256 === cert.issuerCertificate?.fingerprint256,
  };
}

/**
 * TLS inspection with the same SSRF protection as SafeFetcher: the host is resolved and
 * vetted by the fetcher's policy, and the socket connects to that exact address.
 */
export class TlsProber implements TlsProbe {
  constructor(
    private readonly resolver: Pick<SafeFetcher, 'resolve'>,
    private readonly options: { port?: number; timeoutMs?: number } = {},
  ) {}

  private async connect(host: string, extra: tls.ConnectionOptions, options: ProbeOptions = {}): Promise<tls.TLSSocket> {
    const target = await this.resolver.resolve(host);
    if (options.beforeConnect) await options.beforeConnect();
    return new Promise((resolve, reject) => {
      const socket = tls.connect({
        host: target.address,
        port: this.options.port ?? 443,
        servername: host,
        // We inspect the certificate ourselves, so the handshake must not abort on problems.
        rejectUnauthorized: false,
        ...extra,
      });
      const timer = setTimeout(() => socket.destroy(new NetError('timeout', 'TLS handshake timed out')), this.options.timeoutMs ?? 10_000);
      socket.once('secureConnect', () => {
        clearTimeout(timer);
        resolve(socket);
      });
      socket.once('error', (err) => {
        clearTimeout(timer);
        reject(toNetError(err, `tls://${host}`));
      });
    });
  }

  async inspect(host: string, options: ProbeOptions = {}): Promise<TlsInspection> {
    const socket = await this.connect(host, {}, options);
    try {
      const cert = socket.getPeerCertificate(true);
      const hasCert = cert && Object.keys(cert).length > 0;
      return {
        protocol: socket.getProtocol(),
        trusted: socket.authorized,
        trustError: socket.authorizationError ? String(socket.authorizationError) : null,
        hostnameMatches: hasCert ? tls.checkServerIdentity(host, cert) === undefined : false,
        certificate: hasCert ? describeCertificate(cert) : null,
      };
    } finally {
      socket.destroy();
    }
  }

  async acceptsLegacyTls(host: string, options: ProbeOptions = {}): Promise<boolean> {
    try {
      // OpenSSL 3 refuses TLS < 1.2 by default; lower the client's security level so the
      // question becomes "does the *server* still accept it?".
      const socket = await this.connect(host, { minVersion: 'TLSv1', maxVersion: 'TLSv1.1', ciphers: 'DEFAULT:@SECLEVEL=0' }, options);
      socket.destroy();
      return true;
    } catch (err) {
      if (err instanceof NetError && (err.code === 'blocked_address' || err.code === 'dns_failed')) throw err;
      return false;
    }
  }
}
