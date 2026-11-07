import { NetError } from '@shc/net';
import type { CheckModule, Finding } from '../types';

export const EXPIRY_WARNING_DAYS = 21;

/**
 * Inspects the HTTPS certificate and protocol versions with Node's tls module, and checks
 * that plain-HTTP visitors are redirected to HTTPS. Three connections at most.
 */
export const tlsCheck: CheckModule = {
  id: 'tls',
  title: 'HTTPS and certificate',
  stage: 1,

  async run(target, ctx) {
    const host = new URL(target.baseUrl).hostname;
    const findings: Finding[] = [];

    let inspection;
    try {
      inspection = await ctx.http.tlsInspect(host);
    } catch (err) {
      if (!(err instanceof NetError)) throw err;
      // No working HTTPS at all.
      return [
        {
          checkId: 'tls.no-https',
          conceptId: 'exposure/https-not-enforced',
          severity: 'high',
          title: 'The site is not available over HTTPS',
          confidence: 'confirmed',
          evidence: { url: `https://${host}/`, detail: { error: err.code } },
        },
      ];
    }

    const cert = inspection.certificate;
    const certDetail = cert
      ? { issuer: cert.issuer, subject: cert.subjectCN, validTo: cert.validTo, daysRemaining: cert.daysRemaining, altNames: cert.altNames.slice(0, 5) }
      : {};

    if (cert && (cert.daysRemaining < 0 || inspection.trustError === 'CERT_HAS_EXPIRED')) {
      findings.push({
        checkId: 'tls.expired',
        conceptId: 'exposure/tls-certificate-expired',
        severity: 'high',
        title: `The HTTPS certificate expired on ${cert.validTo.slice(0, 10)}`,
        confidence: 'confirmed',
        evidence: { detail: certDetail },
      });
    } else if (cert && cert.daysRemaining <= EXPIRY_WARNING_DAYS) {
      findings.push({
        checkId: 'tls.expiring',
        conceptId: 'exposure/tls-certificate-expiring-soon',
        severity: 'low',
        title: `The HTTPS certificate expires in ${cert.daysRemaining} day${cert.daysRemaining === 1 ? '' : 's'}`,
        confidence: 'confirmed',
        evidence: { detail: certDetail },
      });
    }

    const untrusted = !inspection.trusted && inspection.trustError !== 'CERT_HAS_EXPIRED';
    if (untrusted || !inspection.hostnameMatches) {
      const reason = !inspection.hostnameMatches
        ? `does not cover ${host}`
        : cert?.selfSigned || inspection.trustError === 'DEPTH_ZERO_SELF_SIGNED_CERT'
          ? 'is self-signed'
          : 'is not issued by a trusted authority';
      findings.push({
        checkId: 'tls.untrusted',
        conceptId: 'exposure/tls-certificate-invalid',
        severity: 'high',
        title: `The HTTPS certificate ${reason}`,
        confidence: 'confirmed',
        evidence: { detail: { ...certDetail, trustError: inspection.trustError, hostnameMatches: inspection.hostnameMatches } },
      });
    }

    if (await ctx.http.tlsAcceptsLegacy(host)) {
      findings.push({
        checkId: 'tls.legacy-protocol',
        conceptId: 'exposure/tls-legacy-protocol',
        severity: 'medium',
        title: 'The server still accepts TLS 1.0 or 1.1',
        confidence: 'confirmed',
        evidence: { detail: { negotiatedByDefault: inspection.protocol } },
      });
    }

    // Plain HTTP must redirect to HTTPS rather than serve the site.
    const plain = await ctx.http.get(`http://${host}/`, { followRedirects: false, maxBytes: 1024 }).catch(() => null);
    if (plain && plain.status >= 200 && plain.status < 300) {
      findings.push({
        checkId: 'tls.http-served',
        conceptId: 'exposure/https-not-enforced',
        severity: 'high',
        title: 'Pages are served over plain HTTP without redirecting to HTTPS',
        confidence: 'confirmed',
        evidence: { url: plain.url, status: plain.status },
      });
    }
    return findings;
  },
};
