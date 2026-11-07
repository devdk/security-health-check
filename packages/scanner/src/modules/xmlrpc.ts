import type { CheckModule } from '../types';
import { text } from './common';

/**
 * WordPress answers a plain GET to /xmlrpc.php with "XML-RPC server accepts POST requests
 * only." when the endpoint is live. We never POST to it: that would be an interaction
 * beyond what a browser does, so a reachable endpoint is reported as "likely enabled".
 */
export const xmlrpc: CheckModule = {
  id: 'xmlrpc',
  title: 'XML-RPC',
  stage: 1,

  async run(target, ctx) {
    const res = await ctx.http.get(`${target.baseUrl}/xmlrpc.php`, { maxBytes: 4096 });
    const body = text(res);
    if (!/XML-RPC server accepts POST requests only/i.test(body)) return [];
    return [
      {
        checkId: 'xmlrpc.enabled',
        conceptId: 'exposure/xmlrpc-enabled',
        severity: 'medium',
        title: 'xmlrpc.php is reachable and answering',
        confidence: 'likely',
        evidence: { url: res.url, status: res.status, snippet: 'XML-RPC server accepts POST requests only.' },
      },
    ];
  },
};
