/** Turns report HTML into a PDF. Implemented by a headless-Chromium service; faked in tests. */
export interface PdfRenderer {
  render(html: string): Promise<Buffer>;
}

export class PdfUnavailableError extends Error {
  constructor(message = 'PDF export is not configured') {
    super(message);
    this.name = 'PdfUnavailableError';
  }
}

/**
 * Gotenberg (https://gotenberg.dev, MIT) runs headless Chromium in its own container.
 * The container is started with JavaScript disabled and network access limited to its
 * own temp files, so report content can't make it fetch anything.
 */
export class GotenbergPdfRenderer implements PdfRenderer {
  constructor(private readonly baseUrl: string) {}

  async render(html: string): Promise<Buffer> {
    const form = new FormData();
    form.append('files', new Blob([html], { type: 'text/html' }), 'index.html');
    form.append('preferCssPageSize', 'true');
    form.append('printBackground', 'true');
    form.append('skipNetworkIdleEvent', 'true');
    let res: Response;
    try {
      res = await fetch(`${this.baseUrl}/forms/chromium/convert/html`, { method: 'POST', body: form, signal: AbortSignal.timeout(45_000) });
    } catch {
      throw new PdfUnavailableError('The PDF service is not reachable');
    }
    if (!res.ok) throw new PdfUnavailableError(`The PDF service failed (HTTP ${res.status})`);
    const pdf = Buffer.from(await res.arrayBuffer());
    if (pdf.subarray(0, 5).toString() !== '%PDF-') throw new PdfUnavailableError('The PDF service returned something that is not a PDF');
    return pdf;
  }
}

export const noPdf: PdfRenderer = {
  render: async () => {
    throw new PdfUnavailableError();
  },
};
