export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

export interface User {
  id: string;
  email: string;
  emailVerified: boolean;
  plan: 'free' | 'pro';
}

/** JSON fetch against our own API. Cookies are first-party, so nothing is stored in JS. */
export async function api<T>(path: string, options: { method?: string; body?: unknown } = {}): Promise<T> {
  const init: RequestInit = {
    method: options.method ?? (options.body === undefined ? 'GET' : 'POST'),
    credentials: 'same-origin',
    headers: options.body === undefined ? {} : { 'Content-Type': 'application/json' },
  };
  if (options.body !== undefined) init.body = JSON.stringify(options.body);

  const res = await fetch(`/api${path}`, init);
  if (res.status === 204) return undefined as T;
  const data = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  if (!res.ok) {
    throw new ApiError(
      res.status,
      typeof data.error === 'string' ? data.error : 'error',
      typeof data.message === 'string' ? data.message : 'Something went wrong. Please try again.',
    );
  }
  return data as T;
}

export function errorMessage(err: unknown): string {
  if (err instanceof ApiError) return err.message;
  return 'Could not reach the server. Check your connection and try again.';
}
