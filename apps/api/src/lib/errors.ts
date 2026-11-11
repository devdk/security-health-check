export class HttpError extends Error {
  constructor(
    public readonly statusCode: number,
    public readonly code: string,
    message: string,
    /** Extra machine-readable detail sent with the error, such as validation messages. */
    public readonly details?: unknown,
  ) {
    super(message);
    this.name = 'HttpError';
  }
}

export const unauthorised = () => new HttpError(401, 'unauthorised', 'Sign in required');
export const invalidCredentials = () => new HttpError(401, 'invalid_credentials', 'Invalid email or password');
