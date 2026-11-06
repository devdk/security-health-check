export class HttpError extends Error {
  constructor(
    public readonly statusCode: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'HttpError';
  }
}

export const unauthorised = () => new HttpError(401, 'unauthorised', 'Sign in required');
export const invalidCredentials = () => new HttpError(401, 'invalid_credentials', 'Invalid email or password');
