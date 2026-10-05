import { HttpErrorResponse } from '@angular/common/http';

import { describeHttpError } from './api-error';

function httpError(status: number, body: unknown): HttpErrorResponse {
  return new HttpErrorResponse({ status, error: body });
}

describe('describeHttpError', () => {
  it('uses the message of the backend error envelope', () => {
    const error = httpError(401, {
      error: { code: 'InvalidCredentials', message: 'Invalid email or password.' },
    });

    expect(describeHttpError(error)).toBe('Invalid email or password.');
  });

  it('joins FastAPI validation messages', () => {
    const error = httpError(422, {
      detail: [
        { loc: ['body', 'email'], msg: 'value is not a valid email address' },
        { loc: ['body', 'password'], msg: 'String should have at least 8 characters' },
      ],
    });

    expect(describeHttpError(error)).toBe(
      'value is not a valid email address String should have at least 8 characters',
    );
  });

  it('accepts a plain string detail', () => {
    expect(describeHttpError(httpError(400, { detail: 'Bad request.' }))).toBe('Bad request.');
  });

  it('explains a network failure instead of showing a status of 0', () => {
    expect(describeHttpError(httpError(0, null))).toContain('Cannot reach the server');
  });

  it('replaces the rate limiter technical message with a readable one', () => {
    const error = httpError(429, { error: 'Rate limit exceeded: 5 per 1 minute' });

    expect(describeHttpError(error)).toBe('Too many attempts. Please wait a minute and try again.');
  });

  it.each([
    ['an unknown body shape', httpError(500, { unexpected: true })],
    ['an HTML error page', httpError(502, '<html>Bad Gateway</html>')],
    ['an empty body', httpError(500, null)],
    ['a non-HTTP error', new Error('boom')],
  ])('falls back to the given message for %s', (_label, error) => {
    expect(describeHttpError(error, 'Sign-in failed.')).toBe('Sign-in failed.');
  });
});
