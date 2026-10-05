import { HttpErrorResponse } from '@angular/common/http';

const DEFAULT_MESSAGE = 'Something went wrong. Please try again.';

/**
 * A message fit to show the user for a failed API call.
 *
 * The backend answers errors in one of three shapes, depending on which
 * layer rejected the request:
 * - its own envelope: `{ "error": { "code": "...", "message": "..." } }`
 * - FastAPI request validation: `{ "detail": [{ "msg": "...", ... }] }`
 * - the rate limiter: HTTP 429 with a technical, non user-facing message
 */
export function describeHttpError(error: unknown, fallback = DEFAULT_MESSAGE): string {
  if (!(error instanceof HttpErrorResponse)) {
    return fallback;
  }
  if (error.status === 0) {
    return 'Cannot reach the server. Check your connection and try again.';
  }
  if (error.status === 429) {
    return 'Too many attempts. Please wait a minute and try again.';
  }

  const body: unknown = error.error;
  if (isRecord(body)) {
    const envelope = body['error'];
    if (isRecord(envelope) && typeof envelope['message'] === 'string') {
      return envelope['message'];
    }

    const detail = body['detail'];
    if (typeof detail === 'string') {
      return detail;
    }
    if (Array.isArray(detail)) {
      const messages = detail
        .map((issue: unknown) => (isRecord(issue) ? issue['msg'] : null))
        .filter((message): message is string => typeof message === 'string');
      if (messages.length > 0) {
        return messages.join(' ');
      }
    }
  }

  return fallback;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
