import { HttpErrorResponse } from '@angular/common/http';

const DEFAULT_MESSAGE = 'Something went wrong. Please try again.';

/**
 * A message fit to show the user for a failed API call.
 *
 * The backend answers every error with one envelope,
 * `{ "error": { "code": "...", "message": "..." } }`. FastAPI's native
 * `{ "detail": ... }` shape is still understood, in case a response ever
 * comes from a layer that bypasses the backend's own handlers.
 *
 * When the body carries no usable message, a few statuses still get a
 * specific one (unreachable server, too many requests) rather than the
 * caller's generic fallback.
 */
export function describeHttpError(error: unknown, fallback = DEFAULT_MESSAGE): string {
  if (!(error instanceof HttpErrorResponse)) {
    return fallback;
  }
  if (error.status === 0) {
    return 'Cannot reach the server. Check your connection and try again.';
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

  if (error.status === 429) {
    return 'Too many requests. Please wait a moment and try again.';
  }
  return fallback;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
