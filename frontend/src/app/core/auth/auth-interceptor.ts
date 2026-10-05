import { HttpErrorResponse, HttpInterceptorFn, HttpRequest } from '@angular/common/http';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { catchError, switchMap, throwError } from 'rxjs';

import { API_BASE_URL } from '../config/api-base-url';
import { AuthService } from './auth-service';
import { SIGNED_OUT_PAGES, loginQueryParams } from './return-url';

/**
 * Endpoints that authenticate through their body, not through an access
 * token. A 401 from one of them is an answer ("wrong password", "refresh
 * token rejected"), never a cue to refresh and retry.
 */
const TOKENLESS_PATHS = new Set(['/auth/login', '/auth/register', '/auth/refresh', '/auth/logout']);

/**
 * Attaches the access token to API requests and, when the API answers 401,
 * renews it once and replays the request.
 *
 * - Requests to any other origin are passed through untouched, so the token
 *   is never sent anywhere but our own API.
 * - A request is replayed at most once: a 401 on the replay is returned to
 *   the caller as-is.
 * - If the token can't be renewed, the session is over: it is cleared and
 *   the user is sent to the login page, to come back where they were.
 */
export const authInterceptor: HttpInterceptorFn = (request, next) => {
  const baseUrl = inject(API_BASE_URL);
  if (!request.url.startsWith(`${baseUrl}/`)) {
    return next(request);
  }
  if (TOKENLESS_PATHS.has(request.url.slice(baseUrl.length))) {
    return next(request);
  }

  const auth = inject(AuthService);
  const router = inject(Router);

  return next(withAccessToken(request, auth.accessToken())).pipe(
    catchError((error: unknown) => {
      if (!(error instanceof HttpErrorResponse) || error.status !== 401) {
        return throwError(() => error);
      }

      return auth.refreshAccessToken().pipe(
        // Placed before the replay on purpose: it must only catch a failed
        // refresh, not a failure of the replayed request.
        catchError(() => {
          auth.clearSession();
          redirectToLogin(router);
          return throwError(() => error);
        }),
        switchMap((accessToken) => next(withAccessToken(request, accessToken))),
      );
    }),
  );
};

function withAccessToken(
  request: HttpRequest<unknown>,
  accessToken: string | null,
): HttpRequest<unknown> {
  if (accessToken === null) {
    return request;
  }
  return request.clone({ setHeaders: { Authorization: `Bearer ${accessToken}` } });
}

function redirectToLogin(router: Router): void {
  const currentUrl = router.url;
  if (SIGNED_OUT_PAGES.some((page) => currentUrl.startsWith(page))) {
    return;
  }
  void router.navigate(['/login'], { queryParams: loginQueryParams(currentUrl) });
}
