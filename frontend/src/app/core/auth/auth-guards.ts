import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';

import { AuthService } from './auth-service';
import { DEFAULT_SIGNED_IN_URL, loginQueryParams } from './return-url';

/**
 * Both guards read the session synchronously: `AuthService.restoreSession`
 * has already run, as an app initializer, before any route is activated.
 *
 * They are a navigation convenience, not a security boundary - the backend
 * authorizes every request on its own.
 */

/** Lets signed-in users through; sends everyone else to the login page. */
export const authGuard: CanActivateFn = (_route, state) => {
  if (inject(AuthService).isAuthenticated()) {
    return true;
  }
  return inject(Router).createUrlTree(['/login'], {
    queryParams: loginQueryParams(state.url),
  });
};

/** Keeps signed-in users off the login and register pages. */
export const guestGuard: CanActivateFn = () => {
  if (!inject(AuthService).isAuthenticated()) {
    return true;
  }
  return inject(Router).parseUrl(DEFAULT_SIGNED_IN_URL);
};
