import { TestBed } from '@angular/core/testing';
import {
  ActivatedRouteSnapshot,
  GuardResult,
  Router,
  RouterStateSnapshot,
  UrlTree,
  provideRouter,
} from '@angular/router';

import { authGuard, guestGuard } from './auth-guards';
import { AuthService } from './auth-service';

describe('route guards', () => {
  let authenticated: boolean;
  let router: Router;

  beforeEach(() => {
    authenticated = false;
    TestBed.configureTestingModule({
      providers: [
        provideRouter([]),
        { provide: AuthService, useValue: { isAuthenticated: () => authenticated } },
      ],
    });
    router = TestBed.inject(Router);
  });

  function run(guard: typeof authGuard, url: string): GuardResult {
    const state = { url } as RouterStateSnapshot;
    return TestBed.runInInjectionContext(() =>
      guard({} as ActivatedRouteSnapshot, state),
    ) as GuardResult;
  }

  describe('authGuard', () => {
    it('lets a signed-in user through', () => {
      authenticated = true;

      expect(run(authGuard, '/dashboard')).toBe(true);
    });

    it('sends a visitor to login, remembering where they were going', () => {
      const result = run(authGuard, '/scans/42/report');

      expect(result).toBeInstanceOf(UrlTree);
      expect(router.serializeUrl(result as UrlTree)).toBe(
        '/login?returnUrl=%2Fscans%2F42%2Freport',
      );
    });

    it.each(['/', '/dashboard'])(
      'omits the return URL for %s, where signing in leads anyway',
      (url) => {
        const result = run(authGuard, url);

        expect(router.serializeUrl(result as UrlTree)).toBe('/login');
      },
    );
  });

  describe('guestGuard', () => {
    it('lets a visitor reach the login page', () => {
      expect(run(guestGuard, '/login')).toBe(true);
    });

    it('sends a signed-in user to the dashboard instead', () => {
      authenticated = true;

      const result = run(guestGuard, '/login');

      expect(router.serializeUrl(result as UrlTree)).toBe('/dashboard');
    });
  });
});
