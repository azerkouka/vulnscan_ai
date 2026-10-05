import { HttpErrorResponse, provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';

import { TEST_API_URL, makeTokens, makeUser, signIn } from '../../../testing/auth-fixtures';
import { API_BASE_URL } from '../config/api-base-url';
import { authInterceptor } from './auth-interceptor';
import { AuthService } from './auth-service';
import { TokenStorage } from './token-storage';

describe('AuthService', () => {
  let auth: AuthService;
  let http: HttpTestingController;
  let storage: TokenStorage;

  beforeEach(() => {
    sessionStorage.clear();
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withInterceptors([authInterceptor])),
        provideHttpClientTesting(),
        provideRouter([]),
        { provide: API_BASE_URL, useValue: TEST_API_URL },
      ],
    });
    auth = TestBed.inject(AuthService);
    http = TestBed.inject(HttpTestingController);
    storage = TestBed.inject(TokenStorage);
  });

  afterEach(() => http.verify());

  describe('login', () => {
    it('stores the tokens, then loads the user with the new access token', () => {
      const user = makeUser();
      let emitted: unknown;

      auth.login({ email: user.email, password: 'secret-password' }).subscribe((u) => {
        emitted = u;
      });

      const login = http.expectOne(`${TEST_API_URL}/auth/login`);
      expect(login.request.method).toBe('POST');
      expect(login.request.body).toEqual({ email: user.email, password: 'secret-password' });
      expect(login.request.headers.has('Authorization')).toBe(false);
      expect(auth.isAuthenticated()).toBe(false);
      login.flush(makeTokens());

      const me = http.expectOne(`${TEST_API_URL}/auth/me`);
      expect(me.request.headers.get('Authorization')).toBe('Bearer access-1');
      me.flush(user);

      expect(emitted).toEqual(user);
      expect(auth.user()).toEqual(user);
      expect(auth.isAuthenticated()).toBe(true);
      expect(auth.accessToken()).toBe('access-1');
    });

    it('persists only the refresh token', () => {
      signIn(auth, http);

      expect(storage.getRefreshToken()).toBe('refresh-1');
      const stored = Object.values({ ...sessionStorage }).join(' ');
      expect(stored).not.toContain('access-1');
    });

    it('stays signed out when the credentials are rejected', () => {
      let failure: unknown;

      auth.login({ email: 'ada@example.com', password: 'wrong' }).subscribe({
        error: (error: unknown) => (failure = error),
      });
      http
        .expectOne(`${TEST_API_URL}/auth/login`)
        .flush(
          { error: { code: 'InvalidCredentials', message: 'Invalid email or password.' } },
          { status: 401, statusText: 'Unauthorized' },
        );

      expect(failure).toBeInstanceOf(HttpErrorResponse);
      expect(auth.isAuthenticated()).toBe(false);
      expect(storage.getRefreshToken()).toBeNull();
    });
  });

  describe('register', () => {
    it('creates the account, then signs in with the same credentials', () => {
      const user = makeUser({ full_name: 'Ada' });

      auth
        .register({ email: user.email, password: 'secret-password', full_name: 'Ada' })
        .subscribe();

      const register = http.expectOne(`${TEST_API_URL}/auth/register`);
      expect(register.request.body).toEqual({
        email: user.email,
        password: 'secret-password',
        full_name: 'Ada',
      });
      register.flush(user, { status: 201, statusText: 'Created' });

      const login = http.expectOne(`${TEST_API_URL}/auth/login`);
      expect(login.request.body).toEqual({ email: user.email, password: 'secret-password' });
      login.flush(makeTokens());
      http.expectOne(`${TEST_API_URL}/auth/me`).flush(user);

      expect(auth.isAuthenticated()).toBe(true);
    });

    it('does not attempt to sign in when registration fails', () => {
      let failed = false;

      auth
        .register({ email: 'ada@example.com', password: 'secret-password', full_name: null })
        .subscribe({ error: () => (failed = true) });
      http
        .expectOne(`${TEST_API_URL}/auth/register`)
        .flush(
          { error: { code: 'EmailAlreadyRegistered', message: 'Email already registered.' } },
          { status: 409, statusText: 'Conflict' },
        );

      expect(failed).toBe(true);
      http.expectNone(`${TEST_API_URL}/auth/login`);
    });
  });

  describe('logout', () => {
    it('signs out at once and revokes the refresh token on the backend', () => {
      signIn(auth, http);

      auth.logout().subscribe();

      // Already signed out locally, before the backend has answered.
      expect(auth.isAuthenticated()).toBe(false);
      expect(auth.accessToken()).toBeNull();
      expect(storage.getRefreshToken()).toBeNull();

      const logout = http.expectOne(`${TEST_API_URL}/auth/logout`);
      expect(logout.request.body).toEqual({ refresh_token: 'refresh-1' });
      logout.flush(null, { status: 204, statusText: 'No Content' });
    });

    it('completes normally even if the revocation call fails', () => {
      signIn(auth, http);
      let completed = false;
      let failed = false;

      auth.logout().subscribe({ complete: () => (completed = true), error: () => (failed = true) });
      http.expectOne(`${TEST_API_URL}/auth/logout`).error(new ProgressEvent('error'));

      expect(completed).toBe(true);
      expect(failed).toBe(false);
    });

    it('makes no request when there is no session', () => {
      let completed = false;

      auth.logout().subscribe({ complete: () => (completed = true) });

      expect(completed).toBe(true);
      http.expectNone(`${TEST_API_URL}/auth/logout`);
    });
  });

  describe('refreshAccessToken', () => {
    it('rotates both tokens', () => {
      signIn(auth, http);
      let newAccessToken: string | undefined;

      auth.refreshAccessToken().subscribe((token) => (newAccessToken = token));
      const refresh = http.expectOne(`${TEST_API_URL}/auth/refresh`);
      expect(refresh.request.body).toEqual({ refresh_token: 'refresh-1' });
      expect(refresh.request.headers.has('Authorization')).toBe(false);
      refresh.flush(makeTokens('2'));

      expect(newAccessToken).toBe('access-2');
      expect(auth.accessToken()).toBe('access-2');
      expect(storage.getRefreshToken()).toBe('refresh-2');
    });

    it('shares a single refresh call between concurrent callers', () => {
      signIn(auth, http);
      const received: string[] = [];

      auth.refreshAccessToken().subscribe((token) => received.push(token));
      auth.refreshAccessToken().subscribe((token) => received.push(token));
      auth.refreshAccessToken().subscribe((token) => received.push(token));

      // expectOne fails if the single-use refresh token was sent more than once.
      http.expectOne(`${TEST_API_URL}/auth/refresh`).flush(makeTokens('2'));
      expect(received).toEqual(['access-2', 'access-2', 'access-2']);
    });

    it('starts a new call, with the rotated token, once the previous one is done', () => {
      signIn(auth, http);

      auth.refreshAccessToken().subscribe();
      http.expectOne(`${TEST_API_URL}/auth/refresh`).flush(makeTokens('2'));
      auth.refreshAccessToken().subscribe();

      const second = http.expectOne(`${TEST_API_URL}/auth/refresh`);
      expect(second.request.body).toEqual({ refresh_token: 'refresh-2' });
      second.flush(makeTokens('3'));
      expect(auth.accessToken()).toBe('access-3');
    });

    it('fails every concurrent caller when the refresh is rejected, then allows a retry', () => {
      signIn(auth, http);
      let failures = 0;

      auth.refreshAccessToken().subscribe({ error: () => failures++ });
      auth.refreshAccessToken().subscribe({ error: () => failures++ });
      http
        .expectOne(`${TEST_API_URL}/auth/refresh`)
        .flush(null, { status: 401, statusText: 'Unauthorized' });

      expect(failures).toBe(2);
      auth.refreshAccessToken().subscribe({ error: () => failures++ });
      http.expectOne(`${TEST_API_URL}/auth/refresh`).flush(makeTokens('2'));
      expect(failures).toBe(2);
    });

    it('errors without calling the backend when there is no refresh token', () => {
      let failed = false;

      auth.refreshAccessToken().subscribe({ error: () => (failed = true) });

      expect(failed).toBe(true);
      http.expectNone(`${TEST_API_URL}/auth/refresh`);
    });
  });

  describe('restoreSession', () => {
    it('does nothing when no refresh token was left behind', async () => {
      await auth.restoreSession();

      expect(auth.isAuthenticated()).toBe(false);
      http.expectNone(`${TEST_API_URL}/auth/refresh`);
    });

    it('turns a stored refresh token back into a signed-in session', async () => {
      storage.setRefreshToken('refresh-from-last-visit');
      const user = makeUser();

      const restored = auth.restoreSession();
      const refresh = http.expectOne(`${TEST_API_URL}/auth/refresh`);
      expect(refresh.request.body).toEqual({ refresh_token: 'refresh-from-last-visit' });
      refresh.flush(makeTokens('2'));
      const me = http.expectOne(`${TEST_API_URL}/auth/me`);
      expect(me.request.headers.get('Authorization')).toBe('Bearer access-2');
      me.flush(user);
      await restored;

      expect(auth.user()).toEqual(user);
      expect(storage.getRefreshToken()).toBe('refresh-2');
    });

    it('discards a refresh token the backend rejects', async () => {
      storage.setRefreshToken('expired');

      const restored = auth.restoreSession();
      http
        .expectOne(`${TEST_API_URL}/auth/refresh`)
        .flush(
          { error: { code: 'InvalidRefreshToken', message: 'Refresh token has expired.' } },
          { status: 401, statusText: 'Unauthorized' },
        );
      await restored;

      expect(auth.isAuthenticated()).toBe(false);
      expect(storage.getRefreshToken()).toBeNull();
    });

    it('keeps the refresh token when the backend is merely unreachable', async () => {
      storage.setRefreshToken('still-valid');

      const restored = auth.restoreSession();
      http.expectOne(`${TEST_API_URL}/auth/refresh`).error(new ProgressEvent('error'));
      await restored;

      expect(auth.isAuthenticated()).toBe(false);
      expect(storage.getRefreshToken()).toBe('still-valid');
    });
  });
});
