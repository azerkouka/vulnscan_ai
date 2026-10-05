import {
  HttpClient,
  HttpErrorResponse,
  provideHttpClient,
  withInterceptors,
} from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { Component } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { Router, provideRouter } from '@angular/router';

import { TEST_API_URL, makeTokens, signIn } from '../../../testing/auth-fixtures';
import { API_BASE_URL } from '../config/api-base-url';
import { authInterceptor } from './auth-interceptor';
import { AuthService } from './auth-service';
import { TokenStorage } from './token-storage';

@Component({ template: '' })
class Blank {}

const SCANS_URL = `${TEST_API_URL}/scans`;
const UNAUTHORIZED = { status: 401, statusText: 'Unauthorized' };

describe('authInterceptor', () => {
  let client: HttpClient;
  let http: HttpTestingController;
  let auth: AuthService;
  let router: Router;

  beforeEach(() => {
    sessionStorage.clear();
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withInterceptors([authInterceptor])),
        provideHttpClientTesting(),
        provideRouter([{ path: '**', component: Blank }]),
        { provide: API_BASE_URL, useValue: TEST_API_URL },
      ],
    });
    client = TestBed.inject(HttpClient);
    http = TestBed.inject(HttpTestingController);
    auth = TestBed.inject(AuthService);
    router = TestBed.inject(Router);
  });

  afterEach(() => {
    http.verify();
    vi.restoreAllMocks();
  });

  describe('attaching the access token', () => {
    it('adds it to API requests', () => {
      signIn(auth, http);

      client.get(SCANS_URL).subscribe();

      const request = http.expectOne(SCANS_URL);
      expect(request.request.headers.get('Authorization')).toBe('Bearer access-1');
      request.flush([]);
    });

    it('sends API requests without the header when signed out', () => {
      client.get(`${TEST_API_URL}/health`).subscribe();

      const request = http.expectOne(`${TEST_API_URL}/health`);
      expect(request.request.headers.has('Authorization')).toBe(false);
      request.flush({ status: 'ok' });
    });

    it.each([
      'https://cdn.example.com/lib.js',
      'http://api.test/other-service/data',
      // Shares the API URL as a string prefix, but is a different path.
      `${TEST_API_URL}-internal/secrets`,
    ])('never sends it to %s', (url) => {
      signIn(auth, http);

      client.get(url).subscribe();

      const request = http.expectOne(url);
      expect(request.request.headers.has('Authorization')).toBe(false);
      request.flush({});
    });

    it.each(['/auth/login', '/auth/register', '/auth/refresh', '/auth/logout'])(
      'leaves %s alone, which authenticates through its body',
      (path) => {
        signIn(auth, http);

        client.post(`${TEST_API_URL}${path}`, {}).subscribe({ error: () => undefined });

        const request = http.expectOne(`${TEST_API_URL}${path}`);
        expect(request.request.headers.has('Authorization')).toBe(false);
        request.flush(null, UNAUTHORIZED);
        // A 401 here is an answer, not an expired token: no refresh is attempted.
        http.expectNone(`${TEST_API_URL}/auth/refresh`);
      },
    );
  });

  describe('when the API answers 401', () => {
    it('refreshes the token and replays the request', () => {
      signIn(auth, http);
      let result: unknown;

      client.get(SCANS_URL).subscribe((body) => (result = body));
      http.expectOne(SCANS_URL).flush(null, UNAUTHORIZED);
      http.expectOne(`${TEST_API_URL}/auth/refresh`).flush(makeTokens('2'));

      const replay = http.expectOne(SCANS_URL);
      expect(replay.request.headers.get('Authorization')).toBe('Bearer access-2');
      replay.flush({ scans: [], total: 0 });
      expect(result).toEqual({ scans: [], total: 0 });
    });

    it('replays a request with its original method and body', () => {
      signIn(auth, http);

      client.post(SCANS_URL, { code: 'x = 1' }).subscribe();
      http.expectOne(SCANS_URL).flush(null, UNAUTHORIZED);
      http.expectOne(`${TEST_API_URL}/auth/refresh`).flush(makeTokens('2'));

      const replay = http.expectOne(SCANS_URL);
      expect(replay.request.method).toBe('POST');
      expect(replay.request.body).toEqual({ code: 'x = 1' });
      replay.flush({});
    });

    it('refreshes once for several requests that fail together', () => {
      signIn(auth, http);
      const urls = [SCANS_URL, `${SCANS_URL}/1`, `${SCANS_URL}/1/report`];
      const completed: string[] = [];

      urls.forEach((url) => client.get(url).subscribe(() => completed.push(url)));
      urls.forEach((url) => http.expectOne(url).flush(null, UNAUTHORIZED));

      // expectOne fails if the single-use refresh token was sent more than once.
      http.expectOne(`${TEST_API_URL}/auth/refresh`).flush(makeTokens('2'));
      urls.forEach((url) => {
        const replay = http.expectOne(url);
        expect(replay.request.headers.get('Authorization')).toBe('Bearer access-2');
        replay.flush({});
      });
      expect(completed).toEqual(urls);
    });

    it('returns the 401 of a replayed request without refreshing again', () => {
      signIn(auth, http);
      let failure: unknown;

      client.get(SCANS_URL).subscribe({ error: (error: unknown) => (failure = error) });
      http.expectOne(SCANS_URL).flush(null, UNAUTHORIZED);
      http.expectOne(`${TEST_API_URL}/auth/refresh`).flush(makeTokens('2'));
      http.expectOne(SCANS_URL).flush(null, UNAUTHORIZED);

      expect((failure as HttpErrorResponse).status).toBe(401);
      http.expectNone(`${TEST_API_URL}/auth/refresh`);
      // The refresh itself worked, so the session stands.
      expect(auth.isAuthenticated()).toBe(true);
    });
  });

  describe('when the token cannot be refreshed', () => {
    it('ends the session, sends the user to login and reports the original error', async () => {
      signIn(auth, http);
      await router.navigateByUrl('/scans/42/report');
      const navigate = vi.spyOn(router, 'navigate').mockResolvedValue(true);
      let failure: unknown;

      client.get(SCANS_URL).subscribe({ error: (error: unknown) => (failure = error) });
      http.expectOne(SCANS_URL).flush(null, UNAUTHORIZED);
      http.expectOne(`${TEST_API_URL}/auth/refresh`).flush(null, UNAUTHORIZED);

      expect(auth.isAuthenticated()).toBe(false);
      expect(TestBed.inject(TokenStorage).getRefreshToken()).toBeNull();
      expect(navigate).toHaveBeenCalledWith(['/login'], {
        queryParams: { returnUrl: '/scans/42/report' },
      });
      expect((failure as HttpErrorResponse).status).toBe(401);
      expect((failure as HttpErrorResponse).url).toBe(SCANS_URL);
      http.expectNone(SCANS_URL);
    });

    it('does not redirect a visitor who is already on a signed-out page', async () => {
      await router.navigateByUrl('/login?returnUrl=%2Fscans');
      const navigate = vi.spyOn(router, 'navigate').mockResolvedValue(true);

      // Signed out, so there is no refresh token to try.
      client.get(SCANS_URL).subscribe({ error: () => undefined });
      http.expectOne(SCANS_URL).flush(null, UNAUTHORIZED);

      expect(navigate).not.toHaveBeenCalled();
    });
  });

  it.each([403, 404, 422, 500])('passes a %s through without refreshing', (status) => {
    signIn(auth, http);
    let failure: unknown;

    client.get(SCANS_URL).subscribe({ error: (error: unknown) => (failure = error) });
    http.expectOne(SCANS_URL).flush(null, { status, statusText: 'Error' });

    expect((failure as HttpErrorResponse).status).toBe(status);
    http.expectNone(`${TEST_API_URL}/auth/refresh`);
    expect(auth.isAuthenticated()).toBe(true);
  });
});
