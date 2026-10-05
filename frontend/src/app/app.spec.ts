/**
 * The app as wired for real - actual routes, guards, interceptor and
 * `AuthService` - with only the HTTP backend replaced. Covers what the unit
 * specs can't: that these pieces work together.
 */
import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { Router, provideRouter } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';

import { TEST_API_URL, makeTokens, makeUser, signIn } from '../testing/auth-fixtures';
import { makeSummary } from '../testing/scan-fixtures';
import { routes } from './app.routes';
import { authInterceptor } from './core/auth/auth-interceptor';
import { AuthService } from './core/auth/auth-service';
import { TokenStorage } from './core/auth/token-storage';
import { API_BASE_URL } from './core/config/api-base-url';

describe('App navigation', () => {
  let http: HttpTestingController;
  let router: Router;
  let auth: AuthService;

  beforeEach(() => {
    sessionStorage.clear();
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withInterceptors([authInterceptor])),
        provideHttpClientTesting(),
        provideRouter(routes),
        { provide: API_BASE_URL, useValue: TEST_API_URL },
      ],
    });
    http = TestBed.inject(HttpTestingController);
    router = TestBed.inject(Router);
    auth = TestBed.inject(AuthService);
  });

  afterEach(() => http.verify());

  function type(page: HTMLElement, selector: string, value: string): void {
    const input = page.querySelector<HTMLInputElement>(selector);
    if (input === null) {
      throw new Error(`No input matches ${selector}`);
    }
    input.value = value;
    input.dispatchEvent(new Event('input'));
  }

  /** The dashboard loads its summary as it opens; answer it so `http.verify()` is satisfied. */
  async function answerDashboardSummary(): Promise<void> {
    const summary = await vi.waitFor(() => http.expectOne(`${TEST_API_URL}/dashboard/summary`));
    summary.flush(makeSummary());
  }

  it('sends a visitor who opens the app to the login page', async () => {
    const harness = await RouterTestingHarness.create('/');

    expect(router.url).toBe('/login');
    expect((harness.fixture.nativeElement as HTMLElement).querySelector('h1')?.textContent).toBe(
      'Sign in',
    );
  });

  it('sends a visitor who asks for a protected page to the login page', async () => {
    await RouterTestingHarness.create('/dashboard');

    expect(router.url).toBe('/login');
  });

  it('lets a visitor reach the registration page', async () => {
    const harness = await RouterTestingHarness.create('/register');

    expect(router.url).toBe('/register');
    expect((harness.fixture.nativeElement as HTMLElement).querySelector('h1')?.textContent).toBe(
      'Create your account',
    );
  });

  it('shows a not-found page for an unknown address', async () => {
    const harness = await RouterTestingHarness.create('/no/such/page');

    expect((harness.fixture.nativeElement as HTMLElement).querySelector('h1')?.textContent).toBe(
      'Page not found',
    );
  });

  it('keeps a signed-in user off the login page', async () => {
    signIn(auth, http);

    await RouterTestingHarness.create('/login');
    await answerDashboardSummary();

    expect(router.url).toBe('/dashboard');
  });

  it('signs in from the login form, lands on the dashboard, then signs out', async () => {
    const user = makeUser({ email: 'ada@example.com', full_name: 'Ada Lovelace' });
    const harness = await RouterTestingHarness.create('/dashboard');
    const page = harness.fixture.nativeElement as HTMLElement;
    expect(router.url).toBe('/login');

    type(page, '#login-email', user.email);
    type(page, '#login-password', 'secret-password');
    page.querySelector('form')?.dispatchEvent(new Event('submit'));
    http.expectOne(`${TEST_API_URL}/auth/login`).flush(makeTokens());
    http.expectOne(`${TEST_API_URL}/auth/me`).flush(user);

    await vi.waitFor(() => expect(router.url).toBe('/dashboard'));
    await answerDashboardSummary();
    harness.detectChanges();
    expect(page.querySelector('header .shell-user-email')?.textContent).toBe('ada@example.com');
    expect(page.querySelector('main h1')?.textContent).toBe('Welcome, Ada Lovelace');

    page.querySelector<HTMLButtonElement>('.shell-user button')?.click();
    http
      .expectOne(`${TEST_API_URL}/auth/logout`)
      .flush(null, { status: 204, statusText: 'No Content' });

    await vi.waitFor(() => expect(router.url).toBe('/login'));
    expect(auth.isAuthenticated()).toBe(false);
    expect(TestBed.inject(TokenStorage).getRefreshToken()).toBeNull();
  });

  it('returns to the login page when the session expires mid-use', async () => {
    signIn(auth, http);
    await RouterTestingHarness.create('/dashboard');

    // The access token has expired, and so has the refresh token.
    const expired = { status: 401, statusText: 'Unauthorized' };
    const summary = await vi.waitFor(() => http.expectOne(`${TEST_API_URL}/dashboard/summary`));
    summary.flush(null, expired);
    http.expectOne(`${TEST_API_URL}/auth/refresh`).flush(null, expired);

    await vi.waitFor(() => expect(router.url).toBe('/login'));
    expect(auth.isAuthenticated()).toBe(false);
  });
});
