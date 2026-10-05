import { HttpErrorResponse } from '@angular/common/http';
import { Component } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { Router, provideRouter } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { Observable, Subject, of, throwError } from 'rxjs';

import { makeUser } from '../../../../testing/auth-fixtures';
import { AuthService } from '../../../core/auth/auth-service';
import { Credentials, User } from '../../../core/auth/auth.models';
import { Login } from './login';

@Component({ template: '' })
class Blank {}

describe('Login', () => {
  let login: ReturnType<typeof vi.fn<(credentials: Credentials) => Observable<User>>>;
  let router: Router;

  beforeEach(() => {
    login = vi.fn<(credentials: Credentials) => Observable<User>>(() => of(makeUser()));
    TestBed.configureTestingModule({
      providers: [
        provideRouter([
          { path: 'login', component: Login },
          { path: '**', component: Blank },
        ]),
        { provide: AuthService, useValue: { login } },
      ],
    });
    router = TestBed.inject(Router);
  });

  async function open(
    url = '/login',
  ): Promise<{ harness: RouterTestingHarness; page: HTMLElement }> {
    const harness = await RouterTestingHarness.create(url);
    return { harness, page: harness.routeNativeElement as HTMLElement };
  }

  function type(page: HTMLElement, selector: string, value: string): void {
    const input = page.querySelector<HTMLInputElement>(selector);
    if (input === null) {
      throw new Error(`No input matches ${selector}`);
    }
    input.value = value;
    input.dispatchEvent(new Event('input'));
  }

  function fill(page: HTMLElement, email: string, password: string): void {
    type(page, '#login-email', email);
    type(page, '#login-password', password);
  }

  async function submit(harness: RouterTestingHarness, page: HTMLElement): Promise<void> {
    page.querySelector('form')?.dispatchEvent(new Event('submit'));
    await harness.fixture.whenStable();
    harness.detectChanges();
  }

  it('signs in with the entered credentials and opens the dashboard', async () => {
    const { harness, page } = await open();
    fill(page, 'ada@example.com', 'secret-password');

    await submit(harness, page);

    expect(login).toHaveBeenCalledWith({ email: 'ada@example.com', password: 'secret-password' });
    expect(router.url).toBe('/dashboard');
  });

  it('returns the user to the page they were heading to', async () => {
    const { harness, page } = await open('/login?returnUrl=%2Fscans%2F42%2Freport');
    fill(page, 'ada@example.com', 'secret-password');

    await submit(harness, page);

    expect(router.url).toBe('/scans/42/report');
  });

  it('ignores a return URL that points outside the app', async () => {
    const { harness, page } = await open('/login?returnUrl=%2F%2Fevil.example');
    fill(page, 'ada@example.com', 'secret-password');

    await submit(harness, page);

    expect(router.url).toBe('/dashboard');
  });

  it('shows what is wrong with the form instead of calling the API', async () => {
    const { harness, page } = await open();
    fill(page, 'not-an-email', '');

    await submit(harness, page);

    expect(login).not.toHaveBeenCalled();
    expect(page.querySelector('#login-email-error')?.textContent).toContain('valid email');
    expect(page.querySelector('#login-password-error')?.textContent).toContain('password');
    expect(page.querySelector('#login-email')?.getAttribute('aria-invalid')).toBe('true');
    expect(router.url).toBe('/login');
  });

  it('shows the reason given by the backend when sign-in is refused', async () => {
    login.mockReturnValue(
      throwError(
        () =>
          new HttpErrorResponse({
            status: 401,
            error: { error: { code: 'InvalidCredentials', message: 'Invalid email or password.' } },
          }),
      ),
    );
    const { harness, page } = await open();
    fill(page, 'ada@example.com', 'wrong-password');

    await submit(harness, page);

    expect(page.querySelector('[role="alert"]')?.textContent).toContain(
      'Invalid email or password.',
    );
    expect(router.url).toBe('/login');
    // The form is usable again for another attempt.
    expect(page.querySelector<HTMLButtonElement>('button[type="submit"]')?.disabled).toBe(false);
  });

  it('blocks a second submission while the first is in progress', async () => {
    const pending = new Subject<User>();
    login.mockReturnValue(pending);
    const { harness, page } = await open();
    fill(page, 'ada@example.com', 'secret-password');

    await submit(harness, page);
    await submit(harness, page);

    const button = page.querySelector<HTMLButtonElement>('button[type="submit"]');
    expect(button?.disabled).toBe(true);
    expect(button?.textContent).toContain('Signing in');
    expect(login).toHaveBeenCalledTimes(1);
  });
});
