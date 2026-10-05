import { HttpErrorResponse } from '@angular/common/http';
import { Component } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { Router, provideRouter } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { Observable, of, throwError } from 'rxjs';

import { makeUser } from '../../../../testing/auth-fixtures';
import { AuthService } from '../../../core/auth/auth-service';
import { Registration, User } from '../../../core/auth/auth.models';
import { Register } from './register';

@Component({ template: '' })
class Blank {}

interface FormValues {
  name?: string;
  email?: string;
  password?: string;
  confirmation?: string;
}

describe('Register', () => {
  let register: ReturnType<typeof vi.fn<(registration: Registration) => Observable<User>>>;
  let router: Router;
  let harness: RouterTestingHarness;
  let page: HTMLElement;

  beforeEach(async () => {
    register = vi.fn<(registration: Registration) => Observable<User>>(() => of(makeUser()));
    TestBed.configureTestingModule({
      providers: [
        provideRouter([
          { path: 'register', component: Register },
          { path: '**', component: Blank },
        ]),
        { provide: AuthService, useValue: { register } },
      ],
    });
    router = TestBed.inject(Router);
    harness = await RouterTestingHarness.create('/register');
    page = harness.routeNativeElement as HTMLElement;
  });

  function type(selector: string, value: string): void {
    const input = page.querySelector<HTMLInputElement>(selector);
    if (input === null) {
      throw new Error(`No input matches ${selector}`);
    }
    input.value = value;
    input.dispatchEvent(new Event('input'));
  }

  function fill(values: FormValues): void {
    const password = values.password ?? 'secret-password';
    type('#register-name', values.name ?? '');
    type('#register-email', values.email ?? 'ada@example.com');
    type('#register-password', password);
    type('#register-password-confirmation', values.confirmation ?? password);
  }

  async function submit(): Promise<void> {
    page.querySelector('form')?.dispatchEvent(new Event('submit'));
    await harness.fixture.whenStable();
    harness.detectChanges();
  }

  it('registers and opens the dashboard', async () => {
    fill({ name: '  Ada Lovelace  ' });

    await submit();

    expect(register).toHaveBeenCalledWith({
      email: 'ada@example.com',
      password: 'secret-password',
      full_name: 'Ada Lovelace',
    });
    expect(router.url).toBe('/dashboard');
  });

  it('sends no name rather than an empty one', async () => {
    fill({ name: '   ' });

    await submit();

    expect(register).toHaveBeenCalledWith(expect.objectContaining({ full_name: null }));
  });

  it('rejects a password shorter than the backend accepts', async () => {
    fill({ password: 'short' });

    await submit();

    expect(register).not.toHaveBeenCalled();
    const hint = page.querySelector('#register-password-hint');
    expect(hint?.classList.contains('field-error')).toBe(true);
    expect(hint?.textContent).toContain('At least 8 characters');
  });

  it('rejects two passwords that differ', async () => {
    fill({ password: 'secret-password', confirmation: 'secret-passw0rd' });

    await submit();

    expect(register).not.toHaveBeenCalled();
    expect(page.querySelector('#register-confirmation-error')?.textContent).toContain(
      'do not match',
    );
  });

  it('rejects an invalid email', async () => {
    fill({ email: 'ada@' });

    await submit();

    expect(register).not.toHaveBeenCalled();
    expect(page.querySelector('#register-email-error')).not.toBeNull();
  });

  it('shows the reason given by the backend, such as an email already in use', async () => {
    register.mockReturnValue(
      throwError(
        () =>
          new HttpErrorResponse({
            status: 409,
            error: {
              error: {
                code: 'EmailAlreadyRegistered',
                message: 'Email already registered: ada@example.com',
              },
            },
          }),
      ),
    );
    fill({});

    await submit();

    expect(page.querySelector('[role="alert"]')?.textContent).toContain('Email already registered');
    expect(router.url).toBe('/register');
    expect(page.querySelector<HTMLButtonElement>('button[type="submit"]')?.disabled).toBe(false);
  });
});
