import { Component, signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { Router, provideRouter } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { of } from 'rxjs';

import { makeUser } from '../../../testing/auth-fixtures';
import { AuthService } from '../../core/auth/auth-service';
import { User } from '../../core/auth/auth.models';
import { Shell } from './shell';

@Component({ template: '<p id="page">Dashboard content</p>' })
class DashboardStub {}

@Component({ template: '' })
class Blank {}

describe('Shell', () => {
  let logout: ReturnType<typeof vi.fn>;
  let harness: RouterTestingHarness;
  let page: HTMLElement;

  beforeEach(async () => {
    logout = vi.fn(() => of(undefined));
    TestBed.configureTestingModule({
      providers: [
        provideRouter([
          {
            path: '',
            component: Shell,
            children: [{ path: 'dashboard', component: DashboardStub }],
          },
          { path: 'login', component: Blank },
        ]),
        {
          provide: AuthService,
          useValue: { user: signal<User | null>(makeUser({ email: 'ada@example.com' })), logout },
        },
      ],
    });
    harness = await RouterTestingHarness.create('/dashboard');
    page = harness.fixture.nativeElement as HTMLElement;
  });

  it('frames the current page with the header and navigation', () => {
    expect(page.querySelector('header')?.textContent).toContain('VulnScan AI');
    expect(page.querySelector('main #page')?.textContent).toBe('Dashboard content');
  });

  it('shows who is signed in', () => {
    expect(page.querySelector('.shell-user-email')?.textContent).toBe('ada@example.com');
  });

  it('marks the current section in the navigation', () => {
    const link = page.querySelector('nav a');

    expect(link?.textContent?.trim()).toBe('Dashboard');
    expect(link?.classList.contains('active')).toBe(true);
    expect(link?.getAttribute('aria-current')).toBe('page');
  });

  it('signs out and leaves for the login page', async () => {
    page.querySelector<HTMLButtonElement>('.shell-user button')?.click();
    await harness.fixture.whenStable();

    expect(logout).toHaveBeenCalledTimes(1);
    expect(TestBed.inject(Router).url).toBe('/login');
  });
});
