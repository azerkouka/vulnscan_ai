import { HttpErrorResponse } from '@angular/common/http';
import { signal } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { Observable, of, throwError } from 'rxjs';

import { makeUser } from '../../../testing/auth-fixtures';
import { makeScan, makeSummary } from '../../../testing/scan-fixtures';
import { AuthService } from '../../core/auth/auth-service';
import { User } from '../../core/auth/auth.models';
import { POLL_INTERVAL } from '../../core/scans/poll';
import { ScanService } from '../../core/scans/scan-service';
import { DashboardSummary } from '../../core/scans/scan.models';
import { Dashboard } from './dashboard';

describe('Dashboard', () => {
  let dashboardSummary: ReturnType<typeof vi.fn<() => Observable<DashboardSummary>>>;
  let fixture: ComponentFixture<Dashboard>;
  let page: HTMLElement;

  function render(user: User = makeUser()): void {
    TestBed.configureTestingModule({
      providers: [
        provideRouter([]),
        { provide: AuthService, useValue: { user: signal<User | null>(user) } },
        { provide: ScanService, useValue: { dashboardSummary } },
        { provide: POLL_INTERVAL, useValue: 5 },
      ],
    });
    fixture = TestBed.createComponent(Dashboard);
    fixture.detectChanges();
    page = fixture.nativeElement as HTMLElement;
  }

  beforeEach(() => {
    dashboardSummary = vi.fn<() => Observable<DashboardSummary>>(() => of(makeSummary()));
  });

  const stat = (label: string): string | undefined =>
    [...page.querySelectorAll('.stat')]
      .find((card) => card.querySelector('dt')?.textContent === label)
      ?.querySelector('dd')?.textContent ?? undefined;

  it('greets the user by name, or by email when no name was given', () => {
    render(makeUser({ full_name: 'Ada Lovelace' }));
    expect(page.querySelector('h1')?.textContent).toBe('Welcome, Ada Lovelace');

    TestBed.resetTestingModule();
    render(makeUser({ full_name: null, email: 'ada@example.com' }));
    expect(page.querySelector('h1')?.textContent).toBe('Welcome, ada@example.com');
  });

  it('invites a user with no scan to start one', () => {
    render();

    expect(page.querySelector('.empty-state h2')?.textContent).toBe('No scans yet');
    expect(page.querySelector('.empty-state a')?.getAttribute('href')).toBe('/scans/new');
    expect(page.querySelector('.stat')).toBeNull();
  });

  it('shows the scan and finding totals', () => {
    dashboardSummary.mockReturnValue(
      of(
        makeSummary({
          total_scans: 9,
          scans_by_status: { PENDING: 0, RUNNING: 0, COMPLETED: 7, FAILED: 2 },
          total_findings: 31,
        }),
      ),
    );

    render();

    expect(stat('Scans')).toBe('9');
    expect(stat('Completed')).toBe('7');
    expect(stat('In progress')).toBe('0');
    expect(stat('Failed')).toBe('2');
    expect(stat('Findings')).toBe('31');
  });

  it('draws one bar per severity, scaled to the most frequent one', () => {
    dashboardSummary.mockReturnValue(
      of(
        makeSummary({
          total_scans: 1,
          scans_by_status: { PENDING: 0, RUNNING: 0, COMPLETED: 1, FAILED: 0 },
          total_findings: 15,
          findings_by_severity: { CRITICAL: 2, HIGH: 8, MEDIUM: 4, LOW: 1, INFO: 0 },
        }),
      ),
    );

    render();

    const bars = [...page.querySelectorAll('.bars li')].map((row) => ({
      label: row.querySelector('.bar-label')?.textContent,
      count: row.querySelector('.bar-count')?.textContent,
      width: row.querySelector<HTMLElement>('.bar-fill')?.style.width,
    }));
    expect(bars).toEqual([
      { label: 'Critical', count: '2', width: '25%' },
      { label: 'High', count: '8', width: '100%' },
      { label: 'Medium', count: '4', width: '50%' },
      { label: 'Low', count: '1', width: '12.5%' },
      { label: 'Info', count: '0', width: '0%' },
    ]);
  });

  it('ranks the most frequent weaknesses', () => {
    dashboardSummary.mockReturnValue(
      of(
        makeSummary({
          total_scans: 1,
          scans_by_status: { PENDING: 0, RUNNING: 0, COMPLETED: 1, FAILED: 0 },
          total_findings: 4,
          findings_by_severity: { CRITICAL: 0, HIGH: 4, MEDIUM: 0, LOW: 0, INFO: 0 },
          top_cwes: [
            { cwe_id: 'CWE-89', count: 3 },
            { cwe_id: 'CWE-79', count: 1 },
          ],
        }),
      ),
    );

    render();

    const ranking = [...page.querySelectorAll('.ranking li')].map((row) =>
      [...row.querySelectorAll('span')].map((cell) => cell.textContent?.trim()),
    );
    expect(ranking).toEqual([
      ['CWE-89', '3 findings'],
      ['CWE-79', '1 finding'],
    ]);
  });

  it('lists the recent scans with a link to each, without a delete action', () => {
    const recent = makeScan({ total_findings: 4 });
    dashboardSummary.mockReturnValue(
      of(
        makeSummary({
          total_scans: 1,
          scans_by_status: { PENDING: 0, RUNNING: 0, COMPLETED: 1, FAILED: 0 },
          recent_scans: [recent],
        }),
      ),
    );

    render();

    const row = page.querySelector('tbody tr') as HTMLElement;
    expect(row.querySelector('a')?.getAttribute('href')).toBe(`/scans/${recent.id}`);
    expect(row.textContent).not.toContain('Delete');
  });

  it('refreshes while a scan is in progress, and stops once none is', async () => {
    const running = makeSummary({
      total_scans: 1,
      scans_by_status: { PENDING: 0, RUNNING: 1, COMPLETED: 0, FAILED: 0 },
    });
    const finished = makeSummary({
      total_scans: 1,
      scans_by_status: { PENDING: 0, RUNNING: 0, COMPLETED: 1, FAILED: 0 },
      total_findings: 3,
    });
    dashboardSummary.mockReturnValueOnce(of(running)).mockReturnValue(of(finished));

    render();
    expect(stat('In progress')).toBe('1');

    await vi.waitFor(() => {
      fixture.detectChanges();
      expect(stat('In progress')).toBe('0');
    });
    expect(stat('Findings')).toBe('3');

    await new Promise((resolve) => setTimeout(resolve, 30));
    expect(dashboardSummary).toHaveBeenCalledTimes(2);
  });

  it('says so when the summary cannot be loaded', () => {
    dashboardSummary.mockReturnValue(throwError(() => new HttpErrorResponse({ status: 0 })));

    render();

    expect(page.querySelector('.alert-error')?.textContent).toContain('Cannot reach the server');
    expect(page.querySelector('[role="status"]')).toBeNull();
  });
});
