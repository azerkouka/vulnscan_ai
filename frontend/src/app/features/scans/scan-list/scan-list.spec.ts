import { HttpErrorResponse } from '@angular/common/http';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { Observable, of, throwError } from 'rxjs';

import { makeScan, makeScanList } from '../../../../testing/scan-fixtures';
import { POLL_INTERVAL } from '../../../core/scans/poll';
import { ScanService } from '../../../core/scans/scan-service';
import { ScanList as ScanListPage } from '../../../core/scans/scan.models';
import { ScanList } from './scan-list';

describe('ScanList', () => {
  let list: ReturnType<typeof vi.fn<(limit: number, offset: number) => Observable<ScanListPage>>>;
  let remove: ReturnType<typeof vi.fn<(scanId: string) => Observable<void>>>;
  let fixture: ComponentFixture<ScanList>;
  let page: HTMLElement;

  beforeEach(() => {
    list = vi.fn<(limit: number, offset: number) => Observable<ScanListPage>>();
    remove = vi.fn<(scanId: string) => Observable<void>>(() => of(undefined));
    TestBed.configureTestingModule({
      providers: [
        provideRouter([]),
        { provide: ScanService, useValue: { list, delete: remove } },
        { provide: POLL_INTERVAL, useValue: 5 },
      ],
    });
  });

  afterEach(() => vi.restoreAllMocks());

  function render(): void {
    fixture = TestBed.createComponent(ScanList);
    fixture.detectChanges();
    page = fixture.nativeElement as HTMLElement;
  }

  const rows = (): HTMLTableRowElement[] => [
    ...page.querySelectorAll<HTMLTableRowElement>('tbody tr'),
  ];
  const button = (label: string): HTMLButtonElement | undefined =>
    [...page.querySelectorAll<HTMLButtonElement>('button')].find(
      (candidate) => candidate.textContent?.trim() === label,
    );

  it('invites a user with no scan to start one', () => {
    list.mockReturnValue(of(makeScanList([])));

    render();

    expect(page.querySelector('.empty-state h2')?.textContent).toBe('No scans yet');
    expect(page.querySelector('.empty-state a')?.getAttribute('href')).toBe('/scans/new');
    expect(page.querySelector('table')).toBeNull();
  });

  it('lists scans with their status, counts and a link to each report', () => {
    const completed = makeScan({ source_type: 'ZIP', total_files: 12, total_findings: 7 });
    const failed = makeScan({ status: 'FAILED', source_type: 'FILE' });
    list.mockReturnValue(of(makeScanList([completed, failed])));

    render();

    expect(list).toHaveBeenCalledWith(10, 0);
    const [first, second] = rows();
    expect(first.textContent).toContain('Archive');
    expect(first.textContent).toContain('Completed');
    expect(first.querySelectorAll('.numeric')[0].textContent).toBe('12');
    expect(first.querySelectorAll('.numeric')[1].textContent).toBe('7');
    expect(first.querySelector('a')?.getAttribute('href')).toBe(`/scans/${completed.id}`);
    expect(second.textContent).toContain('Failed');
    expect(page.querySelector('.pagination p')?.textContent?.trim()).toBe('1–2 of 2');
  });

  it('keeps refreshing while a scan is running, and stops once all have finished', async () => {
    const scan = makeScan({ status: 'RUNNING', progress_percent: 40 });
    list
      .mockReturnValueOnce(of(makeScanList([scan])))
      .mockReturnValueOnce(of(makeScanList([{ ...scan, progress_percent: 80 }])))
      .mockReturnValue(of(makeScanList([{ ...scan, status: 'COMPLETED', progress_percent: 100 }])));

    render();
    expect(rows()[0].textContent).toContain('Analyzing');
    expect(rows()[0].textContent).toContain('40%');

    await vi.waitFor(() => {
      fixture.detectChanges();
      expect(rows()[0].textContent).toContain('Completed');
    });
    const callsOnceFinished = list.mock.calls.length;
    expect(callsOnceFinished).toBe(3);

    await new Promise((resolve) => setTimeout(resolve, 30));
    expect(list.mock.calls.length).toBe(callsOnceFinished);
  });

  it('pages through the scans', () => {
    const firstPage = Array.from({ length: 10 }, () => makeScan());
    list.mockImplementation((_limit, offset) =>
      of(
        offset === 0
          ? makeScanList(firstPage, { total: 13, offset: 0 })
          : makeScanList([makeScan(), makeScan(), makeScan()], { total: 13, offset: 10 }),
      ),
    );

    render();
    expect(page.querySelector('.pagination p')?.textContent?.trim()).toBe('1–10 of 13');
    expect(button('Previous')?.disabled).toBe(true);
    expect(button('Next')?.disabled).toBe(false);

    button('Next')?.click();
    fixture.detectChanges();

    expect(list).toHaveBeenLastCalledWith(10, 10);
    expect(rows()).toHaveLength(3);
    expect(page.querySelector('.pagination p')?.textContent?.trim()).toBe('11–13 of 13');
    expect(button('Next')?.disabled).toBe(true);
    expect(button('Previous')?.disabled).toBe(false);
  });

  it('deletes a scan after confirmation and reloads the list', () => {
    const scan = makeScan();
    list.mockReturnValueOnce(of(makeScanList([scan]))).mockReturnValue(of(makeScanList([])));
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true);
    render();

    button('Delete')?.click();
    fixture.detectChanges();

    expect(confirm).toHaveBeenCalledTimes(1);
    expect(remove).toHaveBeenCalledWith(scan.id);
    expect(list).toHaveBeenCalledTimes(2);
    expect(page.querySelector('.empty-state h2')?.textContent).toBe('No scans yet');
  });

  it('deletes nothing when the confirmation is declined', () => {
    list.mockReturnValue(of(makeScanList([makeScan()])));
    vi.spyOn(window, 'confirm').mockReturnValue(false);
    render();

    button('Delete')?.click();

    expect(remove).not.toHaveBeenCalled();
    expect(rows()).toHaveLength(1);
  });

  it('does not offer to delete a scan that is still in progress', () => {
    list.mockReturnValue(of(makeScanList([makeScan({ status: 'PENDING', progress_percent: 0 })])));
    // One load only: this test is not about polling.
    TestBed.overrideProvider(POLL_INTERVAL, { useValue: 60_000 });

    render();

    expect(button('Delete')?.disabled).toBe(true);
  });

  it('reports a failed deletion and keeps the scan listed', () => {
    list.mockReturnValue(of(makeScanList([makeScan()])));
    remove.mockReturnValue(
      throwError(
        () =>
          new HttpErrorResponse({
            status: 409,
            error: {
              error: { code: 'ScanInProgress', message: 'This scan is still in progress.' },
            },
          }),
      ),
    );
    vi.spyOn(window, 'confirm').mockReturnValue(true);
    render();

    button('Delete')?.click();
    fixture.detectChanges();

    expect(page.querySelector('.alert-error')?.textContent).toContain('still in progress');
    expect(rows()).toHaveLength(1);
    expect(button('Delete')?.disabled).toBe(false);
  });

  it('offers to retry when the list cannot be loaded', () => {
    list
      .mockReturnValueOnce(throwError(() => new HttpErrorResponse({ status: 0 })))
      .mockReturnValue(of(makeScanList([makeScan()])));

    render();
    expect(page.querySelector('.alert-error')?.textContent).toContain('Cannot reach the server');

    button('Try again')?.click();
    fixture.detectChanges();

    expect(page.querySelector('.alert-error')).toBeNull();
    expect(rows()).toHaveLength(1);
  });
});
