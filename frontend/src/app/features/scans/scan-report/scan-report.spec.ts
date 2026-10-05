import { HttpErrorResponse } from '@angular/common/http';
import { Component } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { Router, provideRouter } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { Observable, Subject, of, throwError } from 'rxjs';

import { makeFinding, makeReport, makeScan, makeScanFile } from '../../../../testing/scan-fixtures';
import { FileSaver } from '../../../core/api/file-saver';
import { POLL_INTERVAL } from '../../../core/scans/poll';
import { ScanService } from '../../../core/scans/scan-service';
import { ReportFormat, ScanReport } from '../../../core/scans/scan.models';
import { ScanReportPage } from './scan-report';

@Component({ template: '' })
class Blank {}

describe('ScanReportPage', () => {
  let getReport: ReturnType<typeof vi.fn<(scanId: string) => Observable<ScanReport>>>;
  let remove: ReturnType<typeof vi.fn<(scanId: string) => Observable<void>>>;
  let downloadReport: ReturnType<
    typeof vi.fn<(scanId: string, format: ReportFormat) => Observable<Blob>>
  >;
  let save: ReturnType<typeof vi.fn<(content: Blob, filename: string) => void>>;
  let harness: RouterTestingHarness;
  let page: HTMLElement;

  beforeEach(() => {
    getReport = vi.fn<(scanId: string) => Observable<ScanReport>>();
    remove = vi.fn<(scanId: string) => Observable<void>>(() => of(undefined));
    downloadReport = vi.fn<(scanId: string, format: ReportFormat) => Observable<Blob>>(() =>
      of(new Blob(['report'])),
    );
    save = vi.fn<(content: Blob, filename: string) => void>();
    TestBed.configureTestingModule({
      providers: [
        provideRouter([
          { path: 'scans/:id', component: ScanReportPage },
          { path: '**', component: Blank },
        ]),
        { provide: ScanService, useValue: { getReport, delete: remove, downloadReport } },
        { provide: FileSaver, useValue: { save } },
        { provide: POLL_INTERVAL, useValue: 5 },
      ],
    });
  });

  afterEach(() => vi.restoreAllMocks());

  async function open(scanId = 'scan-1'): Promise<void> {
    harness = await RouterTestingHarness.create(`/scans/${scanId}`);
    harness.detectChanges();
    page = harness.routeNativeElement as HTMLElement;
  }

  const text = (selector: string): string =>
    page.querySelector(selector)?.textContent?.trim() ?? '';
  const chip = (label: string): HTMLButtonElement | undefined =>
    [...page.querySelectorAll<HTMLButtonElement>('.chip')].find((candidate) =>
      candidate.textContent?.trim().startsWith(label),
    );
  const findingTitles = (): string[] =>
    [...page.querySelectorAll('.finding-title')].map((title) => title.textContent ?? '');

  it('loads the report of the scan named in the address', async () => {
    getReport.mockReturnValue(of(makeReport()));

    await open('abc-123');

    expect(getReport).toHaveBeenCalledWith('abc-123');
  });

  it('shows the findings of a completed scan, most severe first as sent by the API', async () => {
    const scan = makeScan({ source_type: 'ZIP' });
    const files = [makeScanFile({ loc: 40 }), makeScanFile({ loc: 2 })];
    const findings = [
      makeFinding({ title: 'Command injection', severity: 'CRITICAL' }),
      makeFinding({ title: 'SQL injection', severity: 'HIGH' }),
      makeFinding({ title: 'Verbose error', severity: 'LOW' }),
    ];
    getReport.mockReturnValue(of(makeReport(scan, findings, files)));

    await open();

    expect(text('h1')).toContain('Archive scan');
    expect(text('h1')).toContain('Completed');
    expect(text('.page-header .muted')).toContain('2 files');
    expect(text('.page-header .muted')).toContain('42 lines');
    expect(findingTitles()).toEqual(['Command injection', 'SQL injection', 'Verbose error']);
    // Only the first finding starts expanded.
    const cards = [...page.querySelectorAll<HTMLDetailsElement>('details')];
    expect(cards.map((card) => card.open)).toEqual([true, false, false]);
    expect(page.querySelector('progress')).toBeNull();
  });

  it('shows each finding in full', async () => {
    const finding = makeFinding({ confidence: 0.85, line_start: 4, line_end: 5 });
    getReport.mockReturnValue(of(makeReport(makeScan(), [finding])));

    await open();

    const card = page.querySelector('details') as HTMLElement;
    expect(card.querySelector('.finding-location')?.textContent).toBe('app.py, lines 4–5');
    expect(card.textContent).toContain('85%');
    expect(card.textContent).toContain('User input is concatenated into the SQL query.');
    expect(card.textContent).toContain('Use a parameterized query.');
    // The snippet keeps the line numbers of the scanned file, and its indentation.
    const lines = [...card.querySelectorAll('.code-line')];
    expect(lines.map((line) => line.querySelector('.code-line-number')?.textContent)).toEqual([
      '4',
      '5',
    ]);
    expect(lines[1].querySelector('.code-line-text')?.textContent).toBe(
      '    return conn.execute(query)',
    );
    expect(card.querySelector('pre.code-block')?.textContent).toContain('WHERE name = ?');
    const reference = card.querySelector<HTMLAnchorElement>('.references a');
    expect(reference?.textContent).toBe('CWE-89');
    expect(reference?.getAttribute('href')).toBe('https://cwe.mitre.org/data/definitions/89.html');
    expect(reference?.getAttribute('rel')).toBe('noopener noreferrer');
  });

  it('renders model output as text, never as markup or as a script link', async () => {
    const hostile = makeFinding({
      title: '<img src=x onerror="window.__xss = 1">',
      explanation: '<script>window.__xss = 1</script><b>bold</b>',
      vulnerable_snippet: '</span><script>window.__xss = 1</script>',
      fixed_code: '<iframe src="javascript:alert(1)"></iframe>',
      references: [
        { source: 'OTHER', ref_id: 'EVIL-1', title: 'bad link', url: 'javascript:alert(1)' },
        { source: 'OTHER', ref_id: 'EVIL-2', title: 'no link', url: null },
      ],
    });
    getReport.mockReturnValue(of(makeReport(makeScan(), [hostile])));

    await open();

    expect(page.querySelector('img, script, iframe, b')).toBeNull();
    expect((window as unknown as Record<string, unknown>)['__xss']).toBeUndefined();
    expect(text('.finding-title')).toBe('<img src=x onerror="window.__xss = 1">');
    expect(text('.code-line-text')).toBe('</span><script>window.__xss = 1</script>');
    // Neither reference became a link: one has a javascript: URL, the other none.
    expect(page.querySelector('.references a')).toBeNull();
    expect(text('.references')).toContain('EVIL-1');
  });

  it('filters findings by severity', async () => {
    const findings = [
      makeFinding({ title: 'Command injection', severity: 'CRITICAL' }),
      makeFinding({ title: 'SQL injection', severity: 'HIGH' }),
      makeFinding({ title: 'XSS', severity: 'HIGH' }),
    ];
    getReport.mockReturnValue(of(makeReport(makeScan(), findings)));
    await open();

    expect(chip('All')?.textContent).toContain('3');
    expect(chip('High')?.textContent).toContain('2');
    // No chip for a severity without any finding.
    expect(chip('Low')).toBeUndefined();

    chip('High')?.click();
    harness.detectChanges();
    expect(findingTitles()).toEqual(['SQL injection', 'XSS']);
    expect(chip('High')?.getAttribute('aria-pressed')).toBe('true');
    expect(chip('All')?.getAttribute('aria-pressed')).toBe('false');

    chip('All')?.click();
    harness.detectChanges();
    expect(findingTitles()).toHaveLength(3);
  });

  it('follows a running scan until it completes', async () => {
    const scan = makeScan({ id: 'scan-1', status: 'RUNNING', progress_percent: 30 });
    const done = { ...scan, status: 'COMPLETED' as const, progress_percent: 100 };
    getReport
      .mockReturnValueOnce(of(makeReport(scan)))
      .mockReturnValueOnce(of(makeReport({ ...scan, progress_percent: 70 }, [makeFinding()])))
      .mockReturnValue(of(makeReport(done, [makeFinding(), makeFinding({ title: 'XSS' })])));

    await open();
    expect(text('#progress-title')).toBe('Analyzing your code');
    expect(page.querySelector('progress')?.getAttribute('value')).toBe('30');
    // Cannot be deleted while it runs.
    expect(page.querySelector<HTMLButtonElement>('.btn-danger')?.disabled).toBe(true);

    await vi.waitFor(() => {
      harness.detectChanges();
      expect(text('h1')).toContain('Completed');
    });
    expect(page.querySelector('progress')).toBeNull();
    expect(findingTitles()).toHaveLength(2);
    expect(page.querySelector<HTMLButtonElement>('.btn-danger')?.disabled).toBe(false);

    const callsOnceFinished = getReport.mock.calls.length;
    await new Promise((resolve) => setTimeout(resolve, 30));
    expect(getReport.mock.calls.length).toBe(callsOnceFinished);
  });

  it('says a queued scan is waiting', async () => {
    TestBed.overrideProvider(POLL_INTERVAL, { useValue: 60_000 });
    getReport.mockReturnValue(of(makeReport(makeScan({ status: 'PENDING', progress_percent: 0 }))));

    await open();

    expect(text('#progress-title')).toBe('Waiting to start');
  });

  it('explains why a scan failed', async () => {
    const failed = makeScan({
      status: 'FAILED',
      error_message: 'The LLM could not analyze any of the submitted code.',
    });
    getReport.mockReturnValue(of(makeReport(failed)));

    await open();

    expect(text('.alert-error')).toContain('This scan failed.');
    expect(text('.alert-error')).toContain('The LLM could not analyze any of the submitted code.');
    expect(page.querySelector('.empty-state')).toBeNull();
  });

  it('warns when a completed scan is only partial', async () => {
    const partial = makeScan({
      error_message: '2 of 9 code chunks could not be analyzed; this report may be incomplete.',
    });
    getReport.mockReturnValue(of(makeReport(partial, [makeFinding()])));

    await open();

    expect(text('.alert-warning')).toContain('2 of 9 code chunks');
    expect(findingTitles()).toHaveLength(1);
  });

  it('does not present an empty report as proof the code is secure', async () => {
    getReport.mockReturnValue(of(makeReport(makeScan(), [])));

    await open();

    expect(text('.empty-state h2')).toBe('No vulnerabilities found');
    expect(text('.empty-state p')).toContain('not proof that the code is secure');
  });

  it.each([404, 422])('shows a not-found page when the API answers %s', async (status) => {
    getReport.mockReturnValue(throwError(() => new HttpErrorResponse({ status })));

    await open('missing');

    expect(text('h1')).toBe('Scan not found');
    expect(page.querySelector('a')?.getAttribute('href')).toBe('/scans');
  });

  it('reports other loading failures as such', async () => {
    getReport.mockReturnValue(throwError(() => new HttpErrorResponse({ status: 0 })));

    await open();

    expect(text('.alert-error')).toContain('Cannot reach the server');
    expect(page.querySelector('h1')).toBeNull();
  });

  it.each(['json', 'pdf'] as const)('downloads the report as %s', async (format) => {
    const file = new Blob(['report']);
    downloadReport.mockReturnValue(of(file));
    getReport.mockReturnValue(of(makeReport(makeScan({ id: 'scan-1' }), [makeFinding()])));
    await open();

    page.querySelector<HTMLButtonElement>(`[data-export="${format}"]`)?.click();
    harness.detectChanges();

    expect(downloadReport).toHaveBeenCalledWith('scan-1', format);
    expect(save).toHaveBeenCalledWith(file, `vulnscan-report-scan-1.${format}`);
    // Ready for another download.
    expect(page.querySelector<HTMLButtonElement>(`[data-export="${format}"]`)?.disabled).toBe(
      false,
    );
  });

  it('shows a download in progress and blocks a second one meanwhile', async () => {
    downloadReport.mockReturnValue(new Subject<Blob>());
    getReport.mockReturnValue(of(makeReport()));
    await open();

    page.querySelector<HTMLButtonElement>('[data-export="pdf"]')?.click();
    harness.detectChanges();
    page.querySelector<HTMLButtonElement>('[data-export="json"]')?.click();

    expect(downloadReport).toHaveBeenCalledTimes(1);
    expect(text('[data-export="pdf"]')).toBe('Preparing…');
    expect(page.querySelector<HTMLButtonElement>('[data-export="json"]')?.disabled).toBe(true);
    expect(save).not.toHaveBeenCalled();
  });

  it('explains why a download failed', async () => {
    downloadReport.mockReturnValue(
      throwError(
        () =>
          new HttpErrorResponse({
            status: 503,
            error: {
              error: {
                code: 'ReportFormatUnavailable',
                message: 'PDF export is not available on this installation.',
              },
            },
          }),
      ),
    );
    getReport.mockReturnValue(of(makeReport()));
    await open();

    page.querySelector<HTMLButtonElement>('[data-export="pdf"]')?.click();
    harness.detectChanges();

    expect(text('.alert-error')).toBe('PDF export is not available on this installation.');
    expect(save).not.toHaveBeenCalled();
    expect(page.querySelector<HTMLButtonElement>('[data-export="pdf"]')?.disabled).toBe(false);
  });

  it('does not offer a download while the scan is still running', async () => {
    TestBed.overrideProvider(POLL_INTERVAL, { useValue: 60_000 });
    getReport.mockReturnValue(
      of(makeReport(makeScan({ status: 'RUNNING', progress_percent: 10 }))),
    );

    await open();

    expect(page.querySelector<HTMLButtonElement>('[data-export="json"]')?.disabled).toBe(true);
    expect(page.querySelector<HTMLButtonElement>('[data-export="pdf"]')?.disabled).toBe(true);
  });

  it('deletes the scan after confirmation and returns to the list', async () => {
    getReport.mockReturnValue(of(makeReport(makeScan({ id: 'scan-1' }))));
    vi.spyOn(window, 'confirm').mockReturnValue(true);
    await open();

    page.querySelector<HTMLButtonElement>('.btn-danger')?.click();
    await harness.fixture.whenStable();

    expect(remove).toHaveBeenCalledWith('scan-1');
    expect(TestBed.inject(Router).url).toBe('/scans');
  });

  it('keeps the scan when the confirmation is declined', async () => {
    getReport.mockReturnValue(of(makeReport()));
    vi.spyOn(window, 'confirm').mockReturnValue(false);
    await open();

    page.querySelector<HTMLButtonElement>('.btn-danger')?.click();

    expect(remove).not.toHaveBeenCalled();
    expect(TestBed.inject(Router).url).toBe('/scans/scan-1');
  });
});
