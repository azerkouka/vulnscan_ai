import { DatePipe, TitleCasePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { EMPTY, catchError, map, switchMap, tap } from 'rxjs';

import { describeHttpError } from '../../../core/api/api-error';
import { FileSaver } from '../../../core/api/file-saver';
import { POLL_INTERVAL, pollWhile } from '../../../core/scans/poll';
import { ScanService } from '../../../core/scans/scan-service';
import {
  ReportFormat,
  SEVERITIES,
  ScanReport,
  Severity,
  isInProgress,
  sourceLabel,
} from '../../../core/scans/scan.models';
import { StatusBadge } from '../../../shared/badges/status-badge';
import { FindingCard } from './finding-card';

type SeverityFilter = Severity | 'ALL';

/**
 * One scan: its progress while it is being analyzed, then its report.
 *
 * The report endpoint answers at any status (with the findings recorded so
 * far), so this page simply re-reads it until the scan has finished.
 */
@Component({
  selector: 'app-scan-report',
  imports: [DatePipe, TitleCasePipe, RouterLink, StatusBadge, FindingCard],
  templateUrl: './scan-report.html',
  styleUrl: './scan-report.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ScanReportPage {
  private readonly scans = inject(ScanService);
  private readonly router = inject(Router);
  private readonly fileSaver = inject(FileSaver);
  private readonly pollInterval = inject(POLL_INTERVAL);

  protected readonly severities = SEVERITIES;
  protected readonly sourceLabel = sourceLabel;

  protected readonly report = signal<ScanReport | null>(null);
  protected readonly notFound = signal(false);
  protected readonly loadError = signal<string | null>(null);
  protected readonly actionError = signal<string | null>(null);
  protected readonly deleting = signal(false);
  /** The format being downloaded right now, if any. */
  protected readonly exporting = signal<ReportFormat | null>(null);
  protected readonly filter = signal<SeverityFilter>('ALL');

  protected readonly inProgress = computed(() => {
    const report = this.report();
    return report !== null && isInProgress(report.scan.status);
  });
  protected readonly visibleFindings = computed(() => {
    const findings = this.report()?.findings ?? [];
    const filter = this.filter();
    return filter === 'ALL' ? findings : findings.filter((f) => f.severity === filter);
  });
  protected readonly totalLines = computed(() =>
    (this.report()?.files ?? []).reduce((total, file) => total + file.loc, 0),
  );

  constructor() {
    inject(ActivatedRoute)
      .paramMap.pipe(
        map((params) => params.get('id') ?? ''),
        tap(() => {
          this.report.set(null);
          this.notFound.set(false);
          this.loadError.set(null);
          this.filter.set('ALL');
        }),
        switchMap((scanId) =>
          pollWhile(
            () => this.scans.getReport(scanId),
            (report) => isInProgress(report.scan.status),
            this.pollInterval,
          ).pipe(
            catchError((error: unknown) => {
              // 404: no such scan, or not ours. 422: the id isn't even a valid one.
              const missing =
                error instanceof HttpErrorResponse &&
                (error.status === 404 || error.status === 422);
              if (missing) {
                this.notFound.set(true);
              } else {
                this.loadError.set(describeHttpError(error, 'This scan could not be loaded.'));
              }
              return EMPTY;
            }),
          ),
        ),
        takeUntilDestroyed(),
      )
      .subscribe((report) => {
        this.loadError.set(null);
        this.report.set(report);
      });
  }

  protected download(format: ReportFormat): void {
    const report = this.report();
    if (report === null || this.exporting() !== null) {
      return;
    }
    this.exporting.set(format);
    this.actionError.set(null);
    this.scans.downloadReport(report.scan.id, format).subscribe({
      next: (file) => {
        this.fileSaver.save(file, `vulnscan-report-${report.scan.id}.${format}`);
        this.exporting.set(null);
      },
      error: (error: unknown) => {
        this.exporting.set(null);
        this.actionError.set(describeHttpError(error, 'The report could not be downloaded.'));
      },
    });
  }

  protected remove(): void {
    const report = this.report();
    if (report === null || this.deleting()) {
      return;
    }
    if (!confirm('Delete this scan, its report and its stored source code?')) {
      return;
    }
    this.deleting.set(true);
    this.actionError.set(null);
    this.scans.delete(report.scan.id).subscribe({
      next: () => void this.router.navigate(['/scans']),
      error: (error: unknown) => {
        this.deleting.set(false);
        this.actionError.set(describeHttpError(error, 'The scan could not be deleted.'));
      },
    });
  }
}
