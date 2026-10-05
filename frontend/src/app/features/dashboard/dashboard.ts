import { TitleCasePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';

import { describeHttpError } from '../../core/api/api-error';
import { AuthService } from '../../core/auth/auth-service';
import { POLL_INTERVAL, pollWhile } from '../../core/scans/poll';
import { ScanService } from '../../core/scans/scan-service';
import { DashboardSummary, SEVERITIES, Severity } from '../../core/scans/scan.models';
import { ScanTable } from '../../shared/scan-table/scan-table';

interface SeverityBar {
  severity: Severity;
  count: number;
  /** Bar length, as a percentage of the most frequent severity. */
  percent: number;
}

/** Overview of the user's scans and findings, refreshed while scans are running. */
@Component({
  selector: 'app-dashboard',
  imports: [TitleCasePipe, RouterLink, ScanTable],
  templateUrl: './dashboard.html',
  styleUrl: './dashboard.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class Dashboard {
  private readonly user = inject(AuthService).user;

  protected readonly summary = signal<DashboardSummary | null>(null);
  protected readonly loadError = signal<string | null>(null);

  protected readonly greetingName = computed(() => {
    const user = this.user();
    return user?.full_name?.trim() || user?.email || '';
  });

  protected readonly inProgressCount = computed(() => {
    const byStatus = this.summary()?.scans_by_status;
    return byStatus ? byStatus.PENDING + byStatus.RUNNING : 0;
  });

  protected readonly severityBars = computed<SeverityBar[]>(() => {
    const counts = this.summary()?.findings_by_severity;
    if (!counts) {
      return [];
    }
    const highest = Math.max(1, ...SEVERITIES.map((severity) => counts[severity]));
    return SEVERITIES.map((severity) => ({
      severity,
      count: counts[severity],
      percent: (counts[severity] / highest) * 100,
    }));
  });

  constructor() {
    const scans = inject(ScanService);
    pollWhile(
      () => scans.dashboardSummary(),
      (summary) => summary.scans_by_status.PENDING + summary.scans_by_status.RUNNING > 0,
      inject(POLL_INTERVAL),
    )
      .pipe(takeUntilDestroyed())
      .subscribe({
        next: (summary) => this.summary.set(summary),
        error: (error: unknown) =>
          this.loadError.set(describeHttpError(error, 'The dashboard could not be loaded.')),
      });
  }
}
