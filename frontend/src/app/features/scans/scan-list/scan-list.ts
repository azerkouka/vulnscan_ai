import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import { BehaviorSubject, catchError, of, switchMap } from 'rxjs';

import { describeHttpError } from '../../../core/api/api-error';
import { POLL_INTERVAL, pollWhile } from '../../../core/scans/poll';
import { ScanService } from '../../../core/scans/scan-service';
import { Scan, ScanList as ScanListPage, isInProgress } from '../../../core/scans/scan.models';
import { ScanTable } from '../../../shared/scan-table/scan-table';

const PAGE_SIZE = 10;

/** All of the user's scans, newest first, kept up to date while any is still running. */
@Component({
  selector: 'app-scan-list',
  imports: [RouterLink, ScanTable],
  templateUrl: './scan-list.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ScanList {
  private readonly scans = inject(ScanService);
  private readonly pollInterval = inject(POLL_INTERVAL);

  /** Emits the offset to load; emitting the current one again reloads the page. */
  private readonly offset$ = new BehaviorSubject(0);

  protected readonly page = signal<ScanListPage | null>(null);
  protected readonly loadError = signal<string | null>(null);
  protected readonly actionError = signal<string | null>(null);
  protected readonly deletingId = signal<string | null>(null);

  protected readonly rangeStart = computed(() => {
    const page = this.page();
    return page === null || page.total === 0 ? 0 : page.offset + 1;
  });
  protected readonly rangeEnd = computed(() => {
    const page = this.page();
    return page === null ? 0 : page.offset + page.scans.length;
  });
  protected readonly hasPrevious = computed(() => (this.page()?.offset ?? 0) > 0);
  protected readonly hasNext = computed(() => {
    const page = this.page();
    return page !== null && page.offset + page.scans.length < page.total;
  });

  constructor() {
    this.offset$
      .pipe(
        // switchMap: asking for another page (or a reload) drops the poll of the previous one.
        switchMap((offset) =>
          pollWhile(
            () => this.scans.list(PAGE_SIZE, offset),
            (page) => page.scans.some((scan) => isInProgress(scan.status)),
            this.pollInterval,
          ).pipe(
            catchError((error: unknown) => {
              this.loadError.set(describeHttpError(error, 'Your scans could not be loaded.'));
              return of(null);
            }),
          ),
        ),
        takeUntilDestroyed(),
      )
      .subscribe((page) => {
        if (page !== null) {
          this.loadError.set(null);
          this.page.set(page);
        }
      });
  }

  protected previousPage(): void {
    this.offset$.next(Math.max(0, this.offset$.value - PAGE_SIZE));
  }

  protected nextPage(): void {
    this.offset$.next(this.offset$.value + PAGE_SIZE);
  }

  protected retry(): void {
    this.offset$.next(this.offset$.value);
  }

  protected remove(scan: Scan): void {
    if (!confirm('Delete this scan, its report and its stored source code?')) {
      return;
    }
    this.deletingId.set(scan.id);
    this.actionError.set(null);
    this.scans.delete(scan.id).subscribe({
      next: () => {
        this.deletingId.set(null);
        // Step back when the last scan of a page other than the first was deleted.
        const page = this.page();
        const emptiesPage = page !== null && page.scans.length === 1 && page.offset > 0;
        this.offset$.next(emptiesPage ? page.offset - PAGE_SIZE : this.offset$.value);
      },
      error: (error: unknown) => {
        this.deletingId.set(null);
        this.actionError.set(describeHttpError(error, 'The scan could not be deleted.'));
      },
    });
  }
}
