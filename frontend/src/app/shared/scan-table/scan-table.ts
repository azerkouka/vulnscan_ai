import { DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, input, output } from '@angular/core';
import { RouterLink } from '@angular/router';

import { Scan, isInProgress, sourceLabel } from '../../core/scans/scan.models';
import { StatusBadge } from '../badges/status-badge';

/** A list of scans as a table - used by the scan list and the dashboard. */
@Component({
  selector: 'app-scan-table',
  imports: [DatePipe, RouterLink, StatusBadge],
  templateUrl: './scan-table.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ScanTable {
  readonly scans = input.required<readonly Scan[]>();
  /** Shows a delete action per row (only offered for scans that have finished). */
  readonly deletable = input(false);
  /** Id of the scan currently being deleted, to disable its button meanwhile. */
  readonly deletingId = input<string | null>(null);
  readonly remove = output<Scan>();

  protected readonly sourceLabel = sourceLabel;
  protected readonly isInProgress = isInProgress;
}
