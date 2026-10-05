import { ChangeDetectionStrategy, Component, computed, input } from '@angular/core';

import { ScanStatus } from '../../core/scans/scan.models';

const LABELS: Record<ScanStatus, string> = {
  PENDING: 'Queued',
  RUNNING: 'Analyzing',
  COMPLETED: 'Completed',
  FAILED: 'Failed',
};

@Component({
  selector: 'app-status-badge',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `<span class="badge" [attr.data-status]="status()">{{ label() }}</span>`,
})
export class StatusBadge {
  readonly status = input.required<ScanStatus>();
  protected readonly label = computed(() => LABELS[this.status()]);
}
