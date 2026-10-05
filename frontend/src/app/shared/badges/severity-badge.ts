import { TitleCasePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, input } from '@angular/core';

import { Severity } from '../../core/scans/scan.models';

@Component({
  selector: 'app-severity-badge',
  imports: [TitleCasePipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `<span class="badge" [attr.data-severity]="severity()">{{
    severity() | titlecase
  }}</span>`,
})
export class SeverityBadge {
  readonly severity = input.required<Severity>();
}
