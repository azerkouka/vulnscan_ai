import { PercentPipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, computed, input } from '@angular/core';

import { Finding } from '../../../core/scans/scan.models';
import { SeverityBadge } from '../../../shared/badges/severity-badge';

interface NumberedLine {
  number: number;
  text: string;
}

/**
 * One finding of a report, collapsible.
 *
 * Everything shown here ultimately comes from an LLM reading user-submitted
 * code, so it is all rendered as plain text through Angular's interpolation
 * (never as HTML), and a reference is only made a link when its URL is plain
 * http(s).
 */
@Component({
  selector: 'app-finding-card',
  imports: [PercentPipe, SeverityBadge],
  templateUrl: './finding-card.html',
  styleUrl: './finding-card.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class FindingCard {
  readonly finding = input.required<Finding>();
  /** Whether the card starts expanded. */
  readonly expanded = input(false);

  protected readonly location = computed(() => {
    const { file_path, line_start, line_end } = this.finding();
    const lines =
      line_start === line_end ? `line ${line_start}` : `lines ${line_start}–${line_end}`;
    return `${file_path}, ${lines}`;
  });

  /** The vulnerable lines, numbered as they are in the scanned file. */
  protected readonly snippetLines = computed<NumberedLine[]>(() => {
    const { vulnerable_snippet, line_start } = this.finding();
    return vulnerable_snippet
      .split('\n')
      .map((text, index) => ({ number: line_start + index, text }));
  });

  protected linkable(url: string | null): url is string {
    return url !== null && /^https?:\/\//i.test(url);
  }
}
