import { ChangeDetectionStrategy, Component } from '@angular/core';

/** The product mark: shield icon + name. Purely presentational. */
@Component({
  selector: 'app-brand',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true" focusable="false">
      <path
        d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Zm-1.2 13.6-3.4-3.4 1.4-1.4 2 2 4.4-4.4 1.4 1.4-5.8 5.8Z"
        fill="currentColor"
      />
    </svg>
    <span>VulnScan AI</span>
  `,
  styles: `
    :host {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      font-weight: 700;
      letter-spacing: -0.01em;
      color: var(--color-text);
    }

    svg {
      color: var(--color-accent);
    }
  `,
})
export class Brand {}
