import { ChangeDetectionStrategy, Component } from '@angular/core';
import { RouterLink } from '@angular/router';

@Component({
  selector: 'app-not-found',
  imports: [RouterLink],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <main class="auth-page">
      <section class="card auth-card" aria-labelledby="not-found-title">
        <h1 id="not-found-title">Page not found</h1>
        <p class="muted">The page you are looking for does not exist or has moved.</p>
        <a class="btn btn-primary" routerLink="/">Back to the app</a>
      </section>
    </main>
  `,
})
export class NotFound {}
