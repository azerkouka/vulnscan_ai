import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';

import { AuthService } from '../../core/auth/auth-service';
import { Brand } from '../../shared/brand/brand';

interface NavItem {
  label: string;
  path: string;
  /** Highlight only on this exact path, not on pages beneath it. */
  exact: boolean;
}

/** The frame around every signed-in page: header, navigation, user menu. */
@Component({
  selector: 'app-shell',
  imports: [RouterOutlet, RouterLink, RouterLinkActive, Brand],
  templateUrl: './shell.html',
  styleUrl: './shell.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class Shell {
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);

  protected readonly user = this.auth.user;

  protected readonly navItems: readonly NavItem[] = [
    { label: 'Dashboard', path: '/dashboard', exact: true },
    { label: 'Scans', path: '/scans', exact: false },
  ];

  protected signOut(): void {
    // The session is cleared synchronously by logout(); the revocation call
    // it returns only needs to be started, not waited for.
    this.auth.logout().subscribe();
    void this.router.navigate(['/login']);
  }
}
