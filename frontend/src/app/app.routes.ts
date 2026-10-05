import { Routes } from '@angular/router';

import { authGuard, guestGuard } from './core/auth/auth-guards';

export const routes: Routes = [
  {
    path: 'login',
    canActivate: [guestGuard],
    title: 'Sign in · VulnScan AI',
    loadComponent: () => import('./features/auth/login/login').then((m) => m.Login),
  },
  {
    path: 'register',
    canActivate: [guestGuard],
    title: 'Create account · VulnScan AI',
    loadComponent: () => import('./features/auth/register/register').then((m) => m.Register),
  },
  {
    // Everything behind sign-in shares the shell (header, navigation).
    path: '',
    canActivate: [authGuard],
    loadComponent: () => import('./layout/shell/shell').then((m) => m.Shell),
    children: [
      { path: '', pathMatch: 'full', redirectTo: 'dashboard' },
      {
        path: 'dashboard',
        title: 'Dashboard · VulnScan AI',
        loadComponent: () => import('./features/dashboard/dashboard').then((m) => m.Dashboard),
      },
      {
        path: 'scans',
        title: 'Scans · VulnScan AI',
        loadComponent: () => import('./features/scans/scan-list/scan-list').then((m) => m.ScanList),
      },
      {
        // Declared before ':id', which would otherwise take "new" for a scan id.
        path: 'scans/new',
        title: 'New scan · VulnScan AI',
        loadComponent: () => import('./features/scans/new-scan/new-scan').then((m) => m.NewScan),
      },
      {
        path: 'scans/:id',
        title: 'Scan report · VulnScan AI',
        loadComponent: () =>
          import('./features/scans/scan-report/scan-report').then((m) => m.ScanReportPage),
      },
    ],
  },
  {
    path: '**',
    title: 'Page not found · VulnScan AI',
    loadComponent: () => import('./features/not-found/not-found').then((m) => m.NotFound),
  },
];
