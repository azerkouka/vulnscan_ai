import { Injectable } from '@angular/core';

const REFRESH_TOKEN_KEY = 'vulnscan.refresh_token';

/**
 * Where the refresh token lives between page loads.
 *
 * Only the refresh token is persisted - the access token stays in memory
 * (`AuthService`) and is re-obtained from the refresh token after a reload.
 *
 * `sessionStorage` rather than `localStorage`, for two reasons:
 * - it is scoped to the tab and gone when the tab closes, which limits how
 *   long a token readable by injected script stays around;
 * - the backend rotates refresh tokens and treats the reuse of an already
 *   rotated one as theft, revoking every session of the user. Two tabs
 *   sharing one stored token would trip that the moment both refreshed.
 *   With per-tab storage each tab holds its own token.
 */
@Injectable({ providedIn: 'root' })
export class TokenStorage {
  getRefreshToken(): string | null {
    try {
      return sessionStorage.getItem(REFRESH_TOKEN_KEY);
    } catch {
      return null; // storage blocked (privacy mode, embedded contexts)
    }
  }

  setRefreshToken(token: string): void {
    try {
      sessionStorage.setItem(REFRESH_TOKEN_KEY, token);
    } catch {
      // Without storage the session simply won't survive a reload.
    }
  }

  clear(): void {
    try {
      sessionStorage.removeItem(REFRESH_TOKEN_KEY);
    } catch {
      // Nothing was stored, nothing to remove.
    }
  }
}
