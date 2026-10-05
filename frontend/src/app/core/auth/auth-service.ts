import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Injectable, computed, inject, signal } from '@angular/core';
import {
  Observable,
  catchError,
  finalize,
  firstValueFrom,
  map,
  of,
  shareReplay,
  switchMap,
  tap,
  throwError,
} from 'rxjs';

import { API_BASE_URL } from '../config/api-base-url';
import { Credentials, Registration, TokenPair, User } from './auth.models';
import { TokenStorage } from './token-storage';

/**
 * The signed-in user and their tokens.
 *
 * The access token is held in memory only; the refresh token is persisted
 * by `TokenStorage`. Attaching the access token to requests and renewing it
 * on a 401 is the job of `authInterceptor`, which calls back into this
 * service.
 */
@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly http = inject(HttpClient);
  private readonly baseUrl = inject(API_BASE_URL);
  private readonly storage = inject(TokenStorage);

  private readonly accessTokenState = signal<string | null>(null);
  private readonly userState = signal<User | null>(null);
  private refreshInFlight: Observable<string> | null = null;

  readonly user = this.userState.asReadonly();
  readonly isAuthenticated = computed(() => this.userState() !== null);

  accessToken(): string | null {
    return this.accessTokenState();
  }

  login(credentials: Credentials): Observable<User> {
    return this.http.post<TokenPair>(`${this.baseUrl}/auth/login`, credentials).pipe(
      tap((tokens) => this.storeTokens(tokens)),
      switchMap(() => this.loadCurrentUser()),
    );
  }

  /** Creates the account, then signs straight into it. */
  register(registration: Registration): Observable<User> {
    return this.http
      .post<User>(`${this.baseUrl}/auth/register`, registration)
      .pipe(
        switchMap(() => this.login({ email: registration.email, password: registration.password })),
      );
  }

  /**
   * Signs out locally at once, and asks the backend to revoke the refresh
   * token. A failed revocation is deliberately not surfaced: the user is
   * signed out on this device either way, and the token expires on its own.
   */
  logout(): Observable<void> {
    const refreshToken = this.storage.getRefreshToken();
    this.clearSession();
    if (refreshToken === null) {
      return of(undefined);
    }
    return this.http
      .post<void>(`${this.baseUrl}/auth/logout`, { refresh_token: refreshToken })
      .pipe(catchError(() => of(undefined)));
  }

  /**
   * Exchanges the refresh token for a new token pair and emits the new
   * access token.
   *
   * Single-flight: callers arriving while a refresh is under way share it.
   * This is required, not an optimization - refresh tokens are single-use,
   * so when several requests hit a 401 together, a second refresh call
   * would present an already rotated token, which the backend answers by
   * revoking all of the user's sessions.
   */
  refreshAccessToken(): Observable<string> {
    if (this.refreshInFlight !== null) {
      return this.refreshInFlight;
    }
    const refreshToken = this.storage.getRefreshToken();
    if (refreshToken === null) {
      return throwError(() => new Error('No refresh token available.'));
    }

    this.refreshInFlight = this.http
      .post<TokenPair>(`${this.baseUrl}/auth/refresh`, { refresh_token: refreshToken })
      .pipe(
        tap((tokens) => this.storeTokens(tokens)),
        map((tokens) => tokens.access_token),
        finalize(() => (this.refreshInFlight = null)),
        shareReplay({ bufferSize: 1, refCount: false }),
      );
    return this.refreshInFlight;
  }

  /**
   * Run once before the first route is activated (see `app.config.ts`):
   * turns a refresh token left by a previous page load back into a signed-in
   * session, so guards can decide synchronously. Never rejects - a session
   * that can't be restored just means starting signed out.
   */
  async restoreSession(): Promise<void> {
    if (this.storage.getRefreshToken() === null) {
      return;
    }
    try {
      await firstValueFrom(this.refreshAccessToken().pipe(switchMap(() => this.loadCurrentUser())));
    } catch (error) {
      // Only discard the stored token when the backend actually rejected it.
      // If the backend was merely unreachable, keep it: a reload once the
      // backend is back restores the session.
      const rejected =
        error instanceof HttpErrorResponse && (error.status === 401 || error.status === 403);
      if (rejected) {
        this.clearSession();
      } else {
        this.accessTokenState.set(null);
        this.userState.set(null);
      }
    }
  }

  clearSession(): void {
    this.accessTokenState.set(null);
    this.userState.set(null);
    this.storage.clear();
  }

  private loadCurrentUser(): Observable<User> {
    return this.http
      .get<User>(`${this.baseUrl}/auth/me`)
      .pipe(tap((user) => this.userState.set(user)));
  }

  private storeTokens(tokens: TokenPair): void {
    this.accessTokenState.set(tokens.access_token);
    this.storage.setRefreshToken(tokens.refresh_token);
  }
}
