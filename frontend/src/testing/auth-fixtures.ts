import { HttpTestingController } from '@angular/common/http/testing';

import { AuthService } from '../app/core/auth/auth-service';
import { TokenPair, User } from '../app/core/auth/auth.models';

/** Shared by the specs only - nothing here is imported by application code. */

export const TEST_API_URL = 'http://api.test/api/v1';

export function makeUser(overrides: Partial<User> = {}): User {
  return {
    id: '6f1c1d2e-0000-4000-8000-000000000001',
    email: 'ada@example.com',
    full_name: 'Ada Lovelace',
    is_active: true,
    is_superuser: false,
    created_at: '2026-09-29T10:00:00Z',
    ...overrides,
  };
}

export function makeTokens(suffix = '1'): TokenPair {
  return {
    access_token: `access-${suffix}`,
    refresh_token: `refresh-${suffix}`,
    token_type: 'bearer',
  };
}

/** Signs in through the real `AuthService`, answering its two HTTP calls. */
export function signIn(
  auth: AuthService,
  http: HttpTestingController,
  user: User = makeUser(),
  tokens: TokenPair = makeTokens(),
): void {
  auth.login({ email: user.email, password: 'correct-horse-battery' }).subscribe();
  http.expectOne(`${TEST_API_URL}/auth/login`).flush(tokens);
  http.expectOne(`${TEST_API_URL}/auth/me`).flush(user);
}
