/** Mirrors the backend's `UserResponse` (snake_case, as sent on the wire). */
export interface User {
  id: string;
  email: string;
  full_name: string | null;
  is_active: boolean;
  is_superuser: boolean;
  created_at: string;
}

/** Mirrors the backend's `TokenResponse`. */
export interface TokenPair {
  access_token: string;
  refresh_token: string;
  token_type: string;
}

export interface Credentials {
  email: string;
  password: string;
}

export interface Registration extends Credentials {
  full_name: string | null;
}
