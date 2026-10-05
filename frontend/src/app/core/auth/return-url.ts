export const DEFAULT_SIGNED_IN_URL = '/dashboard';

/** Pages meant for visitors who are not signed in. */
export const SIGNED_OUT_PAGES = ['/login', '/register'];

/**
 * Query parameters for a redirect to the login page from `url`: the page to
 * come back to, unless that is simply where signing in leads anyway.
 */
export function loginQueryParams(url: string): { returnUrl?: string } {
  return url === '/' || url === DEFAULT_SIGNED_IN_URL ? {} : { returnUrl: url };
}

/**
 * Where to send the user after signing in, given the `returnUrl` query
 * parameter of the login page.
 *
 * That parameter comes from the address bar, so anyone can craft a link
 * with any value in it. Only a path inside this app is honoured: it must
 * start with a single "/" ("//host" and "/\host" are how a browser is made
 * to read a path as another site). Anything else falls back to the default.
 */
export function safeReturnUrl(candidate: string | null | undefined): string {
  if (!candidate || !candidate.startsWith('/')) {
    return DEFAULT_SIGNED_IN_URL;
  }
  if (candidate.startsWith('//') || candidate.startsWith('/\\')) {
    return DEFAULT_SIGNED_IN_URL;
  }
  if (SIGNED_OUT_PAGES.some((page) => candidate.startsWith(page))) {
    return DEFAULT_SIGNED_IN_URL; // would bounce straight back off the guest guard
  }
  return candidate;
}
