import { DEFAULT_SIGNED_IN_URL, safeReturnUrl } from './return-url';

describe('safeReturnUrl', () => {
  it.each(['/scans', '/scans/42/report?tab=findings', '/dashboard#top'])(
    'keeps the in-app path %s',
    (url) => {
      expect(safeReturnUrl(url)).toBe(url);
    },
  );

  it.each([
    ['nothing', null],
    ['an empty value', ''],
    ['an absolute URL', 'https://evil.example/login'],
    ['a protocol-relative URL', '//evil.example'],
    ['a backslash variant', '/\\evil.example'],
    ['a javascript: URL', 'javascript:alert(1)'],
    ['a relative path', 'scans'],
    ['the login page itself', '/login'],
    ['the register page', '/register?returnUrl=/scans'],
  ])('falls back to the default for %s', (_label, url) => {
    expect(safeReturnUrl(url)).toBe(DEFAULT_SIGNED_IN_URL);
  });
});
