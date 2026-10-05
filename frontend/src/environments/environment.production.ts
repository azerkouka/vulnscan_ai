/**
 * Production settings: same-origin. nginx serves the bundle and proxies
 * `/api/` to the backend (see nginx.conf), so no CORS is involved and the
 * bundle doesn't have to know where the backend is deployed.
 */
export const environment = {
  apiBaseUrl: '/api/v1',
};
