/**
 * Development settings (`ng serve`): the browser calls the backend directly
 * on its own port - the backend's CORS_ORIGINS allows http://localhost:4200.
 *
 * Replaced by `environment.production.ts` in production builds (see
 * `fileReplacements` in angular.json).
 */
export const environment = {
  apiBaseUrl: 'http://localhost:8000/api/v1',
};
