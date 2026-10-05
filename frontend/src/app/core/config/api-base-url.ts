import { InjectionToken } from '@angular/core';

import { environment } from '../../../environments/environment';

/** Root of the backend REST API, without a trailing slash (e.g. `/api/v1`). */
export const API_BASE_URL = new InjectionToken<string>('API_BASE_URL', {
  providedIn: 'root',
  factory: () => environment.apiBaseUrl,
});
