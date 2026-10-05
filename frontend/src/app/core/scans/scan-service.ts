import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable, catchError, from, switchMap, throwError } from 'rxjs';

import { API_BASE_URL } from '../config/api-base-url';
import {
  DashboardSummary,
  ReportFormat,
  Scan,
  ScanList,
  ScanReport,
  ScanSubmission,
} from './scan.models';

/** Thin client for the `/scans` and `/dashboard` endpoints - no state of its own. */
@Injectable({ providedIn: 'root' })
export class ScanService {
  private readonly http = inject(HttpClient);
  private readonly baseUrl = inject(API_BASE_URL);

  /** Submits code for analysis. Resolves as soon as the scan is queued, not when it is done. */
  create(submission: ScanSubmission): Observable<Scan> {
    // multipart/form-data, as the endpoint expects. The Content-Type header
    // (with its boundary) is left for the browser to set.
    const form = new FormData();
    if ('file' in submission) {
      form.append('file', submission.file, submission.file.name);
    } else {
      form.append('code', submission.code);
      if (submission.language) {
        form.append('language', submission.language);
      }
    }
    return this.http.post<Scan>(`${this.baseUrl}/scans`, form);
  }

  list(limit: number, offset: number): Observable<ScanList> {
    return this.http.get<ScanList>(`${this.baseUrl}/scans`, { params: { limit, offset } });
  }

  getReport(scanId: string): Observable<ScanReport> {
    return this.http.get<ScanReport>(`${this.baseUrl}/scans/${encodeURIComponent(scanId)}/report`);
  }

  /** The report of a finished scan, as a file. */
  downloadReport(scanId: string, format: ReportFormat): Observable<Blob> {
    return this.http
      .get(`${this.baseUrl}/scans/${encodeURIComponent(scanId)}/export`, {
        params: { format },
        responseType: 'blob',
      })
      .pipe(
        catchError((error: unknown) =>
          from(withParsedBody(error)).pipe(switchMap((parsed) => throwError(() => parsed))),
        ),
      );
  }

  delete(scanId: string): Observable<void> {
    return this.http.delete<void>(`${this.baseUrl}/scans/${encodeURIComponent(scanId)}`);
  }

  dashboardSummary(): Observable<DashboardSummary> {
    return this.http.get<DashboardSummary>(`${this.baseUrl}/dashboard/summary`);
  }
}

/**
 * A request made with `responseType: 'blob'` gets its *error* body as a Blob
 * too, even though the backend answered JSON. This turns it back into the
 * parsed JSON every other failed request carries, so the backend's message
 * can be shown as usual.
 */
async function withParsedBody(error: unknown): Promise<unknown> {
  if (!(error instanceof HttpErrorResponse) || !(error.error instanceof Blob)) {
    return error;
  }
  try {
    const body: unknown = JSON.parse(await error.error.text());
    return new HttpErrorResponse({
      error: body,
      headers: error.headers,
      status: error.status,
      statusText: error.statusText,
      url: error.url ?? undefined,
    });
  } catch {
    return error; // not JSON after all: keep the original
  }
}
