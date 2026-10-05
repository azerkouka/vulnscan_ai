import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';

import { TEST_API_URL } from '../../../testing/auth-fixtures';
import { makeReport, makeScan, makeScanList, makeSummary } from '../../../testing/scan-fixtures';
import { API_BASE_URL } from '../config/api-base-url';
import { MAX_UPLOAD_BYTES, uploadProblem } from './scan-limits';
import { ScanService } from './scan-service';
import { isInProgress } from './scan.models';

describe('ScanService', () => {
  let scans: ScanService;
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: API_BASE_URL, useValue: TEST_API_URL },
      ],
    });
    scans = TestBed.inject(ScanService);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  it('submits a snippet as multipart form fields', () => {
    const created = makeScan({ status: 'PENDING' });
    let result: unknown;

    scans.create({ code: 'print(1)', language: 'python' }).subscribe((scan) => (result = scan));

    const request = http.expectOne(`${TEST_API_URL}/scans`);
    expect(request.request.method).toBe('POST');
    const body = request.request.body as FormData;
    expect(body).toBeInstanceOf(FormData);
    expect(body.get('code')).toBe('print(1)');
    expect(body.get('language')).toBe('python');
    expect(body.has('file')).toBe(false);
    // Left unset so the browser adds the multipart boundary itself.
    expect(request.request.headers.has('Content-Type')).toBe(false);
    request.flush(created, { status: 202, statusText: 'Accepted' });
    expect(result).toEqual(created);
  });

  it('omits the language field when none was chosen', () => {
    scans.create({ code: 'x = 1', language: null }).subscribe();

    const request = http.expectOne(`${TEST_API_URL}/scans`);
    expect((request.request.body as FormData).has('language')).toBe(false);
    request.flush(makeScan());
  });

  it('submits an uploaded file under its own name', () => {
    const file = new File(['print(1)'], 'views.py', { type: 'text/x-python' });

    scans.create({ file }).subscribe();

    const request = http.expectOne(`${TEST_API_URL}/scans`);
    const body = request.request.body as FormData;
    const sent = body.get('file') as File;
    expect(sent.name).toBe('views.py');
    expect(body.has('code')).toBe(false);
    request.flush(makeScan({ source_type: 'FILE' }));
  });

  it('lists scans with pagination parameters', () => {
    const page = makeScanList([makeScan()]);
    let result: unknown;

    scans.list(10, 20).subscribe((list) => (result = list));

    const request = http.expectOne((r) => r.url === `${TEST_API_URL}/scans`);
    expect(request.request.params.get('limit')).toBe('10');
    expect(request.request.params.get('offset')).toBe('20');
    request.flush(page);
    expect(result).toEqual(page);
  });

  it('loads a report, deletes a scan and loads the dashboard summary', () => {
    scans.getReport('abc').subscribe();
    http.expectOne(`${TEST_API_URL}/scans/abc/report`).flush(makeReport());

    scans.delete('abc').subscribe();
    const deletion = http.expectOne(`${TEST_API_URL}/scans/abc`);
    expect(deletion.request.method).toBe('DELETE');
    deletion.flush(null, { status: 204, statusText: 'No Content' });

    scans.dashboardSummary().subscribe();
    http.expectOne(`${TEST_API_URL}/dashboard/summary`).flush(makeSummary());
  });

  it('keeps a scan id from altering the request path', () => {
    scans.getReport('../../auth/me?x=').subscribe();

    http.expectOne(`${TEST_API_URL}/scans/..%2F..%2Fauth%2Fme%3Fx%3D/report`).flush(makeReport());
  });
});

describe('scan helpers', () => {
  it('treats queued and running scans as in progress', () => {
    expect(isInProgress('PENDING')).toBe(true);
    expect(isInProgress('RUNNING')).toBe(true);
    expect(isInProgress('COMPLETED')).toBe(false);
    expect(isInProgress('FAILED')).toBe(false);
  });

  function fileOfSize(name: string, size: number): File {
    const file = new File(['x'], name);
    Object.defineProperty(file, 'size', { value: size });
    return file;
  }

  it.each(['app.py', 'Main.JAVA', 'ui/App.tsx', 'project.zip'])('accepts %s', (name) => {
    expect(uploadProblem(fileOfSize(name, 1024))).toBeNull();
  });

  it.each(['tool.exe', 'notes.txt', 'archive.tar.gz', 'Makefile'])(
    'refuses the unsupported type of %s',
    (name) => {
      expect(uploadProblem(fileOfSize(name, 1024))).toContain('not supported');
    },
  );

  it('refuses an empty file', () => {
    expect(uploadProblem(fileOfSize('app.py', 0))).toBe('This file is empty.');
  });

  it('refuses a file over the size limit, and accepts one exactly at it', () => {
    expect(uploadProblem(fileOfSize('app.py', MAX_UPLOAD_BYTES))).toBeNull();
    expect(uploadProblem(fileOfSize('app.py', MAX_UPLOAD_BYTES + 1))).toContain('10 MB limit');
  });
});
