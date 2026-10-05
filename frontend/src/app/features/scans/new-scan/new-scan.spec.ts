import { HttpErrorResponse } from '@angular/common/http';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { Router, provideRouter } from '@angular/router';
import { Observable, Subject, of, throwError } from 'rxjs';

import { makeScan } from '../../../../testing/scan-fixtures';
import { ScanService } from '../../../core/scans/scan-service';
import { Scan, ScanSubmission } from '../../../core/scans/scan.models';
import { NewScan } from './new-scan';

describe('NewScan', () => {
  let create: ReturnType<typeof vi.fn<(submission: ScanSubmission) => Observable<Scan>>>;
  let fixture: ComponentFixture<NewScan>;
  let page: HTMLElement;
  let navigate: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    create = vi.fn<(submission: ScanSubmission) => Observable<Scan>>(() =>
      of(makeScan({ id: 'new-scan-id', status: 'PENDING' })),
    );
    TestBed.configureTestingModule({
      providers: [provideRouter([]), { provide: ScanService, useValue: { create } }],
    });
    navigate = vi.spyOn(TestBed.inject(Router), 'navigate').mockResolvedValue(true);
    fixture = TestBed.createComponent(NewScan);
    fixture.detectChanges();
    page = fixture.nativeElement as HTMLElement;
  });

  afterEach(() => vi.restoreAllMocks());

  function setValue(selector: string, value: string, event = 'input'): void {
    const element = page.querySelector<HTMLTextAreaElement | HTMLSelectElement>(selector);
    if (element === null) {
      throw new Error(`Nothing matches ${selector}`);
    }
    element.value = value;
    element.dispatchEvent(new Event(event));
  }

  function chooseFile(file: File | null): void {
    const input = page.querySelector<HTMLInputElement>('#scan-file');
    if (input === null) {
      throw new Error('The file input is not shown');
    }
    Object.defineProperty(input, 'files', {
      value: file === null ? [] : [file],
      configurable: true,
    });
    input.dispatchEvent(new Event('change'));
    fixture.detectChanges();
  }

  function clickTab(id: string): void {
    page.querySelector<HTMLButtonElement>(`#${id}`)?.click();
    fixture.detectChanges();
  }

  function submit(): void {
    page.querySelector('form')?.dispatchEvent(new Event('submit'));
    fixture.detectChanges();
  }

  const inputError = (): string | null =>
    page.querySelector('#scan-input-error')?.textContent?.trim() ?? null;

  it('submits pasted code with its language and opens the new scan', () => {
    setValue('#scan-code', 'import os\nos.system(cmd)\n');
    setValue('#scan-language', 'python', 'change');

    submit();

    expect(create).toHaveBeenCalledWith({
      code: 'import os\nos.system(cmd)\n',
      language: 'python',
    });
    expect(navigate).toHaveBeenCalledWith(['/scans', 'new-scan-id']);
  });

  it('sends no language when none is chosen', () => {
    setValue('#scan-code', 'x = 1');

    submit();

    expect(create).toHaveBeenCalledWith({ code: 'x = 1', language: null });
  });

  it('offers every language the backend can chunk', () => {
    const options = [...page.querySelectorAll<HTMLOptionElement>('#scan-language option')].map(
      (option) => option.value,
    );

    expect(options).toEqual([
      '',
      'python',
      'javascript',
      'typescript',
      'tsx',
      'java',
      'go',
      'php',
      'csharp',
      'ruby',
    ]);
  });

  it('asks for code instead of submitting nothing', () => {
    setValue('#scan-code', '   \n  ');

    submit();

    expect(create).not.toHaveBeenCalled();
    expect(inputError()).toBe('Paste the code you want to scan.');
    expect(page.querySelector('#scan-code')?.getAttribute('aria-invalid')).toBe('true');
  });

  it('drops the complaint as soon as the user starts typing code', () => {
    submit();
    expect(inputError()).not.toBeNull();

    setValue('#scan-code', 'x = 1');
    fixture.detectChanges();

    expect(inputError()).toBeNull();
    expect(page.querySelector('#scan-code')?.getAttribute('aria-invalid')).toBe('false');
  });

  it('submits an uploaded file', () => {
    const file = new File(['print(1)'], 'views.py');
    clickTab('tab-file');
    chooseFile(file);

    submit();

    expect(create).toHaveBeenCalledWith({ file });
    expect(navigate).toHaveBeenCalledWith(['/scans', 'new-scan-id']);
  });

  it('refuses an unsupported file as soon as it is chosen', () => {
    clickTab('tab-file');
    chooseFile(new File(['MZ'], 'tool.exe'));

    expect(inputError()).toContain('not supported');
    submit();
    expect(create).not.toHaveBeenCalled();
  });

  it('asks for a file when none was chosen', () => {
    clickTab('tab-file');

    submit();

    expect(create).not.toHaveBeenCalled();
    expect(inputError()).toBe('Choose a file to scan.');
  });

  it('does not carry an error over when switching between tabs', () => {
    submit();
    expect(inputError()).not.toBeNull();

    clickTab('tab-file');

    expect(inputError()).toBeNull();
    expect(page.querySelector('#tab-file')?.getAttribute('aria-selected')).toBe('true');
    expect(page.querySelector('#tab-code')?.getAttribute('aria-selected')).toBe('false');
  });

  it('shows why the backend refused the submission and lets the user retry', () => {
    create.mockReturnValue(
      throwError(
        () =>
          new HttpErrorResponse({
            status: 422,
            error: {
              error: {
                code: 'InvalidArchive',
                message: 'The archive contains a path traversal entry and was rejected.',
              },
            },
          }),
      ),
    );
    clickTab('tab-file');
    chooseFile(new File(['PK'], 'project.zip'));

    submit();

    expect(page.querySelector('.alert-error')?.textContent).toContain('path traversal');
    expect(navigate).not.toHaveBeenCalled();
    expect(page.querySelector<HTMLButtonElement>('button[type="submit"]')?.disabled).toBe(false);
  });

  it('blocks a second submission while the first is being sent', () => {
    create.mockReturnValue(new Subject<Scan>());
    setValue('#scan-code', 'x = 1');

    submit();
    submit();

    expect(create).toHaveBeenCalledTimes(1);
    const button = page.querySelector<HTMLButtonElement>('button[type="submit"]');
    expect(button?.disabled).toBe(true);
    expect(button?.textContent).toContain('Starting');
  });
});
