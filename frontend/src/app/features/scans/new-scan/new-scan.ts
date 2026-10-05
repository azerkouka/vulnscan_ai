import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormBuilder, ReactiveFormsModule } from '@angular/forms';
import { Router } from '@angular/router';

import { describeHttpError } from '../../../core/api/api-error';
import {
  MAX_UPLOAD_MB,
  SNIPPET_LANGUAGES,
  UPLOAD_EXTENSIONS,
  uploadProblem,
} from '../../../core/scans/scan-limits';
import { ScanService } from '../../../core/scans/scan-service';
import { ScanSubmission } from '../../../core/scans/scan.models';

type Mode = 'code' | 'file';

/** Submit code for analysis: paste a snippet, or upload a source file or a project archive. */
@Component({
  selector: 'app-new-scan',
  imports: [ReactiveFormsModule],
  templateUrl: './new-scan.html',
  styleUrl: './new-scan.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class NewScan {
  private readonly scans = inject(ScanService);
  private readonly router = inject(Router);

  protected readonly languages = SNIPPET_LANGUAGES;
  protected readonly acceptedExtensions = UPLOAD_EXTENSIONS.join(',');
  protected readonly extensionList = UPLOAD_EXTENSIONS.join(', ');
  protected readonly maxUploadMb = MAX_UPLOAD_MB;

  protected readonly form = inject(FormBuilder).nonNullable.group({
    code: [''],
    language: [''],
  });

  protected readonly mode = signal<Mode>('code');
  protected readonly file = signal<File | null>(null);
  /** What is wrong with the current input; shown once the user has tried to submit or picked a file. */
  protected readonly inputError = signal<string | null>(null);
  protected readonly submitting = signal(false);
  protected readonly errorMessage = signal<string | null>(null);

  constructor() {
    // A complaint about the code is out of date as soon as the code is edited.
    this.form.controls.code.valueChanges
      .pipe(takeUntilDestroyed())
      .subscribe(() => this.inputError.set(null));
  }

  protected selectMode(mode: Mode): void {
    this.mode.set(mode);
    this.inputError.set(null);
    this.errorMessage.set(null);
  }

  protected onFileSelected(event: Event): void {
    const selected = (event.target as HTMLInputElement).files?.[0] ?? null;
    this.file.set(selected);
    this.inputError.set(selected === null ? null : uploadProblem(selected));
    this.errorMessage.set(null);
  }

  protected submit(): void {
    if (this.submitting()) {
      return;
    }
    const submission = this.buildSubmission();
    if (submission === null) {
      return;
    }

    this.submitting.set(true);
    this.errorMessage.set(null);
    this.scans.create(submission).subscribe({
      // Straight to the scan's page, which follows its progress.
      next: (scan) => void this.router.navigate(['/scans', scan.id]),
      error: (error: unknown) => {
        this.errorMessage.set(describeHttpError(error, 'The scan could not be started.'));
        this.submitting.set(false);
      },
    });
  }

  /** The submission for the current mode, or null (with `inputError` set) if it isn't valid. */
  private buildSubmission(): ScanSubmission | null {
    if (this.mode() === 'file') {
      const file = this.file();
      const problem = file === null ? 'Choose a file to scan.' : uploadProblem(file);
      this.inputError.set(problem);
      return file !== null && problem === null ? { file } : null;
    }

    const { code, language } = this.form.getRawValue();
    if (code.trim() === '') {
      this.inputError.set('Paste the code you want to scan.');
      return null;
    }
    this.inputError.set(null);
    return { code, language: language || null };
  }
}
