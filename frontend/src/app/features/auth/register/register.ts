import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import {
  AbstractControl,
  FormBuilder,
  ReactiveFormsModule,
  ValidationErrors,
  Validators,
} from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';

import { describeHttpError } from '../../../core/api/api-error';
import { AuthService } from '../../../core/auth/auth-service';
import { safeReturnUrl } from '../../../core/auth/return-url';
import { Brand } from '../../../shared/brand/brand';

/** Same bounds as the backend's `RegisterRequest`, so the form rejects what the API would. */
const PASSWORD_MIN_LENGTH = 8;
const PASSWORD_MAX_LENGTH = 128;
const FULL_NAME_MAX_LENGTH = 255;

function passwordsMatch(group: AbstractControl): ValidationErrors | null {
  const password: unknown = group.get('password')?.value;
  const confirmation: unknown = group.get('passwordConfirmation')?.value;
  return password === confirmation ? null : { passwordMismatch: true };
}

@Component({
  selector: 'app-register',
  imports: [ReactiveFormsModule, RouterLink, Brand],
  templateUrl: './register.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class Register {
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);

  protected readonly passwordMinLength = PASSWORD_MIN_LENGTH;

  protected readonly form = inject(FormBuilder).nonNullable.group(
    {
      fullName: ['', Validators.maxLength(FULL_NAME_MAX_LENGTH)],
      email: ['', [Validators.required, Validators.email]],
      password: [
        '',
        [
          Validators.required,
          Validators.minLength(PASSWORD_MIN_LENGTH),
          Validators.maxLength(PASSWORD_MAX_LENGTH),
        ],
      ],
      passwordConfirmation: ['', Validators.required],
    },
    { validators: passwordsMatch },
  );
  protected readonly submitting = signal(false);
  protected readonly errorMessage = signal<string | null>(null);

  protected showError(control: 'fullName' | 'email' | 'password'): boolean {
    const field = this.form.controls[control];
    return field.invalid && field.touched;
  }

  protected showMismatch(): boolean {
    const confirmation = this.form.controls.passwordConfirmation;
    return confirmation.touched && (confirmation.invalid || this.form.hasError('passwordMismatch'));
  }

  protected submit(): void {
    if (this.submitting()) {
      return;
    }
    if (this.form.invalid) {
      this.form.markAllAsTouched();
      return;
    }

    const { fullName, email, password } = this.form.getRawValue();
    this.submitting.set(true);
    this.errorMessage.set(null);
    this.auth.register({ email, password, full_name: fullName.trim() || null }).subscribe({
      next: () => {
        const returnUrl = this.route.snapshot.queryParamMap.get('returnUrl');
        void this.router.navigateByUrl(safeReturnUrl(returnUrl));
      },
      error: (error: unknown) => {
        this.errorMessage.set(describeHttpError(error, 'Registration failed. Please try again.'));
        this.submitting.set(false);
      },
    });
  }
}
