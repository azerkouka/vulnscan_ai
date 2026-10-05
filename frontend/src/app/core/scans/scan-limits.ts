/**
 * What the upload form accepts, mirroring the backend defaults
 * (`ALLOWED_UPLOAD_EXTENSIONS`, `UPLOAD_MAX_SIZE_MB`, supported languages).
 *
 * These checks only spare the user a round trip - the backend validates
 * every submission itself and is the one that decides. If its settings are
 * changed, a file refused there is still reported, with the backend's own
 * message.
 */

export const MAX_UPLOAD_MB = 10;
export const MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024;

export const SOURCE_EXTENSIONS: readonly string[] = [
  '.py',
  '.js',
  '.jsx',
  '.ts',
  '.tsx',
  '.java',
  '.go',
  '.php',
  '.cs',
  '.rb',
];
export const ARCHIVE_EXTENSION = '.zip';
export const UPLOAD_EXTENSIONS: readonly string[] = [...SOURCE_EXTENSIONS, ARCHIVE_EXTENSION];

export interface LanguageOption {
  /** The id the backend expects in the `language` form field. */
  value: string;
  label: string;
}

export const SNIPPET_LANGUAGES: readonly LanguageOption[] = [
  { value: 'python', label: 'Python' },
  { value: 'javascript', label: 'JavaScript' },
  { value: 'typescript', label: 'TypeScript' },
  { value: 'tsx', label: 'TypeScript (TSX)' },
  { value: 'java', label: 'Java' },
  { value: 'go', label: 'Go' },
  { value: 'php', label: 'PHP' },
  { value: 'csharp', label: 'C#' },
  { value: 'ruby', label: 'Ruby' },
];

/** Why `file` can't be uploaded, or null if it looks acceptable. */
export function uploadProblem(file: File): string | null {
  const dot = file.name.lastIndexOf('.');
  const extension = dot === -1 ? '' : file.name.slice(dot).toLowerCase();
  if (!UPLOAD_EXTENSIONS.includes(extension)) {
    return `This file type is not supported. Accepted: ${UPLOAD_EXTENSIONS.join(', ')}.`;
  }
  if (file.size === 0) {
    return 'This file is empty.';
  }
  if (file.size > MAX_UPLOAD_BYTES) {
    return `This file is larger than the ${MAX_UPLOAD_MB} MB limit.`;
  }
  return null;
}
