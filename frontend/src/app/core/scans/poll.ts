import { InjectionToken } from '@angular/core';
import { EMPTY, Observable, expand, switchMap, timer } from 'rxjs';

/**
 * How often, in milliseconds, a page re-reads a scan that is still being
 * analyzed. A token so that tests can make it short.
 */
export const POLL_INTERVAL = new InjectionToken<number>('POLL_INTERVAL', {
  providedIn: 'root',
  factory: () => 3000,
});

/**
 * Emits `load()`'s result, then keeps reloading for as long as
 * `shouldContinue` says the latest result is not final.
 *
 * The wait is counted from the arrival of each response, so a slow backend
 * is never sent overlapping requests. An error ends the polling and is
 * passed on to the subscriber.
 */
export function pollWhile<T>(
  load: () => Observable<T>,
  shouldContinue: (value: T) => boolean,
  intervalMs: number,
): Observable<T> {
  return load().pipe(
    expand((value) => (shouldContinue(value) ? timer(intervalMs).pipe(switchMap(load)) : EMPTY)),
  );
}
