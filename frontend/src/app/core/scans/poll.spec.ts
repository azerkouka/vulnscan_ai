import { Observable, of, throwError } from 'rxjs';

import { pollWhile } from './poll';

describe('pollWhile', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  /** A loader answering with each given value in turn. */
  function scripted<T>(...values: T[]): { load: () => Observable<T>; calls: () => number } {
    let calls = 0;
    return {
      load: () => of(values[Math.min(calls++, values.length - 1)]),
      calls: () => calls,
    };
  }

  it('loads once when the first result is already final', () => {
    const source = scripted('done');
    const received: string[] = [];
    let completed = false;

    pollWhile(source.load, (value) => value !== 'done', 1000).subscribe({
      next: (value) => received.push(value),
      complete: () => (completed = true),
    });
    vi.advanceTimersByTime(10_000);

    expect(received).toEqual(['done']);
    expect(source.calls()).toBe(1);
    expect(completed).toBe(true);
  });

  it('reloads at the given interval until the result is final', () => {
    const source = scripted('pending', 'running', 'done');
    const received: string[] = [];

    pollWhile(source.load, (value) => value !== 'done', 1000).subscribe((value) =>
      received.push(value),
    );

    expect(received).toEqual(['pending']);
    vi.advanceTimersByTime(999);
    expect(received).toEqual(['pending']);
    vi.advanceTimersByTime(1);
    expect(received).toEqual(['pending', 'running']);
    vi.advanceTimersByTime(1000);
    expect(received).toEqual(['pending', 'running', 'done']);

    vi.advanceTimersByTime(10_000);
    expect(source.calls()).toBe(3);
  });

  it('stops reloading when unsubscribed', () => {
    const source = scripted('pending');

    const subscription = pollWhile(source.load, () => true, 1000).subscribe();
    vi.advanceTimersByTime(2000);
    expect(source.calls()).toBe(3);

    subscription.unsubscribe();
    vi.advanceTimersByTime(10_000);
    expect(source.calls()).toBe(3);
  });

  it('passes an error on and stops', () => {
    let calls = 0;
    const load = (): Observable<string> =>
      ++calls === 1 ? of('pending') : throwError(() => new Error('backend down'));
    let failure: unknown;

    pollWhile(load, () => true, 1000).subscribe({ error: (error: unknown) => (failure = error) });
    vi.advanceTimersByTime(5000);

    expect((failure as Error).message).toBe('backend down');
    expect(calls).toBe(2);
  });
});
