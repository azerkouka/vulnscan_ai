import { TestBed } from '@angular/core/testing';

import { FileSaver } from './file-saver';

describe('FileSaver', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it('downloads the content under the given name, then releases it', () => {
    vi.useFakeTimers();
    // jsdom implements neither of these.
    const createObjectURL = vi.fn(() => 'blob:report-1');
    const revokeObjectURL = vi.fn();
    Object.assign(URL, { createObjectURL, revokeObjectURL });
    const clicked: { href: string; download: string }[] = [];
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (
      this: HTMLAnchorElement,
    ) {
      clicked.push({ href: this.href, download: this.download });
    });
    const content = new Blob(['{}'], { type: 'application/json' });

    TestBed.inject(FileSaver).save(content, 'vulnscan-report-abc.json');

    expect(createObjectURL).toHaveBeenCalledWith(content);
    expect(clicked).toEqual([{ href: 'blob:report-1', download: 'vulnscan-report-abc.json' }]);
    // The temporary link does not linger in the page.
    expect(document.querySelector('a[download]')).toBeNull();
    expect(revokeObjectURL).not.toHaveBeenCalled();
    vi.runAllTimers();
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:report-1');
  });
});
