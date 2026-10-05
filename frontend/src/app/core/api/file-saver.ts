import { DOCUMENT } from '@angular/common';
import { Injectable, inject } from '@angular/core';

/**
 * Hands a file the app has just fetched to the browser's download manager.
 *
 * Downloads go through an authenticated `HttpClient` request rather than a
 * plain link, because the API authenticates with a header the browser does
 * not send on its own when following a link. The response therefore arrives
 * as an in-memory `Blob`, saved here through a temporary object URL.
 */
@Injectable({ providedIn: 'root' })
export class FileSaver {
  private readonly document = inject(DOCUMENT);

  save(content: Blob, filename: string): void {
    const url = URL.createObjectURL(content);
    const link = this.document.createElement('a');
    link.href = url;
    link.download = filename;
    link.style.display = 'none';
    this.document.body.appendChild(link);
    link.click();
    link.remove();
    // Released on the next tick: the click above only *starts* the download.
    setTimeout(() => URL.revokeObjectURL(url));
  }
}
