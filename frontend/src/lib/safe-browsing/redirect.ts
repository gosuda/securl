export type ScanState = 'scanning' | 'clean' | 'threat' | 'error';

export class RedirectCoordinator {
  #abortController = new AbortController();
  #started = false;
  #redirected = false;

  constructor(
    private readonly scan: (signal: AbortSignal) => Promise<'clean' | 'threat'>,
    private readonly redirect: () => void,
    private readonly update: (scanState: ScanState) => void
  ) {}

  /** Starts the safety scan once and redirects only when it reports a clean destination. */
  start(): void {
    if (this.#started || this.#abortController.signal.aborted) return;
    this.#started = true;
    this.update('scanning');
    this.scan(this.#abortController.signal).then(
      (result) => {
        if (this.#abortController.signal.aborted) return;
        this.update(result);
        if (result === 'clean') this.#redirectOnce();
      },
      () => {
        if (this.#abortController.signal.aborted) return;
        this.update('error');
      }
    );
  }

  /** Explicit user choice after the safety check could not complete. */
  openWithoutSafetyCheck(): void {
    this.cancel();
    this.#redirectOnce();
  }

  cancel(): void {
    this.#abortController.abort();
  }

  #redirectOnce(): void {
    if (this.#redirected) return;
    this.#redirected = true;
    this.redirect();
  }
}
