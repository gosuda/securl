export type ScanState = 'scanning' | 'clean' | 'threat' | 'error';

export interface RedirectSnapshot {
  remainingSeconds: number;
  countdownDone: boolean;
  scanState: ScanState;
}

export class RedirectCoordinator {
  #abortController = new AbortController();
  #countdownTimer: ReturnType<typeof setInterval> | undefined;
  #completionTimer: ReturnType<typeof setTimeout> | undefined;
  #redirected = false;
  #snapshot: RedirectSnapshot = {
    remainingSeconds: 5,
    countdownDone: false,
    scanState: 'scanning'
  };

  constructor(
    private readonly scan: (signal: AbortSignal) => Promise<'clean' | 'threat'>,
    private readonly redirect: () => void,
    private readonly update: (snapshot: RedirectSnapshot) => void
  ) {}

  start(): void {
    const deadline = Date.now() + 5000;
    this.#countdownTimer = setInterval(() => {
      this.#snapshot.remainingSeconds = Math.max(0, Math.ceil((deadline - Date.now()) / 1000));
      this.#emit();
    }, 100);
    this.#completionTimer = setTimeout(() => this.openAfterSafetyCheck(), 5000);
    this.scan(this.#abortController.signal).then(
      (result) => {
        if (this.#abortController.signal.aborted) return;
        this.#snapshot.scanState = result;
        if (result === 'threat') {
          this.cancel();
          this.#emit();
          return;
        }
        this.#emit();
        this.#maybeRedirect();
      },
      () => {
        if (this.#abortController.signal.aborted) return;
        this.#snapshot.scanState = 'error';
        this.cancel();
        this.#emit();
      }
    );
    this.#emit();
  }

  openAfterSafetyCheck(): void {
    if (!this.#snapshot.countdownDone) {
      clearInterval(this.#countdownTimer);
      clearTimeout(this.#completionTimer);
      this.#countdownTimer = undefined;
      this.#completionTimer = undefined;
      this.#snapshot.remainingSeconds = 0;
      this.#snapshot.countdownDone = true;
      this.#emit();
    }
    this.#maybeRedirect();
  }

  openWithoutSafetyCheck(): void {
    this.cancel();
    this.#redirectOnce();
  }

  cancel(): void {
    this.#abortController.abort();
    clearInterval(this.#countdownTimer);
    clearTimeout(this.#completionTimer);
    this.#countdownTimer = undefined;
    this.#completionTimer = undefined;
  }

  #maybeRedirect(): void {
    if (this.#snapshot.countdownDone && this.#snapshot.scanState === 'clean') {
      this.cancel();
      this.#redirectOnce();
    }
  }

  #redirectOnce(): void {
    if (this.#redirected) return;
    this.#redirected = true;
    this.redirect();
  }

  #emit(): void {
    this.update({ ...this.#snapshot });
  }
}
