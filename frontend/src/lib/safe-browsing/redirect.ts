export type ScanState = 'scanning' | 'clean' | 'threat' | 'error';

const DEFAULT_DELAY_MS = 5000;
const SCAN_LEAD_TIME_MS = 1000;

export interface RedirectSnapshot {
  remainingSeconds: number;
  countdownDone: boolean;
  scanState: ScanState;
}

export class RedirectCoordinator {
  #abortController = new AbortController();
  #countdownTimer: ReturnType<typeof setInterval> | undefined;
  #completionTimer: ReturnType<typeof setTimeout> | undefined;
  #scanTimer: ReturnType<typeof setTimeout> | undefined;
  #scanStarted = false;
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

  start(deadline: number = Date.now() + DEFAULT_DELAY_MS): void {
    const remainingMilliseconds = Math.max(0, deadline - Date.now());
    this.#snapshot.remainingSeconds = Math.ceil(remainingMilliseconds / 1000);
    if (remainingMilliseconds === 0) {
      this.#snapshot.countdownDone = true;
    } else {
      this.#countdownTimer = setInterval(() => {
        this.#snapshot.remainingSeconds = Math.max(
          0,
          Math.ceil((deadline - Date.now()) / 1000)
        );
        this.#emit();
      }, 100);
      this.#completionTimer = setTimeout(
        () => this.openAfterSafetyCheck(),
        remainingMilliseconds
      );
      const scanDelay = Math.max(0, remainingMilliseconds - SCAN_LEAD_TIME_MS);
      if (scanDelay === 0) this.#startScan();
      else this.#scanTimer = setTimeout(() => this.#startScan(), scanDelay);
    }
    if (remainingMilliseconds === 0) this.#startScan();
    this.#emit();
  }

  openAfterSafetyCheck(): void {
    this.#startScan();
    if (!this.#snapshot.countdownDone) {
      clearInterval(this.#countdownTimer);
      clearTimeout(this.#completionTimer);
      this.#countdownTimer = undefined;
      this.#completionTimer = undefined;
      this.#snapshot.remainingSeconds = 0;
      this.#snapshot.countdownDone = true;
      this.#emit();
    }
    return;
  }

  openWithoutSafetyCheck(): void {
    this.cancel();
    this.#redirectOnce();
  }

  cancel(): void {
    this.#abortController.abort();
    clearInterval(this.#countdownTimer);
    clearTimeout(this.#completionTimer);
    clearTimeout(this.#scanTimer);
    this.#countdownTimer = undefined;
    this.#completionTimer = undefined;
    this.#scanTimer = undefined;
  }

  #startScan(): void {
    if (this.#scanStarted || this.#abortController.signal.aborted) return;
    this.#scanStarted = true;
    clearTimeout(this.#scanTimer);
    this.#scanTimer = undefined;
    this.scan(this.#abortController.signal).then(
      (result) => {
        if (this.#abortController.signal.aborted) return;
        this.#snapshot.scanState = result;
        this.cancel();
        this.#emit();
        if (result === 'clean') this.#redirectOnce();
      },
      () => {
        if (this.#abortController.signal.aborted) return;
        this.#snapshot.scanState = 'error';
        this.cancel();
        this.#emit();
      }
    );
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
