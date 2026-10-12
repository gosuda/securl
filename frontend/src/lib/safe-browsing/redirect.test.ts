import { describe, expect, it, vi } from 'vitest';
import { RedirectCoordinator, type ScanState } from './redirect';

describe('redirect safety coordination', () => {
  it('scans immediately and redirects as soon as the scan is clean', async () => {
    const scanResult = Promise.withResolvers<'clean' | 'threat'>();
    const scan = vi.fn(() => scanResult.promise);
    const redirect = vi.fn();
    const coordinator = new RedirectCoordinator(scan, redirect, () => {});
    coordinator.start();

    expect(scan).toHaveBeenCalledOnce();
    expect(redirect).not.toHaveBeenCalled();
    scanResult.resolve('clean');
    await Promise.resolve();
    expect(redirect).toHaveBeenCalledOnce();
  });

  it('never auto-redirects threats or scan failures', async () => {
    const threatRedirect = vi.fn();
    const threatStates: ScanState[] = [];
    new RedirectCoordinator(async () => 'threat', threatRedirect, (state) =>
      threatStates.push(state)
    ).start();
    await Promise.resolve();
    expect(threatRedirect).not.toHaveBeenCalled();
    expect(threatStates.at(-1)).toBe('threat');

    const errorRedirect = vi.fn();
    const errorStates: ScanState[] = [];
    new RedirectCoordinator(
      async () => {
        throw new Error('unavailable');
      },
      errorRedirect,
      (state) => errorStates.push(state)
    ).start();
    await Promise.resolve();
    await Promise.resolve();
    expect(errorRedirect).not.toHaveBeenCalled();
    expect(errorStates.at(-1)).toBe('error');
  });

  it('opens once on explicit choice and ignores a later clean result', async () => {
    const scanResult = Promise.withResolvers<'clean' | 'threat'>();
    const redirect = vi.fn();
    const coordinator = new RedirectCoordinator(() => scanResult.promise, redirect, () => {});
    coordinator.start();
    coordinator.openWithoutSafetyCheck();
    expect(redirect).toHaveBeenCalledOnce();

    scanResult.resolve('clean');
    await Promise.resolve();
    expect(redirect).toHaveBeenCalledOnce();
  });

  it('does not redirect after cancellation', async () => {
    const scanResult = Promise.withResolvers<'clean' | 'threat'>();
    const redirect = vi.fn();
    const coordinator = new RedirectCoordinator(() => scanResult.promise, redirect, () => {});
    coordinator.start();
    coordinator.cancel();
    scanResult.resolve('clean');
    await Promise.resolve();
    expect(redirect).not.toHaveBeenCalled();
  });
});
