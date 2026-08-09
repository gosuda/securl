import { afterEach, describe, expect, it, vi } from 'vitest';
import { RedirectCoordinator } from './redirect';

afterEach(() => vi.useRealTimers());

describe('redirect safety coordination', () => {
  it('starts scanning with one second remaining and redirects immediately when clean', async () => {
    vi.useFakeTimers();
    const scanResult = Promise.withResolvers<'clean' | 'threat'>();
    const scan = vi.fn(() => scanResult.promise);
    const redirect = vi.fn();
    const coordinator = new RedirectCoordinator(scan, redirect, () => {});
    coordinator.start();

    await vi.advanceTimersByTimeAsync(3999);
    expect(scan).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    expect(scan).toHaveBeenCalledOnce();
    expect(redirect).not.toHaveBeenCalled();

    scanResult.resolve('clean');
    await Promise.resolve();
    expect(redirect).toHaveBeenCalledOnce();
  });

  it('uses an existing deadline to schedule the final-second scan', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(2000);
    const scanResult = Promise.withResolvers<'clean' | 'threat'>();
    const scan = vi.fn(() => scanResult.promise);
    const redirect = vi.fn();
    const coordinator = new RedirectCoordinator(scan, redirect, () => {});
    coordinator.start(5000);

    await vi.advanceTimersByTimeAsync(1999);
    expect(scan).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    expect(scan).toHaveBeenCalledOnce();

    scanResult.resolve('clean');
    await Promise.resolve();
    expect(redirect).toHaveBeenCalledOnce();
  });

  it('waits after five seconds until the safety scan is clean', async () => {
    vi.useFakeTimers();
    const scanResult = Promise.withResolvers<'clean' | 'threat'>();
    const scan = vi.fn(() => scanResult.promise);
    const redirect = vi.fn();
    const coordinator = new RedirectCoordinator(scan, redirect, () => {});
    coordinator.start();

    await vi.advanceTimersByTimeAsync(5000);
    expect(scan).toHaveBeenCalledOnce();
    expect(redirect).not.toHaveBeenCalled();
    scanResult.resolve('clean');
    await Promise.resolve();
    expect(redirect).toHaveBeenCalledOnce();
  });

  it('skips the delay but waits for a clean safety scan before redirecting', async () => {
    vi.useFakeTimers();
    const scanResult = Promise.withResolvers<'clean' | 'threat'>();
    const scan = vi.fn(() => scanResult.promise);
    const redirect = vi.fn();
    const coordinator = new RedirectCoordinator(scan, redirect, () => {});
    coordinator.start();
    expect(scan).not.toHaveBeenCalled();
    coordinator.openAfterSafetyCheck();
    expect(scan).toHaveBeenCalledOnce();
    expect(redirect).not.toHaveBeenCalled();

    scanResult.resolve('clean');
    await Promise.resolve();
    expect(redirect).toHaveBeenCalledOnce();
    await vi.advanceTimersByTimeAsync(10000);
    expect(redirect).toHaveBeenCalledOnce();
  });

  it('bypasses the delay before the scheduled safety scan starts', async () => {
    vi.useFakeTimers();
    const scanResult = Promise.withResolvers<'clean' | 'threat'>();
    const scan = vi.fn(() => scanResult.promise);
    const redirect = vi.fn();
    const coordinator = new RedirectCoordinator(scan, redirect, () => {});
    coordinator.start();
    coordinator.openWithoutSafetyCheck();

    expect(redirect).toHaveBeenCalledOnce();
    expect(scan).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(10000);
    expect(redirect).toHaveBeenCalledOnce();
  });

  it('does not bypass a threat when the delay is skipped', async () => {
    vi.useFakeTimers();
    const scan = Promise.withResolvers<'clean' | 'threat'>();
    const redirect = vi.fn();
    const coordinator = new RedirectCoordinator(() => scan.promise, redirect, () => {});
    coordinator.start();
    coordinator.openAfterSafetyCheck();
    scan.resolve('threat');
    await Promise.resolve();
    expect(redirect).not.toHaveBeenCalled();
  });

  it('never auto-redirects threats or scan failures', async () => {
    vi.useFakeTimers();
    const threatRedirect = vi.fn();
    const threat = new RedirectCoordinator(async () => 'threat', threatRedirect, () => {});
    threat.start();
    await Promise.resolve();
    await vi.advanceTimersByTimeAsync(6000);
    expect(threatRedirect).not.toHaveBeenCalled();

    const errorRedirect = vi.fn();
    const failure = new RedirectCoordinator(
      async () => {
        throw new Error('unavailable');
      },
      errorRedirect,
      () => {}
    );
    failure.start();
    await Promise.resolve();
    await vi.advanceTimersByTimeAsync(6000);
    expect(errorRedirect).not.toHaveBeenCalled();
  });
});
