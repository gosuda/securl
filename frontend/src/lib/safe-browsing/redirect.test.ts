import { afterEach, describe, expect, it, vi } from 'vitest';
import { RedirectCoordinator } from './redirect';

afterEach(() => vi.useRealTimers());

describe('redirect safety coordination', () => {
  it('never redirects a clean result before exactly five seconds', async () => {
    vi.useFakeTimers();
    const scan = Promise.withResolvers<'clean' | 'threat'>();
    const redirect = vi.fn();
    const coordinator = new RedirectCoordinator(() => scan.promise, redirect, () => {});
    coordinator.start();
    scan.resolve('clean');
    await Promise.resolve();

    await vi.advanceTimersByTimeAsync(4999);
    expect(redirect).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    expect(redirect).toHaveBeenCalledOnce();
  });

  it('waits after five seconds until the safety scan is clean', async () => {
    vi.useFakeTimers();
    const scan = Promise.withResolvers<'clean' | 'threat'>();
    const redirect = vi.fn();
    const coordinator = new RedirectCoordinator(() => scan.promise, redirect, () => {});
    coordinator.start();

    await vi.advanceTimersByTimeAsync(5000);
    expect(redirect).not.toHaveBeenCalled();
    scan.resolve('clean');
    await Promise.resolve();
    expect(redirect).toHaveBeenCalledOnce();
  });

  it('skips the delay but waits for a clean safety scan before redirecting', async () => {
    vi.useFakeTimers();
    const scan = Promise.withResolvers<'clean' | 'threat'>();
    const redirect = vi.fn();
    const coordinator = new RedirectCoordinator(() => scan.promise, redirect, () => {});
    coordinator.start();
    coordinator.openAfterSafetyCheck();
    expect(redirect).not.toHaveBeenCalled();

    scan.resolve('clean');
    await Promise.resolve();
    expect(redirect).toHaveBeenCalledOnce();
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
