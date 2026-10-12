import { describe, expect, it } from 'vitest';
import { MAX_MARKDOWN_BYTES, deflateMarkdown, inflateMarkdown } from './compression';

describe('Markdown compression', () => {
  it('round-trips UTF-8 and compresses repetitive Markdown', async () => {
    const markdown = '# 제목 ✓\n\n' + '| col | value |\n|---|---|\n| a | 1 |\n'.repeat(500);
    const deflated = await deflateMarkdown(markdown);
    expect(deflated.length).toBeLessThan(new TextEncoder().encode(markdown).length / 20);
    expect(await inflateMarkdown(deflated)).toBe(markdown);
  });

  it('refuses decompression bombs beyond the inflated cap', async () => {
    const bomb = await new Response(
      new Blob([new Uint8Array(MAX_MARKDOWN_BYTES + 1)]).stream().pipeThrough(new CompressionStream('deflate-raw'))
    ).bytes();
    await expect(inflateMarkdown(bomb)).rejects.toThrow(/size limit/);
  });

  it('rejects non-UTF-8 output', async () => {
    const invalid = await new Response(
      new Blob([new Uint8Array([0xff, 0xfe])]).stream().pipeThrough(new CompressionStream('deflate-raw'))
    ).bytes();
    await expect(inflateMarkdown(invalid)).rejects.toThrow();
  });
});
