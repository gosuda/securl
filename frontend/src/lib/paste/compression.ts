const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder('utf-8', { fatal: true });

/** Hard cap on inflated Markdown so a hostile envelope cannot exhaust memory. */
export const MAX_MARKDOWN_BYTES = 4 << 20;

async function collect(stream: ReadableStream<Uint8Array>, limit: number): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  let length = 0;
  const reader = stream.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.length;
      if (length > limit) {
        await reader.cancel();
        throw new Error('Inflated Markdown exceeds the size limit.');
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const output = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
    chunk.fill(0);
  }
  return output;
}

/** Compresses UTF-8 Markdown with raw DEFLATE (RFC 1951). */
export async function deflateMarkdown(markdown: string): Promise<Uint8Array> {
  const input = textEncoder.encode(markdown);
  try {
    if (input.length > MAX_MARKDOWN_BYTES) throw new Error('Markdown exceeds the size limit.');
    return await collect(
      new Blob([input]).stream().pipeThrough(new CompressionStream('deflate-raw')),
      Number.MAX_SAFE_INTEGER
    );
  } finally {
    input.fill(0);
  }
}

export async function inflateMarkdown(deflated: Uint8Array): Promise<string> {
  const output = await collect(
    new Blob([deflated as Uint8Array<ArrayBuffer>])
      .stream()
      .pipeThrough(new DecompressionStream('deflate-raw')),
    MAX_MARKDOWN_BYTES
  );
  try {
    return textDecoder.decode(output);
  } finally {
    output.fill(0);
  }
}
