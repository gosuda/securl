import DOMPurify from 'dompurify';
import { Marked } from 'marked';

// Raw HTML in the source is shown as text instead of being interpreted.
const marked = new Marked({
  gfm: true,
  async: false,
  renderer: {
    html({ text }) {
      return text
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;');
    }
  }
});

const SAFE_LINK = /^(?:https?:|mailto:|#)/i;

let hooksInstalled = false;

function installHooks(): void {
  if (hooksInstalled) return;
  hooksInstalled = true;
  DOMPurify.addHook('afterSanitizeAttributes', (node) => {
    if (node.tagName === 'A') {
      const href = node.getAttribute('href') ?? '';
      if (!SAFE_LINK.test(href.trim())) node.removeAttribute('href');
      if (!href.startsWith('#')) {
        node.setAttribute('target', '_blank');
        node.setAttribute('rel', 'noopener noreferrer nofollow');
      }
    }
    // Remote images would leak the reader's IP and timing to third parties.
    if (node.tagName === 'IMG') {
      const src = node.getAttribute('src') ?? '';
      if (!src.startsWith('data:image/')) node.removeAttribute('src');
    }
  });
}

/** Renders untrusted Markdown into sanitized HTML. Browser-only. */
export function renderMarkdown(markdown: string): string {
  installHooks();
  const html = marked.parse(markdown) as string;
  return DOMPurify.sanitize(html, {
    USE_PROFILES: { html: true },
    FORBID_TAGS: ['style', 'form', 'input', 'button', 'textarea', 'select', 'iframe'],
    FORBID_ATTR: ['style', 'class', 'id']
  });
}
