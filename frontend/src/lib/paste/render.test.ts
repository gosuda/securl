// @vitest-environment jsdom
import { describe, expect, it } from 'vitest';
import { renderMarkdown } from './render';

function render(markdown: string): HTMLElement {
  const container = document.createElement('div');
  container.innerHTML = renderMarkdown(markdown);
  return container;
}

describe('renderMarkdown', () => {
  it('renders GFM structure', () => {
    const html = render('# Title\n\n| a | b |\n|---|---|\n| 1 | 2 |\n\n- [x] done\n\n```js\nx<1\n```');
    expect(html.querySelector('h1')?.textContent).toBe('Title');
    expect(html.querySelectorAll('td')).toHaveLength(2);
    expect(html.querySelector('pre code')?.textContent).toBe('x<1\n');
  });

  it('shows raw HTML as text instead of interpreting it', () => {
    const html = render('<img src=x onerror=alert(1)>\n\n<script>alert(1)</script>\n\nhi <b onclick=x>b</b>');
    expect(html.querySelector('img, script, b')).toBeNull();
    expect(html.textContent).toContain('<script>alert(1)</script>');
  });

  it('strips script URLs and isolates external links', () => {
    const html = render('[x](javascript:alert(1)) [y](https://example.com) [z](#top) [w](data:text/html,hi)');
    const [script, external, anchor, data] = Array.from(html.querySelectorAll('a'));
    expect(script.hasAttribute('href')).toBe(false);
    expect(external.getAttribute('rel')).toBe('noopener noreferrer nofollow');
    expect(external.getAttribute('target')).toBe('_blank');
    expect(anchor.getAttribute('href')).toBe('#top');
    expect(anchor.hasAttribute('target')).toBe(false);
    expect(data.hasAttribute('href')).toBe(false);
  });

  it('drops remote image sources so opening a paste cannot be tracked', () => {
    const html = render('![t](https://tracker.example/p.gif) ![ok](data:image/png;base64,iVBORw0KGgo=)');
    const [remote, inline] = Array.from(html.querySelectorAll('img'));
    expect(remote.hasAttribute('src')).toBe(false);
    expect(inline.getAttribute('src')).toMatch(/^data:image\/png/);
  });
});
