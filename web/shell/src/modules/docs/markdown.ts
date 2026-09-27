// SPDX-License-Identifier: Apache-2.0

// A tiny, dependency-free markdown-ish renderer (a plain textarea + rendered preview is enough;
// no WYSIWYG and no third-party markdown dependency), so this hand-rolls just enough:
// headers (#/##/###), **bold**, *italic*, "- " bullet lists, and paragraph breaks). Input is HTML-
// escaped FIRST, then the markdown transforms run on the escaped text — user-authored document
// bodies are rendered as HTML via dangerouslySetInnerHTML in document-page.tsx, so this ordering
// is the whole XSS defense; never reorder it.
function escapeHtml(input: string): string {
  return input
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function renderInline(line: string): string {
  return line
    .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
    .replace(/\*(.+?)\*/g, "<em>$1</em>");
}

/** Renders a (already-escaped-input) markdown-ish string to a safe HTML string. */
export function renderMarkdown(raw: string): string {
  const escaped = escapeHtml(raw);
  const lines = escaped.split("\n");
  const htmlParts: string[] = [];
  let listOpen = false;
  let paragraphLines: string[] = [];

  function flushParagraph(): void {
    if (paragraphLines.length > 0) {
      htmlParts.push(`<p>${paragraphLines.map(renderInline).join("<br />")}</p>`);
      paragraphLines = [];
    }
  }
  function closeList(): void {
    if (listOpen) {
      htmlParts.push("</ul>");
      listOpen = false;
    }
  }

  for (const line of lines) {
    const headerMatch = /^(#{1,3})\s+(.*)$/.exec(line);
    const bulletMatch = /^[-*]\s+(.*)$/.exec(line);

    if (headerMatch) {
      flushParagraph();
      closeList();
      const level = headerMatch[1]!.length;
      htmlParts.push(`<h${level}>${renderInline(headerMatch[2]!)}</h${level}>`);
      continue;
    }
    if (bulletMatch) {
      flushParagraph();
      if (!listOpen) {
        htmlParts.push("<ul>");
        listOpen = true;
      }
      htmlParts.push(`<li>${renderInline(bulletMatch[1]!)}</li>`);
      continue;
    }
    if (line.trim() === "") {
      flushParagraph();
      closeList();
      continue;
    }
    paragraphLines.push(line);
  }
  flushParagraph();
  closeList();

  return htmlParts.join("\n");
}
