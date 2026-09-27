// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { renderMarkdown } from "../../../src/modules/docs/markdown";

describe("renderMarkdown", () => {
  it("renders a paragraph", () => {
    expect(renderMarkdown("hello world")).toBe("<p>hello world</p>");
  });

  it("renders headers", () => {
    expect(renderMarkdown("# Title")).toBe("<h1>Title</h1>");
    expect(renderMarkdown("## Sub")).toBe("<h2>Sub</h2>");
  });

  it("renders bold and italic inline", () => {
    expect(renderMarkdown("**bold** and *italic*")).toBe("<p><strong>bold</strong> and <em>italic</em></p>");
  });

  it("renders a bullet list", () => {
    expect(renderMarkdown("- one\n- two")).toBe("<ul>\n<li>one</li>\n<li>two</li>\n</ul>");
  });

  it("escapes raw HTML before applying markdown transforms (XSS defense)", () => {
    const rendered = renderMarkdown("<script>alert(1)</script>");
    expect(rendered).not.toContain("<script>");
    expect(rendered).toContain("&lt;script&gt;");
  });
});
