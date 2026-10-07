// Content extraction for web_fetch (SPEC 12.2).
//
// Accepts only textual, HTML and PDF content. HTML is tokenised and reduced
// to text without executing anything (no DOM, no scripts, no subresources).
// PDFs are parsed with pdf.js (via unpdf) with eval disabled and a page
// limit. Extracted text is capped; overflow goes only to sandbox-ephemeral
// storage, never to the vault.

import { mkdirSync, realpathSync, rmSync, writeFileSync, existsSync, readdirSync, statSync } from "node:fs";
import { join, resolve, sep } from "node:path";
import { randomBytes } from "node:crypto";

export interface ExtractLimits {
  maxTextChars: number;
  maxPdfPages: number;
}

export const DEFAULT_EXTRACT_LIMITS: ExtractLimits = {
  maxTextChars: 60_000,
  maxPdfPages: 30,
};

export type ContentKind = "html" | "text" | "pdf";

export class ExtractError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
    this.name = "ExtractError";
  }
}

const TEXT_TYPES = new Set([
  "text/plain",
  "text/markdown",
  "text/x-markdown",
  "text/csv",
  "text/xml",
  "application/xml",
  "application/json",
  "application/ld+json",
  "text/x-rst",
  "text/asciidoc",
]);
const HTML_TYPES = new Set(["text/html", "application/xhtml+xml"]);

export function classifyContentType(header: string): { kind: ContentKind; mime: string; charset: string | null } {
  const [rawMime, ...params] = header.split(";");
  const mime = rawMime.trim().toLowerCase();
  let charset: string | null = null;
  for (const p of params) {
    const [k, v] = p.split("=");
    if (k && v && k.trim().toLowerCase() === "charset") charset = v.trim().replace(/^"|"$/g, "").toLowerCase();
  }
  if (!mime) throw new ExtractError("unsupported_content", "the response has no Content-Type");
  if (HTML_TYPES.has(mime)) return { kind: "html", mime, charset };
  if (TEXT_TYPES.has(mime) || (mime.startsWith("text/") && mime !== "text/javascript" && mime !== "text/css")) {
    return { kind: "text", mime, charset };
  }
  if (mime === "application/pdf") return { kind: "pdf", mime, charset };
  throw new ExtractError("unsupported_content", `unsupported content type ${mime} (only text, HTML and PDF)`);
}

export function decodeText(body: Buffer, charset: string | null, sniffHtml: boolean): string {
  let label = charset;
  if (!label && sniffHtml) {
    const head = body.subarray(0, 2048).toString("latin1");
    const m = /<meta[^>]+charset\s*=\s*["']?([A-Za-z0-9_-]+)/i.exec(head);
    if (m) label = m[1].toLowerCase();
  }
  try {
    return new TextDecoder(label || "utf-8", { fatal: false }).decode(body);
  } catch {
    return new TextDecoder("utf-8", { fatal: false }).decode(body);
  }
}

// ── HTML → text ─────────────────────────────────────────────────────────────

const DROP_WITH_CONTENT = new Set(["script", "style", "noscript", "template", "svg", "math", "iframe", "object", "embed", "canvas", "head", "select", "button", "form"]);
const BLOCK_TAGS = new Set([
  "p", "div", "section", "article", "main", "header", "footer", "nav", "aside", "br", "hr", "li", "ul", "ol",
  "table", "tr", "td", "th", "thead", "tbody", "tfoot", "blockquote", "pre", "figure", "figcaption", "dl", "dt", "dd",
  "h1", "h2", "h3", "h4", "h5", "h6", "address", "details", "summary",
]);

const NAMED_ENTITIES: Record<string, string> = {
  amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ", ndash: "–", mdash: "—", hellip: "…",
  lsquo: "‘", rsquo: "’", ldquo: "“", rdquo: "”", copy: "©", reg: "®", trade: "™", middot: "·", bull: "•",
  laquo: "«", raquo: "»", times: "×", divide: "÷", deg: "°", euro: "€", pound: "£", yen: "¥", sect: "§",
};

export function decodeEntities(text: string): string {
  return text.replace(/&(#x[0-9a-f]+|#\d+|[a-z][a-z0-9]*);?/gi, (whole, ent: string) => {
    if (ent[0] === "#") {
      const code = ent[1] === "x" || ent[1] === "X" ? parseInt(ent.slice(2), 16) : parseInt(ent.slice(1), 10);
      if (!Number.isFinite(code) || code <= 0 || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) return "�";
      return String.fromCodePoint(code);
    }
    const named = NAMED_ENTITIES[ent.toLowerCase()];
    return named ?? whole;
  });
}

export interface HtmlExtraction {
  title: string | null;
  text: string;
}

export function htmlToText(html: string): HtmlExtraction {
  let title: string | null = null;
  const titleMatch = /<title[^>]*>([\s\S]*?)<\/title\s*>/i.exec(html);
  if (titleMatch) title = decodeEntities(titleMatch[1].replace(/\s+/g, " ").trim()) || null;

  // Remove comments and CDATA first so their contents never surface.
  let s = html.replace(/<!--[\s\S]*?-->/g, " ").replace(/<!\[CDATA\[[\s\S]*?\]\]>/g, " ");
  s = s.replace(/<!doctype[^>]*>/gi, " ");

  const out: string[] = [];
  // <pre> content is stashed behind placeholders so whitespace normalisation
  // never touches it, then restored at the end.
  const preserved: string[] = [];
  const tagRe = /<\/?([a-zA-Z][a-zA-Z0-9:-]*)\b[^>]*>/g;
  let last = 0;
  let dropDepth = 0;
  let dropTag: string | null = null;
  let preDepth = 0;
  let m: RegExpExecArray | null;
  while ((m = tagRe.exec(s))) {
    const before = s.slice(last, m.index);
    if (!dropDepth) {
      if (preDepth) {
        preserved.push(before);
        out.push(`\u0000${preserved.length - 1}\u0000`);
      } else {
        out.push(before.replace(/\s+/g, " "));
      }
    }
    last = m.index + m[0].length;
    const tag = m[1].toLowerCase();
    const closing = m[0][1] === "/";
    if (dropDepth) {
      if (tag === dropTag) dropDepth += closing ? -1 : m[0].endsWith("/>") ? 0 : 1;
      if (dropDepth === 0) dropTag = null;
      continue;
    }
    if (DROP_WITH_CONTENT.has(tag) && !closing) {
      if (!m[0].endsWith("/>")) {
        dropDepth = 1;
        dropTag = tag;
      }
      continue;
    }
    if (tag === "pre") preDepth = Math.max(0, preDepth + (closing ? -1 : 1));
    if (/^h[1-6]$/.test(tag) && !closing) out.push(`\n\n${"#".repeat(Number(tag[1]))} `);
    else if (tag === "li") {
      if (!closing) out.push("\n- ");
    } else if (BLOCK_TAGS.has(tag)) out.push("\n");
    else if (tag === "img" && !closing) {
      const alt = /\balt\s*=\s*"([^"]*)"|\balt\s*=\s*'([^']*)'/i.exec(m[0]);
      const text = alt ? alt[1] ?? alt[2] : "";
      if (text) out.push(` [image: ${text}] `);
    }
  }
  if (!dropDepth) out.push(s.slice(last).replace(/\s+/g, " "));
  const text = decodeEntities(
    out
      .join("")
      .replace(/[ \t\f\v ]+\n/g, "\n")
      .replace(/\n[ \t\f\v ]+/g, "\n")
      .replace(/\n{3,}/g, "\n\n")
      .trim(),
  ).replace(/\u0000(\d+)\u0000/g, (_w, i: string) => decodeEntities(preserved[Number(i)] ?? ""));
  return { title, text };
}

// ── PDF → text ──────────────────────────────────────────────────────────────

export interface PdfExtraction {
  totalPages: number;
  pagesRead: number;
  text: string;
}

export async function pdfToText(body: Buffer, maxPages: number): Promise<PdfExtraction> {
  let unpdf: any;
  try {
    unpdf = await import("unpdf");
  } catch {
    throw new ExtractError("pdf_unavailable", "PDF support is not installed in this runtime");
  }
  let doc: any;
  try {
    doc = await unpdf.getDocumentProxy(new Uint8Array(body), {
      isEvalSupported: false,
      disableFontFace: true,
      useSystemFonts: false,
      stopAtErrors: false,
      verbosity: 0,
    });
  } catch (err: any) {
    throw new ExtractError("pdf_invalid", `could not parse PDF: ${err?.message ?? err}`);
  }
  try {
    const totalPages: number = doc.numPages;
    const pagesRead = Math.min(totalPages, maxPages);
    const pages: string[] = [];
    for (let i = 1; i <= pagesRead; i++) {
      const page = await doc.getPage(i);
      const content = await page.getTextContent();
      const text = content.items.map((item: any) => (typeof item.str === "string" ? item.str : "") + (item.hasEOL ? "\n" : " ")).join("");
      pages.push(`--- page ${i} ---\n${text.replace(/[ \t]+\n/g, "\n").trim()}`);
    }
    return { totalPages, pagesRead, text: pages.join("\n\n") };
  } finally {
    await doc.destroy?.();
  }
}

// ── Overflow storage ────────────────────────────────────────────────────────

/** Directory for overflow text. Must not be inside any protected root (the vault mount). */
export class OverflowStore {
  readonly dir: string;

  constructor(dir: string, protectedRoots: string[]) {
    const abs = resolve(dir);
    mkdirSync(abs, { recursive: true, mode: 0o700 });
    const real = realpathSync(abs);
    for (const root of protectedRoots) {
      if (!root || !existsSync(root)) continue;
      const protectedReal = realpathSync(root);
      if (real === protectedReal || real.startsWith(protectedReal + sep)) {
        throw new ExtractError("overflow_in_vault", `refusing to write overflow data under ${root}`);
      }
    }
    this.dir = real;
  }

  write(text: string): string {
    const file = join(this.dir, `fetch-${Date.now()}-${randomBytes(4).toString("hex")}.txt`);
    writeFileSync(file, text, { mode: 0o600 });
    return file;
  }

  /** Remove everything this store wrote (session teardown). */
  clear(): void {
    rmSync(this.dir, { recursive: true, force: true });
  }

  /** Remove sibling session directories older than `maxAgeMs` (crash leftovers). */
  static sweep(parent: string, maxAgeMs: number, now = Date.now()): string[] {
    const removed: string[] = [];
    if (!existsSync(parent)) return removed;
    for (const name of readdirSync(parent)) {
      const path = join(parent, name);
      try {
        if (now - statSync(path).mtimeMs > maxAgeMs) {
          rmSync(path, { recursive: true, force: true });
          removed.push(path);
        }
      } catch {
        // already gone
      }
    }
    return removed;
  }
}

export interface Extracted {
  kind: ContentKind;
  mime: string;
  title: string | null;
  text: string;
  textTruncated: boolean;
  overflowFile: string | null;
  notes: string[];
}

export async function extract(
  body: Buffer,
  contentType: string,
  bodyTruncated: boolean,
  limits: ExtractLimits,
  overflow: OverflowStore | null,
): Promise<Extracted> {
  const { kind, mime, charset } = classifyContentType(contentType);
  const notes: string[] = [];
  let title: string | null = null;
  let text: string;
  if (kind === "pdf") {
    if (bodyTruncated) throw new ExtractError("pdf_too_large", "the PDF exceeds the response-byte limit");
    const pdf = await pdfToText(body, limits.maxPdfPages);
    text = pdf.text;
    if (pdf.pagesRead < pdf.totalPages) notes.push(`read ${pdf.pagesRead} of ${pdf.totalPages} PDF pages (page limit)`);
  } else {
    const decoded = decodeText(body, charset, kind === "html");
    if (kind === "html") {
      const html = htmlToText(decoded);
      title = html.title;
      text = html.text;
    } else {
      text = decoded.replace(/\r\n?/g, "\n");
    }
    if (bodyTruncated) notes.push("response truncated at the byte limit");
  }
  // Strip control characters other than newline and tab.
  text = text.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "");
  let textTruncated = false;
  let overflowFile: string | null = null;
  if (text.length > limits.maxTextChars) {
    textTruncated = true;
    if (overflow) {
      overflowFile = overflow.write(text);
      notes.push(`full text (${text.length} chars) saved to sandbox-ephemeral ${overflowFile}`);
    }
    text = text.slice(0, limits.maxTextChars);
    notes.push(`text truncated to ${limits.maxTextChars} characters`);
  }
  return { kind, mime, title, text, textTruncated, overflowFile, notes };
}
