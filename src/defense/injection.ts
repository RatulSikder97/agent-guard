/**
 * Heuristic detector for indirect prompt injection in tool OUTPUT (web pages, issues, files,
 * emails...). It is deliberately transparent: every hit is a named signal with a weight, and
 * the final score is a noisy-OR of the distinct signals: score = 1 - prod(1 - w_i).
 *
 * Heuristics are bypassable by a motivated attacker (paraphrase, other languages, novel
 * encodings). They are one layer; the egress allowlist, trifecta escalation and approvals
 * are what bound the blast radius when detection misses.
 */

export interface InjectionSignal {
  id: string;
  weight: number;
  excerpt: string;
}

export interface InjectionResult {
  score: number;
  flagged: boolean;
  signals: InjectionSignal[];
}

interface Rule {
  id: string;
  weight: number;
  patterns: RegExp[];
}

const W = "[^.\\n]";

const RULES: Rule[] = [
  {
    id: "instruction_override",
    weight: 0.6,
    patterns: [
      new RegExp(
        `\\b(ignore|disregard|forget|override|bypass|skip|abandon)\\b${W}{0,40}\\b(previous|prior|above|earlier|preceding|all|any|your|the|system|original)\\b${W}{0,30}\\b(instructions?|prompts?|directions?|rules|guidelines|context|constraints|guardrails|programming)\\b`,
      ),
    ],
  },
  {
    id: "new_instructions",
    weight: 0.45,
    patterns: [
      /\b(new|updated|revised|real|actual|true|additional|hidden|secret) (instructions?|directives?|task|orders|objective|goal)\s*(:|-|—|are|is)/,
      /\byour (new|real|true|actual|primary|only) (task|instructions?|goal|objective|job|purpose) (is|are|:)/,
    ],
  },
  {
    id: "role_hijack",
    weight: 0.4,
    patterns: [
      /\byou are (now|no longer)\b/,
      /\bfrom now on,? (you|your|the assistant)\b/,
      /\bpretend (to be|you are|that you)\b/,
      /\b(enter|enable|activate) (developer|god|dan|jailbreak|unrestricted|admin) mode\b/,
    ],
  },
  {
    id: "jailbreak_persona",
    weight: 0.4,
    patterns: [
      /\b(dan|do anything now|stan|aim)\b[^.\n]{0,40}\b(no|without( any)?) (restrictions|limits|rules|filters|guidelines)\b/,
      /\b(an? )?(agent|assistant|ai|model) (without|with no) (any )?(restrictions|limits|rules|filters|guidelines)\b/,
    ],
  },
  {
    id: "chat_template_tokens",
    weight: 0.6,
    patterns: [
      /<\|(im_start|im_end|system|user|assistant|endoftext)\|>/,
      /\[\/?inst\]|<<\/?sys>>/,
      /<\/?(system|system_prompt|instructions?|important)>/,
      /^\s*#{1,4}\s*(system|instruction|new instructions?)\b/m,
      /^\s*(system|assistant)\s*:\s*\S/m,
    ],
  },
  {
    id: "addresses_the_model",
    weight: 0.35,
    patterns: [
      /\b(attention|note to|message (to|for)|hey|dear|instructions? for( the)?)\s*,?\s*(the )?(ai|llm|assistant|agent|claude|chatgpt|gpt|copilot|language model|model)s?\b/,
      /\bif you are (an? )?(ai|llm|assistant|agent|language model|automated)\b/,
      /\b(ai|llm|automated) (assistants?|agents?|systems?|models?) (reading|processing|summari[sz]ing|parsing|viewing) this\b/,
      /\b(the|this|any|every) (ai|agent|assistant|llm|model) (should|must|needs to|is required to|has to)\b/,
    ],
  },
  {
    id: "concealment",
    weight: 0.5,
    patterns: [
      new RegExp(
        `\\b(do not|don't|dont|never|without)\\b${W}{0,25}\\b(tell|telling|inform|informing|mention|mentioning|reveal|revealing|alert|alerting|notify|notifying|asking|ask|show|showing)\\b${W}{0,15}\\b(the )?(user|human|operator|owner|anyone|them)\\b`,
      ),
      /\b(silently|secretly|covertly|quietly|discreetly)\b[^.\n]{0,30}\b(send|call|run|execute|forward|upload|include|add|append|fetch|post|delete)\b/,
    ],
  },
  {
    id: "exfiltration_request",
    weight: 0.5,
    patterns: [
      new RegExp(
        `\\b(send|post|upload|forward|transmit|exfiltrate|leak|email|append|include|encode|attach|paste)\\b${W}{0,60}\\b(credentials?|secrets?|api[ _-]?keys?|tokens?|passwords?|ssh keys?|private keys?|\\.env|env(ironment)? var(iable)?s|cookies?|session ids?|chat history|conversation|system prompt|contents? of)\\b`,
      ),
      new RegExp(`\\b(send|post|upload|forward|transmit|submit)\\b${W}{0,80}\\b(to|at)\\s+(https?://|[\\w.-]+@[\\w-]+\\.)`),
    ],
  },
  {
    id: "markdown_exfil",
    weight: 0.55,
    patterns: [
      /!\[[^\]]*\]\(\s*https?:\/\/[^)\s]+\?[^)\s]*=[^)\s]*\)/,
      /<img\b[^>]*\bsrc\s*=\s*["']?https?:\/\/[^"'\s>]+\?[^"'\s>]*=/,
      /https?:\/\/[^\s)]+[?&][\w-]+=(\{\{?|<|\$\{?|\[)[\w .-]*(\}\}?|>|\]|\})/,
    ],
  },
  {
    id: "prompt_leak",
    weight: 0.5,
    patterns: [
      /\b(reveal|print|output|repeat|show|display|dump|leak)\b[^.\n]{0,30}\b(your|the)\b[^.\n]{0,15}\b(system prompt|initial prompt|hidden prompt|instructions above|original instructions|developer message)\b/,
    ],
  },
  {
    id: "tool_coercion",
    weight: 0.35,
    patterns: [
      /\b(immediately|now|first|must|then)\b[^.\n]{0,20}\b(call|invoke|use|run|execute|trigger)\b[^.\n]{0,15}\b(the )?[\w.-]+ (tool|function)\b/,
      /\b(execute|run) (the following|this) (shell )?(command|code|script)\b/,
      /\b(curl|wget)\b[^\n|]{0,200}\|\s*(ba|z)?sh\b/,
    ],
  },
  {
    id: "destructive_request",
    weight: 0.3,
    patterns: [
      /\b(delete|remove|drop|wipe|destroy|truncate|force[- ]push)\b[^.\n]{0,30}\b(all|every|entire|the database|repositor(y|ies)|all files|tables?|branches|production)\b/,
      /\brm\s+-rf\s+[/~]/,
    ],
  },
  {
    id: "urgency_pressure",
    weight: 0.15,
    patterns: [/\b(important|urgent|critical|mandatory|required|warning)\s*[:!]/],
  },
  {
    id: "hidden_html_comment",
    weight: 0.3,
    patterns: [/<!--[\s\S]{0,800}?\b(ai|assistant|agent|instructions?|ignore|prompt|model)\b[\s\S]{0,800}?-->/],
  },
];

const ZERO_WIDTH = /[\u200B-\u200F\u2060-\u2064\uFEFF\u00AD]/g;
const BIDI = /[\u202A-\u202E\u2066-\u2069]/g;
const TAG_CHARS = /[\u{E0000}-\u{E007F}]/gu;

function excerptAround(text: string, index: number, length: number): string {
  const start = Math.max(0, index - 20);
  const end = Math.min(text.length, index + Math.min(length, 80) + 20);
  return text.slice(start, end).replace(/\s+/g, " ").trim();
}

/** Decodes Unicode "tag" characters (ASCII smuggling) into visible ASCII. */
function decodeTagChars(text: string): string {
  let out = "";
  for (const ch of text) {
    const cp = ch.codePointAt(0) ?? 0;
    if (cp >= 0xe0020 && cp <= 0xe007e) out += String.fromCharCode(cp - 0xe0000);
  }
  return out;
}

function decodeBase64Candidates(text: string): string[] {
  const out: string[] = [];
  const re = /[A-Za-z0-9+/]{40,}={0,2}/g;
  let m: RegExpExecArray | null;
  let count = 0;
  while ((m = re.exec(text)) && count < 20) {
    count++;
    const decoded = Buffer.from(m[0], "base64").toString("utf8");
    const printable = decoded.replace(/[^\x20-\x7E\n\r\t]/g, "").length / Math.max(1, decoded.length);
    if (printable > 0.95 && /[a-z]{3,} [a-z]{3,}/i.test(decoded)) out.push(decoded);
  }
  return out;
}

export interface ScanOptions {
  threshold?: number;
}

function scanRules(normalized: string, weightScale: number, prefix: string): InjectionSignal[] {
  const signals: InjectionSignal[] = [];
  for (const rule of RULES) {
    for (const p of rule.patterns) {
      const m = p.exec(normalized);
      if (m) {
        signals.push({ id: prefix + rule.id, weight: rule.weight * weightScale, excerpt: excerptAround(normalized, m.index, m[0].length) });
        break;
      }
    }
  }
  return signals;
}

export function scanForInjection(text: string, opts: ScanOptions = {}): InjectionResult {
  const threshold = opts.threshold ?? 0.5;
  const signals: InjectionSignal[] = [];

  const zw = text.match(ZERO_WIDTH)?.length ?? 0;
  const bidi = text.match(BIDI)?.length ?? 0;
  const tags = text.match(TAG_CHARS)?.length ?? 0;
  if (tags > 0) signals.push({ id: "unicode_tag_smuggling", weight: 0.6, excerpt: `${tags} invisible tag characters` });
  if (zw >= 3 || bidi > 0) {
    signals.push({ id: "invisible_characters", weight: 0.25, excerpt: `${zw} zero-width, ${bidi} bidi-control characters` });
  }

  const normalized = text.normalize("NFKC").replace(ZERO_WIDTH, "").replace(BIDI, "").replace(TAG_CHARS, "").toLowerCase();
  signals.push(...scanRules(normalized, 1, ""));

  const smuggled = decodeTagChars(text);
  if (smuggled.length > 0) signals.push(...scanRules(smuggled.toLowerCase(), 1, "smuggled:"));

  for (const decoded of decodeBase64Candidates(text)) {
    const inner = scanRules(decoded.toLowerCase(), 0.9, "base64:");
    if (inner.length > 0) {
      signals.push({ id: "encoded_payload", weight: 0.3, excerpt: decoded.slice(0, 80) });
      signals.push(...inner);
    }
  }

  // Noisy-OR over the strongest instance of each distinct signal id.
  const best = new Map<string, InjectionSignal>();
  for (const s of signals) {
    const prev = best.get(s.id);
    if (!prev || s.weight > prev.weight) best.set(s.id, s);
  }
  const unique = [...best.values()].sort((a, b) => b.weight - a.weight);
  const score = 1 - unique.reduce((acc, s) => acc * (1 - Math.min(0.99, s.weight)), 1);
  const rounded = Math.round(score * 1000) / 1000;
  return { score: rounded, flagged: rounded >= threshold, signals: unique };
}
