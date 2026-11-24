/**
 * Runs the heuristic injection scanner over the fixture corpus and prints a confusion matrix,
 * precision/recall/F1 and every misclassified sample. `--markdown` prints the README table.
 */
import { scanForInjection } from "../src/defense/injection.js";
import { CORPUS } from "../test/fixtures/corpus.js";

export interface BenchResult {
  tp: number;
  fp: number;
  tn: number;
  fn: number;
  precision: number;
  recall: number;
  f1: number;
  misses: { id: string; label: string; score: number; signals: string[] }[];
}

export function runBench(threshold = 0.5): BenchResult {
  let tp = 0, fp = 0, tn = 0, fn = 0;
  const misses: BenchResult["misses"] = [];
  for (const s of CORPUS) {
    const r = scanForInjection(s.text, { threshold });
    const malicious = s.label === "malicious";
    if (r.flagged && malicious) tp++;
    else if (r.flagged && !malicious) fp++;
    else if (!r.flagged && !malicious) tn++;
    else fn++;
    if (r.flagged !== malicious) misses.push({ id: s.id, label: s.label, score: r.score, signals: r.signals.map((x) => x.id) });
  }
  const precision = tp / Math.max(1, tp + fp);
  const recall = tp / Math.max(1, tp + fn);
  const f1 = (2 * precision * recall) / Math.max(1e-9, precision + recall);
  return { tp, fp, tn, fn, precision, recall, f1, misses };
}

const isMain = process.argv[1] !== undefined && import.meta.url.endsWith(process.argv[1].split("/").pop() ?? "");
if (isMain) {
  const threshold = Number(process.env.THRESHOLD ?? 0.5);
  const r = runBench(threshold);
  const pct = (x: number) => `${(x * 100).toFixed(1)}%`;
  const malicious = CORPUS.filter((s) => s.label === "malicious").length;
  if (process.argv.includes("--markdown")) {
    console.log(`| Samples | Malicious | Benign | TP | FP | TN | FN | Precision | Recall | F1 |`);
    console.log(`|---|---|---|---|---|---|---|---|---|---|`);
    console.log(`| ${CORPUS.length} | ${malicious} | ${CORPUS.length - malicious} | ${r.tp} | ${r.fp} | ${r.tn} | ${r.fn} | ${pct(r.precision)} | ${pct(r.recall)} | ${pct(r.f1)} |`);
  } else {
    console.log(`corpus: ${CORPUS.length} samples (${malicious} malicious, ${CORPUS.length - malicious} benign), threshold ${threshold}`);
    console.log(`TP ${r.tp}  FP ${r.fp}  TN ${r.tn}  FN ${r.fn}`);
    console.log(`precision ${pct(r.precision)}  recall ${pct(r.recall)}  F1 ${pct(r.f1)}`);
  }
  if (r.misses.length) {
    console.log(process.argv.includes("--markdown") ? "\nMisclassified:\n" : "\nmisclassified:");
    for (const m of r.misses) console.log(`  - ${m.id} (${m.label}, score ${m.score.toFixed(2)}${m.signals.length ? `, signals: ${m.signals.join(", ")}` : ""})`);
  }
}
