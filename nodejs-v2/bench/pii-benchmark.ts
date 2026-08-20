/**
 * PII detection benchmark. Measures how much PII the shield actually catches on
 * a labeled corpus. RECALL is the headline number — an unrecalled entity is a
 * real leak to the LLM. Precision/false-positives are secondary (over-redaction
 * is caught in human review; under-redaction is not).
 *
 * Run: npx tsx bench/pii-benchmark.ts
 *
 * Tuning knobs (recall-first): PII_NER_THRESHOLD (default 0.25 — lower = more
 * recall), PII_MIN_SCORE, PII_NER_LABEL_SET. Without the GLiNER model downloaded
 * the engine runs patterns-only — you'll see structured PII caught and NAMES
 * missed, which is exactly the gap to close for HR docs.
 */
import { CORPUS, type LabeledDoc } from "./corpus.js";

const { PIIEngine } = await import("../src/engine/pii-engine.js");
const { isNerReady } = await import("../src/engine/ner-backend.js");

interface Span { start: number; end: number }
const overlaps = (a: Span, b: Span) => a.start < b.end && b.start < a.end;

function gtSpans(doc: LabeledDoc): Array<{ text: string; type: string; start: number; end: number }> {
  const out: Array<{ text: string; type: string; start: number; end: number }> = [];
  for (const e of doc.entities) {
    const start = doc.text.indexOf(e.text);
    if (start < 0) {
      console.warn(`  [corpus] '${e.text}' not found verbatim in ${doc.id} — fix the label`);
      continue;
    }
    out.push({ text: e.text, type: e.type, start, end: start + e.text.length });
  }
  return out;
}

async function main(): Promise<void> {
  const engine = PIIEngine.getInstance();

  let totalGt = 0, recalled = 0;
  let totalDet = 0, truePos = 0;
  const perType: Record<string, { gt: number; hit: number }> = {};
  const misses: Array<{ doc: string; text: string; type: string }> = [];

  for (const doc of CORPUS) {
    const gts = gtSpans(doc);
    let detected: Array<{ start: number; end: number; text: string; type: string }>;
    try {
      detected = (await engine.detect(doc.text)) as any;
    } catch (e) {
      console.error(`  detect failed on ${doc.id}: ${e}`);
      detected = [];
    }

    totalGt += gts.length;
    totalDet += detected.length;

    for (const gt of gts) {
      perType[gt.type] ??= { gt: 0, hit: 0 };
      perType[gt.type].gt++;
      const hit = detected.some((d) => overlaps(d, gt));
      if (hit) { recalled++; perType[gt.type].hit++; }
      else misses.push({ doc: doc.id, text: gt.text, type: gt.type });
    }
    for (const d of detected) {
      if (gts.some((gt) => overlaps(d, gt))) truePos++;
    }
  }

  const recall = totalGt ? recalled / totalGt : 0;
  const precision = totalDet ? truePos / totalDet : 0;
  const f1 = recall + precision ? (2 * recall * precision) / (recall + precision) : 0;
  const nerReady = isNerReady();

  console.log("\n════════ PII Detection Benchmark ════════");
  console.log(`mode:      ${nerReady ? "FULL (GLiNER + patterns)" : "PATTERNS ONLY (GLiNER model not downloaded)"}`);
  console.log(`docs:      ${CORPUS.length}   ground-truth entities: ${totalGt}`);
  console.log(`RECALL:    ${(recall * 100).toFixed(1)}%   (${recalled}/${totalGt} caught — the leak metric)`);
  console.log(`precision: ${(precision * 100).toFixed(1)}%   f1: ${(f1 * 100).toFixed(1)}%`);

  console.log("\nrecall by type:");
  for (const t of Object.keys(perType).sort()) {
    const { gt, hit } = perType[t];
    const r = ((hit / gt) * 100).toFixed(0);
    console.log(`  ${t.padEnd(12)} ${String(hit).padStart(2)}/${gt}  ${r}%`);
  }

  console.log(`\nLEAKS (${misses.length}) — PII that reached the LLM unredacted:`);
  for (const m of misses) console.log(`  ✗ [${m.type}] "${m.text}"  (${m.doc})`);

  // Fail the run if any PII leaked — a shield must not silently under-redact.
  process.exit(misses.length === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(2); });
