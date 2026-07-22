// Refund ledger: records jobs that were paid for but failed to deliver, so a
// human can process the actual refund. This service can't send funds itself —
// see README §Security notes — so this is the honest version of "handling"
// the charge-on-accept-then-failure gap: tracked and minimized, not automatic.

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { config } from "./config.js";

export interface RefundEntry {
  jobId: string;
  payer: string; // lowercased wallet address
  amountBaseUnits: string; // raw x402 amount, e.g. "200000000" = $200 at 6dp
  tier: "attack" | "triage";
  reason: string;
  createdAt: number;
  refunded: boolean;
}

const FILE = config.refundsFile;
let entries: RefundEntry[] = [];

function load(): void {
  if (!existsSync(FILE)) return;
  try {
    entries = JSON.parse(readFileSync(FILE, "utf8")) as RefundEntry[];
  } catch (err) {
    console.error("[refunds] load failed:", (err as Error).message);
  }
}
load();

function persist(): void {
  try {
    writeFileSync(FILE, JSON.stringify(entries, null, 2));
  } catch (err) {
    console.error("[refunds] persist failed:", (err as Error).message);
  }
}

export function recordFailure(entry: Omit<RefundEntry, "createdAt" | "refunded">): void {
  entries.push({ ...entry, createdAt: Date.now(), refunded: false });
  persist();
  console.error(
    `[refunds] job ${entry.jobId} failed after payment — ${entry.amountBaseUnits} base units owed to ${entry.payer}: ${entry.reason}`
  );
}

/** Read-only list of unrefunded entries — for a human to actually process. */
export function pendingRefunds(): RefundEntry[] {
  return entries.filter((e) => !e.refunded);
}
