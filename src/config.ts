// Central config + caps. Everything secret comes from env (set on Railway),
// never from the repo.

function num(name: string, def: number): number {
  const v = process.env[name];
  if (v === undefined || v === "") return def;
  const n = Number(v);
  if (!Number.isFinite(n)) throw new Error(`${name} must be a number, got "${v}"`);
  return n;
}

export const config = {
  port: process.env.PORT ?? 3000,
  model: process.env.ARGUS_MODEL ?? "claude-opus-4-8",

  // x402 / payment
  network: process.env.X402_NETWORK ?? "eip155:196",
  payTo: process.env.PAY_TO_ADDRESS,
  price: process.env.ARGUS_PRICE_USD ?? "$200",
  triagePrice: process.env.TRIAGE_PRICE_USD ?? "$15",

  // caps — the margin guardrails (full attack simulation)
  maxToolIterations: num("MAX_TOOL_ITERATIONS", 60),
  maxWallclockSec: num("MAX_WALLCLOCK_SEC", 1200),
  maxOutputTokensPerTurn: num("MAX_OUTPUT_TOKENS_PER_TURN", 8000),
  maxInputScopeChars: num("MAX_INPUT_SCOPE_CHARS", 200_000),

  // caps for the cheaper quick-triage tier — same engine, much shorter leash
  triageMaxToolIterations: num("TRIAGE_MAX_TOOL_ITERATIONS", 10),
  triageMaxWallclockSec: num("TRIAGE_MAX_WALLCLOCK_SEC", 180),

  // runtime
  workspaceRoot: process.env.WORKSPACE_ROOT ?? "./workspaces",
  jobsFile: process.env.JOBS_FILE ?? "./jobs.json",

  // per-tool-call bash timeout (ms)
  bashTimeoutMs: num("BASH_TIMEOUT_MS", 180_000),
} as const;

/** Fail fast at boot if required payment env is missing (mirrors fit-check). */
export function assertPaymentEnv(): void {
  if (!config.payTo) {
    throw new Error("PAY_TO_ADDRESS env var is required (the wallet that receives payment)");
  }
  if (!process.env.OKX_API_KEY || !process.env.OKX_SECRET_KEY || !process.env.OKX_PASSPHRASE) {
    throw new Error(
      "OKX_API_KEY / OKX_SECRET_KEY / OKX_PASSPHRASE env vars are required (from the OKX Developer Portal)"
    );
  }
  if (!/^[^:]+:[^:]+$/.test(config.network)) {
    throw new Error(`X402_NETWORK must be CAIP-2 formatted (e.g. "eip155:196"), got "${config.network}"`);
  }
}
