// Renegade HTTP service.
//   GET  /health           — liveness (marketplace heartbeat)
//   POST /attack           — x402-gated, full attack simulation; queues a job, returns { jobId }
//   GET  /attack/:jobId    — poll job status / retrieve the finished report
//   POST /triage           — x402-gated, cheap fast preliminary scan; same shape, shorter cap
//   GET  /triage/:jobId    — poll for the triage job
//
// The audit is a multi-minute agentic job, so POST returns immediately (202)
// after payment settles and the work runs in the background — unlike Fit
// Check's synchronous single call.

import express from "express";
import { config } from "./config.js";
import { auditPaymentMiddleware, paymentInfoOf } from "./payment.js";
import { createJob, getJob, updateJob, publicView } from "./jobs.js";
import { runAudit, type EngineCaps } from "./engine.js";
import { recordFailure } from "./refunds.js";

process.on("uncaughtException", (err) => console.error("uncaughtException:", err));
process.on("unhandledRejection", (err) => console.error("unhandledRejection:", err));

const app = express();
app.use(express.json({ limit: "2mb" }));

app.get("/health", (_req, res) => {
  res.json({ status: "ok", service: "argus", model: config.model });
});

// Kick the audit off in the background. Never throws into the request path.
// One retry on a thrown failure (sandbox crash, transient API error) before
// giving up — reduces how often a paid job actually needs a refund. If both
// attempts fail, the payment already settled on job acceptance (see README
// §Security notes), so it goes in the refund ledger for a human to process —
// this service can't send funds itself.
async function startAudit(
  jobId: string,
  scope: unknown,
  caps: EngineCaps,
  tier: "attack" | "triage",
  payer: string,
  amountBaseUnits: string
): Promise<void> {
  updateJob(jobId, { status: "running" });
  for (let attempt = 1; attempt <= 2; attempt++) {
    try {
      const { report, meta } = await runAudit(jobId, scope, caps);
      updateJob(jobId, { status: "done", report, meta });
      return;
    } catch (err) {
      const message = (err as Error).message;
      console.error(`[audit ${jobId}] attempt ${attempt} failed:`, err);
      if (attempt === 2) {
        updateJob(jobId, { status: "failed", error: message });
        recordFailure({ jobId, payer, amountBaseUnits, tier, reason: message });
      }
    }
  }
}

function validateScope(scope: unknown): string | null {
  const s = scope as Record<string, unknown> | undefined;
  const hasTarget = s && (s.repo || s.addresses || s.source || s.bytecode);
  if (!hasTarget) {
    return "scope must include at least one of: repo (git URL), addresses (+chain/explorer), source (inline Solidity), or bytecode (raw hex, e.g. for a not-yet-deployed or unverified contract).";
  }
  if (s?.source && String(s.source).length > config.maxInputScopeChars) {
    return `inline source exceeds ${config.maxInputScopeChars} chars; submit a repo instead.`;
  }
  if (s?.bytecode && String(s.bytecode).length > config.maxInputScopeChars) {
    return `bytecode exceeds ${config.maxInputScopeChars} chars.`;
  }
  return null;
}

// Shared handler for both priced tiers — same scope shape, different caps and poll prefix.
function makeAuditRoute(pollPrefix: string, tier: "attack" | "triage", caps: EngineCaps) {
  return (req: express.Request, res: express.Response) => {
    console.log(`[renegade] paid ${pollPrefix} request received`);
    const scope = req.body?.scope ?? req.body;

    const error = validateScope(scope);
    if (error) {
      res.status(400).json({ error });
      return;
    }

    // Payment already verified by the middleware — this just reads back who
    // paid and how much, for the refund ledger if the job later fails.
    let payer = "unknown";
    let amountBaseUnits = "unknown";
    try {
      ({ payer, amountBaseUnits } = paymentInfoOf(req));
    } catch (err) {
      console.error(`[renegade] could not read payer info for a paid request:`, err);
    }

    const job = createJob(scope);
    void startAudit(job.id, scope, caps, tier, payer, amountBaseUnits);

    res.status(202).json({
      jobId: job.id,
      status: job.status,
      poll: `/${pollPrefix}/${job.id}`,
      note: "Audit running. Poll the `poll` URL until status is 'done' or 'failed'.",
    });
  };
}

// Paid entrypoints. Payment middleware runs first — unpaid requests get a 402
// and never reach the handler (so the audit engine only ever runs for a
// settled payment).
app.post(
  "/attack",
  auditPaymentMiddleware,
  makeAuditRoute("attack", "attack", {
    maxToolIterations: config.maxToolIterations,
    maxWallclockSec: config.maxWallclockSec,
    mode: "full",
  })
);
app.post(
  "/triage",
  auditPaymentMiddleware,
  makeAuditRoute("triage", "triage", {
    maxToolIterations: config.triageMaxToolIterations,
    maxWallclockSec: config.triageMaxWallclockSec,
    mode: "triage",
  })
);

// x402 convention: non-POST to a paid endpoint → 405, not a generic 404.
app.all("/attack", (_req, res) => {
  res.set("Allow", "POST").status(405).json({ error: "method not allowed, use POST" });
});
app.all("/triage", (_req, res) => {
  res.set("Allow", "POST").status(405).json({ error: "method not allowed, use POST" });
});

app.get("/attack/:jobId", (req, res) => {
  const job = getJob(req.params.jobId);
  if (!job) {
    res.status(404).json({ error: "job not found" });
    return;
  }
  res.json(publicView(job));
});
app.get("/triage/:jobId", (req, res) => {
  const job = getJob(req.params.jobId);
  if (!job) {
    res.status(404).json({ error: "job not found" });
    return;
  }
  res.json(publicView(job));
});

app.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error("route error:", err);
  if (!res.headersSent) res.status(500).json({ error: "internal error" });
});

app.listen(config.port, () => {
  console.log(`Renegade listening on port ${config.port} (model=${config.model}, price=${config.price})`);
});
