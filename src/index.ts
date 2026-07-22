// Renegade HTTP service.
//   GET  /health          — liveness (marketplace heartbeat)
//   POST /audit           — x402-gated; on payment, queues an audit job, returns { jobId }
//   GET  /audit/:jobId     — poll job status / retrieve the finished report
//
// The audit is a multi-minute agentic job, so POST returns immediately (202)
// after payment settles and the work runs in the background — unlike Fit
// Check's synchronous single call.

import express from "express";
import { config } from "./config.js";
import { auditPaymentMiddleware } from "./payment.js";
import { createJob, getJob, updateJob, publicView } from "./jobs.js";
import { runAudit } from "./engine.js";

process.on("uncaughtException", (err) => console.error("uncaughtException:", err));
process.on("unhandledRejection", (err) => console.error("unhandledRejection:", err));

const app = express();
app.use(express.json({ limit: "2mb" }));

app.get("/health", (_req, res) => {
  res.json({ status: "ok", service: "argus", model: config.model });
});

// Kick the audit off in the background. Never throws into the request path.
function startAudit(jobId: string, scope: unknown): void {
  updateJob(jobId, { status: "running" });
  runAudit(jobId, scope)
    .then(({ report, meta }) => updateJob(jobId, { status: "done", report, meta }))
    .catch((err) => {
      console.error(`[audit ${jobId}] failed:`, err);
      updateJob(jobId, { status: "failed", error: (err as Error).message });
    });
}

// Paid entrypoint. Payment middleware runs first — unpaid requests get a 402
// and never reach this handler (so the audit engine only ever runs for a
// settled payment).
app.post("/audit", auditPaymentMiddleware, (req, res) => {
  console.log("[argus] paid audit request received");
  const scope = req.body?.scope ?? req.body;

  // Basic scope validation — must give us something to audit.
  const s = scope as Record<string, unknown> | undefined;
  const hasTarget = s && (s.repo || s.addresses || s.source);
  if (!hasTarget) {
    res.status(400).json({
      error:
        "scope must include at least one of: repo (git URL), addresses (+chain/explorer), or source (inline Solidity).",
    });
    return;
  }
  if (s?.source && String(s.source).length > config.maxInputScopeChars) {
    res.status(400).json({ error: `inline source exceeds ${config.maxInputScopeChars} chars; submit a repo instead.` });
    return;
  }

  const job = createJob(scope);
  startAudit(job.id, scope);

  res.status(202).json({
    jobId: job.id,
    status: job.status,
    poll: `/audit/${job.id}`,
    note: "Audit running. Poll the `poll` URL until status is 'done' or 'failed'.",
  });
});

// x402 convention: non-POST to a paid endpoint → 405, not a generic 404.
app.all("/audit", (_req, res) => {
  res.set("Allow", "POST").status(405).json({ error: "method not allowed, use POST" });
});

app.get("/audit/:jobId", (req, res) => {
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
