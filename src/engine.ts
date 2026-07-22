// The Renegade audit engine: an Anthropic tool-use loop that runs the bug-hunt
// methodology autonomously against a submitted scope, bounded by hard caps
// (iterations / wall-clock / tokens) so one job can't eat the fee.
//
// Two tools:
//   bash          — the only investigation surface (git/forge/cast/curl/jq),
//                   executed inside the per-job Sandbox.
//   submit_report — the forced terminal output (structured findings), same
//                   forced-tool pattern Fit Check uses for its verdict.

import Anthropic from "@anthropic-ai/sdk";
import { config } from "./config.js";
import { ARGUS_SYSTEM_PROMPT } from "./prompt.js";
import { Sandbox } from "./sandbox.js";
import type { AuditReport } from "./jobs.js";

const anthropic = new Anthropic(); // reads ANTHROPIC_API_KEY

const BASH_TOOL: Anthropic.Tool = {
  name: "bash",
  description:
    "Run a bash command inside your sandboxed audit workspace (cwd is a fresh throwaway dir). Foundry (forge/cast/anvil), git, node, curl, jq are available. ffi is disabled. Use this for everything: clone repos, fetch verified source from explorer APIs, compile, write and run Foundry PoCs (forge test), inspect on-chain state (cast). Output is truncated at 60KB per stream.",
  input_schema: {
    type: "object",
    properties: { command: { type: "string", description: "the bash command to run" } },
    required: ["command"],
  },
};

const SUBMIT_REPORT_TOOL: Anthropic.Tool = {
  name: "submit_report",
  description: "Submit the final audit report. Call this exactly once when the audit is complete or you are near your budget cap.",
  input_schema: {
    type: "object",
    properties: {
      findings: {
        type: "array",
        items: {
          type: "object",
          properties: {
            severity: { type: "string", enum: ["Critical", "High", "Medium", "Low", "Informational"] },
            likelihood: { type: "string", enum: ["Very High", "High", "Medium", "Low"] },
            title: { type: "string" },
            affected: { type: "string", description: "function / file / contract" },
            description: { type: "string", description: "the vulnerability and why it exists" },
            attack_path: { type: "string", description: "step-by-step exploitation" },
            poc: { type: "string", description: "the Foundry PoC and its result, or why none was built" },
            recommendation: { type: "string" },
          },
          required: ["severity", "likelihood", "title", "affected", "description", "attack_path", "recommendation"],
        },
      },
      killed_leads: { type: "string", description: "hypotheses disproved and why (required)" },
      coverage: { type: "string", description: "what was audited / sampled / not reached" },
      summary: { type: "string", description: "one-paragraph verdict" },
    },
    required: ["findings", "killed_leads", "coverage", "summary"],
  },
};

/** Turn the buyer's submitted scope into the opening user message. */
function scopeToPrompt(scope: unknown): string {
  const s = scope as Record<string, unknown>;
  const lines: string[] = ["Audit the following scope. Begin by orienting yourself, then hunt.\n"];
  if (s.repo) lines.push(`Repository: ${s.repo}${s.commit ? ` @ ${s.commit}` : ""}`);
  if (s.addresses) lines.push(`On-chain addresses: ${JSON.stringify(s.addresses)}`);
  if (s.chain) lines.push(`Chain / RPC: ${JSON.stringify(s.chain)}`);
  if (s.explorer) lines.push(`Explorer API base: ${s.explorer}`);
  if (s.source) lines.push(`Inline source provided (see below).`);
  if (s.bytecode) lines.push(`Raw bytecode provided (see below) — not yet deployed, or deployed but unverified.`);
  if (s.notes) lines.push(`Notes from submitter: ${s.notes}`);
  if (s.source) lines.push("\n--- SUBMITTED SOURCE ---\n" + String(s.source));
  if (s.bytecode) lines.push("\n--- SUBMITTED BYTECODE ---\n" + String(s.bytecode));
  return lines.join("\n");
}

export interface EngineResult {
  report: AuditReport;
  meta: { iterations: number; wallclockSec: number; model: string; hitCap: boolean };
}

export async function runAudit(jobId: string, scope: unknown): Promise<EngineResult> {
  const sandbox = new Sandbox(jobId);
  const startedAt = Date.now();
  const messages: Anthropic.MessageParam[] = [{ role: "user", content: scopeToPrompt(scope) }];

  let iterations = 0;
  let hitCap = false;

  try {
    while (true) {
      const wallclockSec = (Date.now() - startedAt) / 1000;
      const overIterations = iterations >= config.maxToolIterations;
      const overTime = wallclockSec >= config.maxWallclockSec;

      // When over budget, force the model to wrap up with a report on this turn.
      const forceReport = overIterations || overTime;
      if (forceReport) hitCap = true;

      const resp = await anthropic.messages.create({
        model: config.model,
        max_tokens: config.maxOutputTokensPerTurn,
        system:
          ARGUS_SYSTEM_PROMPT +
          (forceReport
            ? "\n\n[BUDGET REACHED] You are out of budget. Call submit_report NOW with whatever you have."
            : `\n\n[BUDGET] iteration ${iterations}/${config.maxToolIterations}, ${Math.round(
                wallclockSec
              )}s/${config.maxWallclockSec}s elapsed.`),
        tools: [BASH_TOOL, SUBMIT_REPORT_TOOL],
        tool_choice: forceReport ? { type: "tool", name: "submit_report" } : { type: "auto" },
        messages,
      });

      iterations++;
      messages.push({ role: "assistant", content: resp.content });

      const toolUses = resp.content.filter((b): b is Anthropic.ToolUseBlock => b.type === "tool_use");

      // No tool call (model just talked) — nudge it to use tools or report.
      if (toolUses.length === 0) {
        messages.push({
          role: "user",
          content: "Use the bash tool to investigate, or call submit_report if you are done.",
        });
        continue;
      }

      const reportCall = toolUses.find((t) => t.name === "submit_report");
      if (reportCall) {
        const report = reportCall.input as AuditReport;
        return {
          report,
          meta: { iterations, wallclockSec: (Date.now() - startedAt) / 1000, model: config.model, hitCap },
        };
      }

      // Execute every bash tool_use and feed results back.
      const results: Anthropic.ToolResultBlockParam[] = [];
      for (const t of toolUses) {
        if (t.name !== "bash") {
          results.push({ type: "tool_result", tool_use_id: t.id, content: "unknown tool", is_error: true });
          continue;
        }
        const cmd = String((t.input as { command?: string }).command ?? "");
        const out = await sandbox.run(cmd);
        const body =
          `exit=${out.code}${out.timedOut ? " (TIMED OUT / killed)" : ""}\n` +
          `--- stdout ---\n${out.stdout}\n--- stderr ---\n${out.stderr}`;
        results.push({ type: "tool_result", tool_use_id: t.id, content: body });
      }
      messages.push({ role: "user", content: results });
    }
  } finally {
    sandbox.cleanup();
  }
}
