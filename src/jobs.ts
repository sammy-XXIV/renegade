// Minimal async job store. Payment settles on the POST /audit response (2xx),
// then the audit runs in the background; the buyer polls GET /audit/:jobId.
// Persisted to a JSON file so a restart doesn't lose in-flight results.
// Swap for a real DB (Postgres on a Railway plugin) when volume warrants it.

import { randomUUID } from "node:crypto";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { config } from "./config.js";

export type JobStatus = "queued" | "running" | "done" | "failed";

export interface AuditReport {
  findings: unknown[];
  killed_leads: unknown;
  coverage: unknown;
  summary: string;
}

export interface Job {
  id: string;
  status: JobStatus;
  createdAt: number;
  updatedAt: number;
  scope: unknown; // the buyer's submitted scope (repo / addresses / source)
  report?: AuditReport;
  error?: string;
  meta?: Record<string, unknown>; // iterations used, wallclock, model, etc.
}

const jobs = new Map<string, Job>();

function persist(): void {
  try {
    writeFileSync(config.jobsFile, JSON.stringify([...jobs.values()], null, 2));
  } catch (err) {
    console.error("[jobs] persist failed:", (err as Error).message);
  }
}

function load(): void {
  if (!existsSync(config.jobsFile)) return;
  try {
    const arr = JSON.parse(readFileSync(config.jobsFile, "utf8")) as Job[];
    for (const j of arr) {
      // Any job left mid-run by a restart is marked failed — it can't resume.
      if (j.status === "running" || j.status === "queued") {
        j.status = "failed";
        j.error = "interrupted by service restart";
      }
      jobs.set(j.id, j);
    }
  } catch (err) {
    console.error("[jobs] load failed:", (err as Error).message);
  }
}
load();

export function createJob(scope: unknown): Job {
  const now = Date.now();
  const job: Job = { id: randomUUID(), status: "queued", createdAt: now, updatedAt: now, scope };
  jobs.set(job.id, job);
  persist();
  return job;
}

export function getJob(id: string): Job | undefined {
  return jobs.get(id);
}

export function updateJob(id: string, patch: Partial<Job>): void {
  const job = jobs.get(id);
  if (!job) return;
  Object.assign(job, patch, { updatedAt: Date.now() });
  persist();
}

/** Public view — never leak internal fields the buyer shouldn't see. */
export function publicView(job: Job) {
  return {
    jobId: job.id,
    status: job.status,
    createdAt: job.createdAt,
    updatedAt: job.updatedAt,
    ...(job.report ? { report: job.report } : {}),
    ...(job.error ? { error: job.error } : {}),
    ...(job.meta ? { meta: job.meta } : {}),
  };
}
