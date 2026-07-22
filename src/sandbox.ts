// Per-job sandbox: an isolated workspace directory + a constrained bash runner.
//
// This is the security boundary for running foundry/git/cast against
// ATTACKER-SUPPLIED contracts and repos. It is defense-in-depth on top of the
// container itself (the Railway container is ephemeral and holds no user funds):
//   - each job gets its own throwaway working dir under WORKSPACE_ROOT
//   - commands run with cwd pinned to that dir, and HOME/TMPDIR are pinned
//     there too, so a command can't read/write the default home dir or drop
//     temp files anywhere outside the workspace
//   - the child process env is SCRUBBED of all secrets (no ANTHROPIC/OKX keys
//     ever reach code compiled or executed from the audit target)
//   - a per-command timeout kills runaway/forking processes, plus ulimit caps
//     on memory, process count (fork-bomb guard), and file size
//   - foundry ffi is disabled via a workspace foundry.toml (blocks forge's
//     host-command-execution cheatcode), and the prompt forbids re-enabling it
//
// NOTE (documented limitation): this is still process-level isolation, not a
// real container/VM boundary — a determined command still shares the host
// kernel and can read most world-readable files, and network egress is
// required (fetch verified source, fork RPCs) so it is not blocked. Because
// secrets are scrubbed from the child env and the container holds no keys of
// value, this is judged acceptable for v1. A stricter deployment would run
// each job in a gVisor/Firecracker microVM or a managed sandboxing service.

import { spawn } from "node:child_process";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { config } from "./config.js";

// Env vars that must NEVER be visible to sandboxed processes.
const SECRET_KEYS = [
  "ANTHROPIC_API_KEY",
  "OKX_API_KEY",
  "OKX_SECRET_KEY",
  "OKX_PASSPHRASE",
  "PAY_TO_ADDRESS",
];

/** A minimal, secret-free env for the sandbox child, pinned to its own workspace. */
function scrubbedEnv(workspaceDir: string): NodeJS.ProcessEnv {
  const clean: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (SECRET_KEYS.includes(k)) continue;
    if (/KEY|SECRET|TOKEN|PASSPHRASE|MNEMONIC|PRIVATE/i.test(k)) continue; // belt & suspenders
    clean[k] = v;
  }
  clean.FOUNDRY_FFI = "false"; // hard off, in addition to foundry.toml
  // Pin HOME/TMPDIR into the workspace so nothing reads/writes outside it —
  // otherwise tools default to the real container HOME (e.g. ~/.foundry state,
  // stray dotfiles) which isn't cleaned up per-job.
  clean.HOME = workspaceDir;
  clean.TMPDIR = workspaceDir;
  return clean;
}

/** ulimit caps applied to every bash call — bounds one command's blast radius
 * even though this isn't full container isolation (see file header). */
function resourceLimitPrefix(): string {
  return [
    `ulimit -v ${config.sandboxMaxMemoryKb}`, // virtual memory
    `ulimit -u ${config.sandboxMaxProcesses}`, // process count — fork-bomb guard
    `ulimit -f ${config.sandboxMaxFileSizeKb}`, // max single-file size
    `ulimit -c 0`, // no core dumps
  ].join("; ") + "; ";
}

export class Sandbox {
  readonly dir: string;

  constructor(jobId: string) {
    this.dir = resolve(join(config.workspaceRoot, jobId));
    mkdirSync(this.dir, { recursive: true });
    // Pin foundry config: ffi off, so `forge` can't run host commands on behalf
    // of a malicious target's test/script.
    writeFileSync(
      join(this.dir, "foundry.toml"),
      `[profile.default]\nffi = false\nfs_permissions = [{ access = "read-write", path = "./" }]\n`
    );
  }

  /** Run one bash command inside the workspace. Returns combined output, truncated. */
  run(command: string): Promise<{ stdout: string; stderr: string; code: number | null; timedOut: boolean }> {
    return new Promise((resolvePromise) => {
      // NOT "-lc" (login shell): verified directly against the deployed container
      // that a login shell re-sources /etc/profile and drops the Docker-ENV PATH
      // entry for /root/.foundry/bin, so `forge`/`cast`/`anvil` fail to resolve —
      // "-c" (non-login) correctly inherits the passed-in env's PATH.
      const child = spawn("bash", ["-c", resourceLimitPrefix() + command], {
        cwd: this.dir,
        env: scrubbedEnv(this.dir),
        timeout: config.bashTimeoutMs,
        killSignal: "SIGKILL",
      });

      let stdout = "";
      let stderr = "";
      const CAP = 60_000; // cap each stream so a noisy build can't blow up the context
      child.stdout.on("data", (d) => {
        if (stdout.length < CAP) stdout += d.toString();
      });
      child.stderr.on("data", (d) => {
        if (stderr.length < CAP) stderr += d.toString();
      });

      child.on("close", (code, signal) => {
        resolvePromise({
          stdout: stdout.slice(0, CAP),
          stderr: stderr.slice(0, CAP),
          code,
          timedOut: signal === "SIGKILL",
        });
      });
      child.on("error", (err) => {
        resolvePromise({ stdout, stderr: stderr + "\n" + err.message, code: null, timedOut: false });
      });
    });
  }

  cleanup(): void {
    try {
      rmSync(this.dir, { recursive: true, force: true });
    } catch {
      /* best effort */
    }
  }
}
