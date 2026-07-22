# Renegade

Adversarial smart-contract security auditor, packaged as an x402-paid A2MCP agent on X Layer.

Submit a scope → Renegade runs a **full agentic audit** (live-code review + Foundry PoCs) inside a sandboxed container → returns a severity-rated findings report. Same methodology as the `bug-hunt` skill: audit the deployed bytecode not the docs, kill false positives before claiming them, prove every real bug with a runnable PoC.

## How it works

Three layers (the model every ASP here uses):

1. **This backend (Railway)** — runs the audit by driving a Claude tool-use loop with Foundry/cast/git/curl in the container.
2. **x402 payment** enforced at `POST /attack` (USD₮0 on X Layer, `eip155:196`). Unpaid requests get a 402; the engine only runs for settled payments.
3. **ERC-8004 listing** on OKX.AI pointing at this endpoint — discovery, identity, reviews, liveness heartbeat.

## API

| Method & path | Description |
|---|---|
| `GET /health` | Liveness (marketplace heartbeat). |
| `POST /attack` | **x402-gated.** Body: `{ scope }`. On payment, queues a job → `202 { jobId, poll }`. |
| `GET /attack/:jobId` | Poll status; returns the report when `status: "done"`. |

### Scope shape

Provide at least one target:

```json
{
  "scope": {
    "repo": "https://github.com/org/repo",     "commit": "optional sha",
    "addresses": ["0x..."],                     "chain": { "rpc": "https://...", "id": 196 },
    "explorer": "https://<blockscout-host>/api/v2",
    "source": "// inline Solidity (alternative to repo)",
    "bytecode": "0x608060... (alternative to repo/address — e.g. not-yet-deployed or unverified)",
    "notes": "anything the submitter wants Renegade to know / known-issues doc URL"
  }
}
```

## Config (env — set on Railway, never commit)

See `.env.example`. Required: `ANTHROPIC_API_KEY`, `PAY_TO_ADDRESS`, `OKX_API_KEY`/`OKX_SECRET_KEY`/`OKX_PASSPHRASE`. Caps (`MAX_TOOL_ITERATIONS`, `MAX_WALLCLOCK_SEC`, …) bound per-job cost so a single audit can't exceed the fee.

## Security notes

- The engine runs Foundry against **attacker-supplied** contracts. Each job gets a throwaway workspace; the child env is **scrubbed of all secrets**; foundry `ffi` is disabled. The container holds no keys of value. A hardened deployment would add a per-job microVM (gVisor/Firecracker) — documented as a v1 limitation.
- Payment settles on job acceptance (charge-on-accept). A failed audit still consumed the fee in v1; a refund path is future work.

## Local dev

```bash
cp .env.example .env   # fill in keys
npm install
npm run dev            # tsx watch
# unpaid probe should 402:
curl -s -X POST localhost:3000/attack -H 'content-type: application/json' -d '{"scope":{"source":"contract C{}"}}' -i | head -1
```
