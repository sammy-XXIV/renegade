// x402 payment enforcement for Renegade — same proven pattern as Fit Check's
// payment.ts (OKXFacilitatorClient + x402ResourceServer + ExactEvmScheme +
// paymentMiddleware). Two priced routes: POST /attack (full attack simulation)
// and POST /triage (cheap, fast preliminary scan, same engine, shorter cap).
//
// Unpaid/unsigned requests get a 402 and never reach the handler, so the
// (expensive) audit engine only runs for paid jobs.

import type express from "express";
import { paymentMiddleware, x402ResourceServer } from "@okxweb3/x402-express";
import { ExactEvmScheme } from "@okxweb3/x402-evm/exact/server";
import { OKXFacilitatorClient } from "@okxweb3/x402-core";
import { config, assertPaymentEnv } from "./config.js";

assertPaymentEnv();

type CaipNetwork = `${string}:${string}`;

const facilitatorClient = new OKXFacilitatorClient({
  apiKey: process.env.OKX_API_KEY!,
  secretKey: process.env.OKX_SECRET_KEY!,
  passphrase: process.env.OKX_PASSPHRASE!,
});

const resourceServer = new x402ResourceServer(facilitatorClient);
resourceServer.register(config.network as CaipNetwork, new ExactEvmScheme());

export const auditPaymentMiddleware = paymentMiddleware(
  {
    "POST /attack": {
      accepts: [
        {
          scheme: "exact",
          network: config.network as CaipNetwork,
          payTo: config.payTo!,
          price: config.price,
        },
      ],
      description:
        "Renegade hires itself out as your attacker. Submit a deployed address, a git repo, raw bytecode, or inline source — it compiles or decodes what it's given, and attacks it from a hacker's perspective: forking the live chain and running real exploit code against the actual bytecode, not just reading it for red flags. Every finding comes with the executed Foundry PoC that proved it, rated by severity and likelihood, plus the hypotheses it tried and ruled out. No source code required — works directly from a contract address or raw bytecode. " +
        "Checks: reentrancy, access control, missing authorization, integer issues, precision loss, flash loan attacks, oracle manipulation, front-running, MEV exploits, signature replay, permit misuse, timestamp manipulation, governance attacks, economic exploits, griefing attacks, DoS attacks, state desynchronization, upgradeability issues, storage collisions, initialization flaws, unchecked external calls, ERC20 non-standard behavior, token inflation, reward accounting bugs, liquidity manipulation, cross-chain assumptions, and insolvency risks.",
      mimeType: "application/json",
    },
    "POST /triage": {
      accepts: [
        {
          scheme: "exact",
          network: config.network as CaipNetwork,
          payTo: config.payTo!,
          price: config.triagePrice,
        },
      ],
      description:
        "Quick Risk Triage — a fast, cheap preliminary read from Renegade before you commit to the full attack simulation. Same engine, same scope input (deployed address, repo, bytecode, or source), a few minutes instead of twenty. Flags the highest-risk red flags with reasoning, not full executed Foundry PoCs — if it flags something real, run the full attack simulation for proof.",
      mimeType: "application/json",
    },
  },
  resourceServer
);

/**
 * Payer address + settled amount, for the refund ledger. Same proven approach
 * as Frank's payerOf (verified against the installed SDK — the express
 * middleware's exact-scheme path doesn't attach payment context to `req`):
 * read it back from the PAYMENT-SIGNATURE header the middleware already
 * verified. The EIP-3009 authorization's `from` is the paying wallet;
 * `accepted.amount` is the settled amount in base units.
 */
export function paymentInfoOf(req: express.Request): { payer: string; amountBaseUnits: string } {
  const header = req.header("payment-signature") ?? req.header("x-payment");
  if (!header) throw new Error("no verified payment on request");
  const payload = JSON.parse(Buffer.from(header, "base64").toString("utf8")) as {
    payload?: { authorization?: { from?: string } };
    accepted?: { amount?: string };
  };
  const from = payload?.payload?.authorization?.from;
  const amount = payload?.accepted?.amount;
  if (!from || !amount) throw new Error("payment payload missing payer or amount");
  return { payer: from.toLowerCase(), amountBaseUnits: amount };
}
