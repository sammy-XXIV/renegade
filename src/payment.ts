// x402 payment enforcement for Renegade — same proven pattern as Fit Check's
// payment.ts (OKXFacilitatorClient + x402ResourceServer + ExactEvmScheme +
// paymentMiddleware). Two priced routes: POST /attack (full attack simulation)
// and POST /triage (cheap, fast preliminary scan, same engine, shorter cap).
//
// Unpaid/unsigned requests get a 402 and never reach the handler, so the
// (expensive) audit engine only runs for paid jobs.

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
