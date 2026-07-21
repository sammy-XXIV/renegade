// x402 payment enforcement for Argus — same proven pattern as Fit Check's
// payment.ts (OKXFacilitatorClient + x402ResourceServer + ExactEvmScheme +
// paymentMiddleware), pointed at POST /audit at the configured price.
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
    "POST /audit": {
      accepts: [
        {
          scheme: "exact",
          network: config.network as CaipNetwork,
          payTo: config.payTo!,
          price: config.price,
        },
      ],
      description:
        "Adversarial smart-contract security audit. Submit a scope (repo, contract addresses + chain, or source); Argus runs a live-code review with Foundry PoCs and returns a severity-rated findings report.",
      mimeType: "application/json",
    },
  },
  resourceServer
);
