// Calls Argus's actual audit engine directly, bypassing the HTTP layer and
// x402 payment gate entirely — same code that's deployed, just invoked
// locally so we can test the engine's audit quality without needing real
// or testnet payment tokens.
import { runAudit } from "./dist/engine.js";

const scope = {
  addresses: {
    "eip155:1952": [
      "0x0F28a5FF519A72135008f1618108d4BdaeB3b1Cb", // VulnerableVault
      "0x2bc4855c79888cED0567D25986a71F972e8AE812", // SafeVault
    ],
  },
  chain: { network: "eip155:1952", rpcUrl: "https://testrpc.xlayer.tech" },
  notes:
    "Two deployed contracts on X Layer testnet, identical deposit()/withdraw()/balanceOf() interface. " +
    "One or both may contain a real vulnerability — determine which, independently, for each.",
};

console.log("Running Argus engine locally against both testnet contracts...\n");
const result = await runAudit("local-test-" + Date.now(), scope);

console.log("=== META ===");
console.log(JSON.stringify(result.meta, null, 2));
console.log("\n=== REPORT ===");
console.log(JSON.stringify(result.report, null, 2));
