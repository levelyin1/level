// Dev evidence tool: probes the official gatekeeper circuit's boundary
// conditions with real fullProve round-trips. Results: circuits/PROBE.md.
// Usage: node scripts/probe-boundary.mjs (requires downloaded artifacts)
import * as snarkjs from "snarkjs";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const WASM = path.join(ROOT, "circuits/artifacts/gatekeeper.wasm");
const ZKEY = path.join(ROOT, "circuits/artifacts/gatekeeper_final.zkey");
const VK = fs.readFileSync(path.join(ROOT, "circuits/gatekeeper.vkey.json"), "utf8");
const vkey = JSON.parse(VK);
const base = {
  registeredVkHash: "123", proofVkHash: "123", minimum: "1000", publicBalance: "1460",
  expiryBlock: "8430000", currentBlock: "8420000",
  recipient: "111", conditionRecipient: "111", amount: "500", maxTransfer: "1000",
  taskId: "42", salt: "7",
};
async function tryProve(label, inputs) {
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, WASM, ZKEY);
    const ok = await snarkjs.groth16.verify(vkey, publicSignals, proof);
    console.log(label, "=> WITNESS OK, verify:", ok, "| signals[1..12]:", JSON.stringify(publicSignals.slice(1)));
    console.log("   signal0 (Poseidon commitment):", publicSignals[0]);
  } catch (e) {
    console.log(label, "=> WITNESS FAILED:", String(e.message || e).split("\n")[0]);
  }
}
await tryProve("A: all-true decision=1", { ...base, decision: "1" });
await tryProve("B: current==expiry decision=1", { ...base, currentBlock: "8430000", decision: "1" });
await tryProve("C: current==expiry decision=0", { ...base, currentBlock: "8430000", decision: "0" });
await tryProve("D: amount=0 decision=1", { ...base, amount: "0", decision: "1" });
await tryProve("E: amount=0 decision=0", { ...base, amount: "0", decision: "0" });
await tryProve("F: amount>max decision=0", { ...base, amount: "1500", decision: "0" });
await tryProve("G: amount>max decision=1", { ...base, amount: "1500", decision: "1" });
await tryProve("H: all-true decision=0 (wrong)", { ...base, decision: "0" });
await tryProve("I: salt changed, signal0 moves?", { ...base, decision: "1", salt: "8" });
process.exit(0);
