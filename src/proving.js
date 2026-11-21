"use strict";
/**
 * proving.js — Groth16 proof generation (snarkjs) + Steal publicInputsHash.
 *
 * Uses the PLATFORM's official published circuits (see SPEC.md). No local
 * Circom build, no trusted setup — the platform publishes the .wasm/.zkey
 * artifacts and we prove with snarkjs.
 *
 * Gatekeeper input names (13/13, recovered from the official artifacts by
 * probing the .wasm and verified by live fullProve + local-verify
 * round-trips — see circuits/PROBE.md):
 *   registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
 *   currentBlock, recipient, conditionRecipient, amount, maxTransfer,
 *   decision, taskId, salt (salt is the only private input).
 * Public-signal order:
 *   [Poseidon(salt, taskId), registeredVkHash, proofVkHash, minimum,
 *    publicBalance, expiryBlock, currentBlock, recipient,
 *    conditionRecipient, amount, maxTransfer, decision, taskId].
 *
 * vfyPolicy (Steal): only 9 of 17 input names are recoverable from the
 * published material; the 8 private policy input names are NOT published
 * and cannot be guessed. generateProof("steal") therefore throws an honest
 * error — never a fake proof. The Steal response still carries the
 * published publicInputsHash, which the platform can check without a proof.
 *
 * snarkjs is lazy-required on first use: the first require is slow and the
 * server must answer health checks immediately at startup.
 */
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { keccak_256 } = require("@noble/hashes/sha3");
const { bytesToHex } = require("@noble/hashes/utils");
const { normalizeGatekeeperInput, evaluateCircuitConditions } = require("./gatekeeper");

/** Published platform vkHashes (public constants from /api/circuit-info). */
const PUBLISHED_VK_HASH = {
  gatekeeper: "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
  vfyPolicy: "0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047",
};

const TRACK_FILES = {
  gatekeeper: {
    wasm: "gatekeeper.wasm",
    zkey: "gatekeeper_final.zkey",
    vkey: "gatekeeper.vkey.json",
    circuit: "gatekeeper",
  },
  steal: {
    wasm: "vfy-policy.wasm",
    zkey: "vfy-policy_final.zkey",
    vkey: "vfy-policy.vkey.json",
    circuit: "vfyPolicy",
  },
};

let snarkjsModule = null;
function snarkjs() {
  if (!snarkjsModule) snarkjsModule = require("snarkjs");
  return snarkjsModule;
}

/**
 * Resolve the artifacts directory. Order:
 *  1. $CIRCUIT_DIR (resolved against cwd if relative)
 *  2. <repo-root>/circuits/artifacts
 */
function resolveArtifactDir() {
  const candidates = [];
  if (process.env.CIRCUIT_DIR) candidates.push(path.resolve(process.env.CIRCUIT_DIR));
  candidates.push(path.resolve(__dirname, "..", "circuits", "artifacts"));
  for (const dir of candidates) {
    if (fs.existsSync(path.join(dir, "gatekeeper.wasm"))) return dir;
  }
  return candidates[0];
}

/** Committed verification keys live in circuits/ (not artifacts/). */
function resolveVkeyPath(circuit) {
  return path.resolve(__dirname, "..", "circuits", TRACK_FILES[circuit].vkey);
}

/** Read the published vkHash from circuit-info.json, falling back to the
 * hardcoded published constant (same value) if the file is unreadable. */
function publishedVkHash(circuit) {
  try {
    const info = JSON.parse(
      fs.readFileSync(path.join(resolveArtifactDir(), "circuit-info.json"), "utf8"),
    );
    const h = info.circuits && info.circuits[circuit] && info.circuits[circuit].vkHash;
    if (typeof h === "string" && h.startsWith("0x")) return h;
  } catch {
    // fall through to the published constant below
  }
  return PUBLISHED_VK_HASH[circuit];
}

function toFieldString(value, field) {
  if (typeof value === "number") {
    if (!Number.isInteger(value) || value < 0) {
      throw new Error(`gatekeeper input ${field}: must be a non-negative integer, got ${value}`);
    }
    return BigInt(value).toString();
  }
  if (typeof value === "string") {
    const s = value.trim();
    if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s).toString();
    if (/^[0-9]+$/.test(s)) return BigInt(s).toString();
    throw new Error(
      `gatekeeper input ${field}: expected a decimal or 0x-hex integer, got ${JSON.stringify(value)}`,
    );
  }
  throw new Error(`gatekeeper input ${field}: expected a number or numeric string, got ${typeof value}`);
}

/**
 * taskId encoding (ASSUMPTION — the platform's encoding is unpublished):
 * a numeric string stays numeric; an alphanumeric id such as "gk_24_9d1"
 * is encoded as the big-endian integer of its UTF-8 bytes. The proof
 * verifies cryptographically for any field element; only the platform's
 * reading of public signal 12 depends on this encoding matching theirs.
 */
function taskIdToField(value) {
  if (typeof value === "number") {
    if (!Number.isInteger(value) || value < 0) {
      throw new Error(`gatekeeper input taskId: must be a non-negative integer, got ${value}`);
    }
    return BigInt(value).toString();
  }
  if (typeof value === "string") {
    const s = value.trim();
    if (s.length === 0) throw new Error("gatekeeper input taskId: empty string");
    if (/^[0-9]+$/.test(s)) return BigInt(s).toString();
    return BigInt(`0x${Buffer.from(s, "utf8").toString("hex")}`).toString();
  }
  throw new Error(`gatekeeper input taskId: expected a string or number, got ${typeof value}`);
}

/**
 * Translate envelope-style gatekeeper inputs into the circuit's 13 named
 * signals. Accepts envelope spellings (registered_vk, public_balance, ...)
 * and circuit spellings (registeredVkHash, publicBalance, ...).
 *
 * - proof_tx is DROPPED (not a circuit input).
 * - decision: explicit "APPROVE"/"REJECT"/1/0 wins; when absent it is
 *   DERIVED from the same rule as src/gatekeeper.js (evaluateCircuitConditions).
 *   Prefer passing the server's decision explicitly — derivation cannot see
 *   off-circuit reject reasons (e.g. PROOF_REUSED).
 * - salt: supplied value wins, otherwise a fresh random 31-byte field
 *   element is drawn per proof (private blinding for Poseidon(salt, taskId)).
 */
function buildGatekeeperCircuitInputs(input) {
  const pick = (...keys) => {
    for (const k of keys) if (input[k] !== undefined) return input[k];
    return undefined;
  };

  // Normalize through the shared gatekeeper rule so the circuit inputs and
  // the server's decision can never disagree about field values.
  const envelopeStyle = {
    registered_vk: pick("registeredVkHash", "registeredVk", "registered_vk"),
    proof_vk: pick("proofVkHash", "proofVk", "proof_vk"),
    minimum: pick("minimum"),
    public_balance: pick("publicBalance", "public_balance"),
    expiry_block: pick("expiryBlock", "expiry_block"),
    current_block: pick("currentBlock", "current_block"),
    recipient: pick("recipient"),
    condition_recipient: pick("conditionRecipient", "condition_recipient"),
    amount: pick("amount"),
    max_transfer: pick("maxTransfer", "max_transfer"),
  };
  const n = normalizeGatekeeperInput(envelopeStyle);

  const rawTaskId = pick("taskId", "task_id");
  if (rawTaskId === undefined) {
    throw new Error("gatekeeper inputs missing required field: taskId (task_id)");
  }

  const rawDecision = pick("decision");
  let decision;
  if (rawDecision === undefined) {
    decision = evaluateCircuitConditions(n) ? "1" : "0";
  } else if (rawDecision === "APPROVE" || rawDecision === 1 || rawDecision === "1") {
    decision = "1";
  } else if (rawDecision === "REJECT" || rawDecision === 0 || rawDecision === "0") {
    decision = "0";
  } else {
    throw new Error(
      `gatekeeper input decision: expected "APPROVE"/"REJECT"/1/0, got ${JSON.stringify(rawDecision)}`,
    );
  }

  const rawSalt = pick("salt");
  const salt =
    rawSalt === undefined
      ? BigInt(`0x${crypto.randomBytes(31).toString("hex")}`).toString()
      : toFieldString(rawSalt, "salt");

  return {
    registeredVkHash: n.registeredVk.toString(),
    proofVkHash: n.proofVk.toString(),
    minimum: n.minimum.toString(),
    publicBalance: n.publicBalance.toString(),
    expiryBlock: n.expiryBlock.toString(),
    currentBlock: n.currentBlock.toString(),
    recipient: n.recipient.toString(),
    conditionRecipient: n.conditionRecipient.toString(),
    amount: n.amount.toString(),
    maxTransfer: n.maxTransfer.toString(),
    decision,
    taskId: taskIdToField(rawTaskId),
    salt,
  };
}

/**
 * Generate a Groth16 proof for a track.
 * @param {{ track: "gatekeeper"|"steal", circuitInputs: object }} req
 * @returns {{ proof, publicSignals: string[], circuit, circuitVersion }}
 * @throws on missing artifacts, bad inputs, witness failure (a wrong
 * decision cannot produce a witness — the circuit asserts
 * decision == evaluated condition), or for "steal" (input names
 * unpublished — see module docs). A proof is never fabricated.
 */
async function generateProof(req) {
  const files = TRACK_FILES[req.track];
  if (!files) throw new Error(`unknown track: ${req.track}`);

  if (req.track === "steal") {
    throw new Error(
      "Steal (vfyPolicy) circuit input signal names are not fully published: " +
        "only 9 of 17 inputs are recoverable from the published material. " +
        "generateProof cannot build a valid witness until the platform " +
        "publishes the remaining private input names — see SPEC.md.",
    );
  }

  const dir = resolveArtifactDir();
  const wasmPath = path.join(dir, files.wasm);
  const zkeyPath = path.join(dir, files.zkey);
  for (const [label, p] of [["wasm", wasmPath], ["zkey", zkeyPath]]) {
    if (!fs.existsSync(p)) {
      throw new Error(
        `Missing ${req.track} circuit artifact (${label}): ${p}. Run: bash scripts/download-artifacts.sh`,
      );
    }
  }

  const circuitInputs = buildGatekeeperCircuitInputs(req.circuitInputs);
  const { proof, publicSignals } = await snarkjs().groth16.fullProve(
    circuitInputs,
    wasmPath,
    zkeyPath,
  );
  return {
    proof,
    publicSignals: publicSignals.map(String),
    circuit: files.circuit,
    circuitVersion: publishedVkHash(files.circuit),
  };
}

/**
 * Verify a Groth16 proof locally against the committed platform VK
 * (circuits/<circuit>.vkey.json). Used by tests and as a server sanity
 * check. Returns true only if snarkjs verification passes.
 */
async function verifyProofLocally(proof, publicSignals, circuit) {
  const vkeyPath = resolveVkeyPath(circuit);
  if (!fs.existsSync(vkeyPath)) {
    throw new Error(`Missing exported verification key: ${vkeyPath}`);
  }
  const vKey = JSON.parse(fs.readFileSync(vkeyPath, "utf8"));
  return snarkjs().groth16.verify(vKey, publicSignals, proof);
}

// ---------------------------------------------------------------------------
// Steal the VFY publicInputsHash (SPEC.md — published, use exactly)
// ---------------------------------------------------------------------------

const STEAL_ACTION_CODE = { HOLD: 0, FORTIFY: 1, EXTRACT: 2 };

/** Encode a BigInt as 32-byte big-endian. Throws on negative/overflow. */
function toBytes32BE(value, field) {
  if (value < 0n) throw new Error(`publicInputsHash: ${field} must be >= 0`);
  const out = new Uint8Array(32);
  let v = value;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) throw new Error(`publicInputsHash: ${field} exceeds 32 bytes`);
  return out;
}

function parseUintField(value, field) {
  if (typeof value === "number") {
    if (!Number.isInteger(value)) {
      throw new Error(`publicInputsHash: ${field} must be an integer`);
    }
    return BigInt(value);
  }
  const s = String(value).trim();
  if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
  if (/^[0-9]+$/.test(s)) return BigInt(s);
  throw new Error(`publicInputsHash: ${field} must be a decimal or 0x-hex integer, got ${JSON.stringify(value)}`);
}

/**
 * Compute the Steal the VFY publicInputsHash (SPEC.md, published).
 *
 * keccak256 over 8 fields, each 32-byte big-endian, in this exact order:
 *  1. strategyCommitment.hash (0x-hex, 32 bytes)
 *  2. matchId (hyphens stripped, parsed as an integer)
 *  3. turn
 *  4. selfBalance
 *  5. opponentBalance
 *  6. action (HOLD=0, FORTIFY=1, EXTRACT=2)
 *  7. amount (0 for HOLD/FORTIFY — forced, even if nonzero is passed)
 *  8. circuitVersion "v1" (=1; defaults to "v1" when omitted)
 *
 * Returns "0x..." hex (64 hex chars). Verified against independent
 * pycryptodome keccak vectors in tests/proving.test.js.
 */
function computeStealPublicInputsHash(input) {
  const commitment = parseUintField(input.strategyCommitmentHash, "strategyCommitmentHash");
  const matchId = BigInt(`0x${String(input.matchId).replace(/-/g, "")}`);
  const turn = parseUintField(input.turn, "turn");
  const selfBalance = parseUintField(input.selfBalance, "selfBalance");
  const opponentBalance = parseUintField(input.opponentBalance, "opponentBalance");
  const actionCode = STEAL_ACTION_CODE[input.action];
  if (actionCode === undefined) {
    throw new Error(`publicInputsHash: unknown action ${JSON.stringify(input.action)}`);
  }
  // Spec: amount is 0 for HOLD/FORTIFY.
  const amount = input.action === "EXTRACT" ? parseUintField(input.amount, "amount") : 0n;

  const versionStr = String(input.circuitVersion ?? "v1").trim();
  const versionMatch = /^v(\d+)$/.exec(versionStr);
  const version = versionMatch ? BigInt(versionMatch[1]) : parseUintField(versionStr, "circuitVersion");

  const buf = new Uint8Array(32 * 8);
  const fields = [
    [commitment, "strategyCommitmentHash"],
    [matchId, "matchId"],
    [turn, "turn"],
    [selfBalance, "selfBalance"],
    [opponentBalance, "opponentBalance"],
    [BigInt(actionCode), "action"],
    [amount, "amount"],
    [version, "circuitVersion"],
  ];
  fields.forEach(([value, field], i) => {
    buf.set(toBytes32BE(value, field), i * 32);
  });

  return `0x${bytesToHex(keccak_256(buf))}`;
}

module.exports = {
  PUBLISHED_VK_HASH,
  TRACK_FILES,
  resolveArtifactDir,
  publishedVkHash,
  buildGatekeeperCircuitInputs,
  taskIdToField,
  generateProof,
  verifyProofLocally,
  computeStealPublicInputsHash,
  STEAL_ACTION_CODE,
};
