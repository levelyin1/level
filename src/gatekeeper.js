"use strict";
/**
 * gatekeeper.js — Proof Gatekeeper decision policy (deterministic).
 *
 * APPROVE only when ALL hold (SPEC.md, with two boundaries settled by live
 * probes against the official circuit — see circuits/PROBE.md):
 *   proof_vk == registered_vk
 *   public_balance >= minimum
 *   current_block < expiry_block        (circuit: current == expiry is EXPIRED)
 *   recipient == condition_recipient
 *   0 <= amount <= max_transfer         (circuit: amount == 0 is VALID)
 *   proof_tx not previously accepted    (off-chain replay check)
 *
 * Reason-code priority: on-circuit violations are checked BEFORE
 * PROOF_REUSED, so a REJECT that the circuit can prove is proven (a
 * PROOF_REUSED reject has no witness when all on-circuit conditions hold).
 * Trap tasks normally carry a single violation, so priority rarely matters.
 *
 * The decision rule here and the circuit-input derivation in proving.js
 * share one source of truth: normalizeGatekeeperInput() +
 * evaluateCircuitConditions(). A decision the circuit disagrees with cannot
 * produce a witness at all, so the two must never drift apart.
 */

const REASON_CODES = {
  VALID: "VALID_CONDITION",
  VK_SUBSTITUTION: "VK_SUBSTITUTION",
  THRESHOLD_MISMATCH: "THRESHOLD_MISMATCH",
  PROOF_REUSED: "PROOF_REUSED",
  EXPIRED_CONDITION: "EXPIRED_CONDITION",
  RECIPIENT_MISMATCH: "RECIPIENT_MISMATCH",
  AMOUNT_OVERFLOW: "AMOUNT_OVERFLOW",
  INVALID_INPUT: "INVALID_INPUT", // malformed envelope (not a trap code)
};

class GatekeeperInputError extends Error {
  constructor(message) {
    super(message);
    this.name = "GatekeeperInputError";
  }
}

/**
 * Parse a field-element value (decimal string, number, or 0x-hex) into a
 * BigInt. Throws GatekeeperInputError on anything else (including negatives
 * and non-numeric strings) — a negative amount cannot be a circuit input.
 */
function toBigInt(value, field) {
  if (typeof value === "number") {
    if (!Number.isInteger(value) || value < 0) {
      throw new GatekeeperInputError(
        `${field}: must be a non-negative integer, got ${value}`,
      );
    }
    return BigInt(value);
  }
  if (typeof value === "string") {
    const s = value.trim();
    if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
    if (/^[0-9]+$/.test(s)) return BigInt(s);
    throw new GatekeeperInputError(
      `${field}: expected a decimal or 0x-hex integer, got ${JSON.stringify(value)}`,
    );
  }
  throw new GatekeeperInputError(
    `${field}: expected a number or numeric string, got ${typeof value}`,
  );
}

/**
 * Normalize an envelope `input` object into BigInt fields. Hex and decimal
 * spellings of the same value compare equal after normalization (so a vk
 * hash written as 0x-hex matches the same value written as decimal).
 * Missing required fields throw GatekeeperInputError.
 */
function normalizeGatekeeperInput(input) {
  if (!input || typeof input !== "object") {
    throw new GatekeeperInputError("input must be an object");
  }
  const required = [
    "registered_vk",
    "proof_vk",
    "minimum",
    "public_balance",
    "expiry_block",
    "current_block",
    "recipient",
    "condition_recipient",
    "amount",
    "max_transfer",
  ];
  const missing = required.filter((k) => input[k] === undefined || input[k] === null);
  if (missing.length > 0) {
    throw new GatekeeperInputError(`missing required field(s): ${missing.join(", ")}`);
  }
  return {
    registeredVk: toBigInt(input.registered_vk, "registered_vk"),
    proofVk: toBigInt(input.proof_vk, "proof_vk"),
    minimum: toBigInt(input.minimum, "minimum"),
    publicBalance: toBigInt(input.public_balance, "public_balance"),
    expiryBlock: toBigInt(input.expiry_block, "expiry_block"),
    currentBlock: toBigInt(input.current_block, "current_block"),
    recipient: toBigInt(input.recipient, "recipient"),
    conditionRecipient: toBigInt(input.condition_recipient, "condition_recipient"),
    amount: toBigInt(input.amount, "amount"),
    maxTransfer: toBigInt(input.max_transfer, "max_transfer"),
    // proof_tx is not a circuit input; kept for the replay check only.
    proofTx: typeof input.proof_tx === "string" ? input.proof_tx : "",
  };
}

/**
 * The on-circuit condition, exactly as the gatekeeper circuit evaluates it
 * (verified by live fullProve round-trips — see circuits/PROBE.md).
 */
function evaluateCircuitConditions(n) {
  return (
    n.proofVk === n.registeredVk &&
    n.publicBalance >= n.minimum &&
    n.currentBlock < n.expiryBlock &&
    n.recipient === n.conditionRecipient &&
    n.amount <= n.maxTransfer
  );
}

/**
 * Decide APPROVE/REJECT for one task.
 * @param {object} input envelope `input` object (raw values).
 * @param {object} opts { isProofReused: boolean } — off-chain replay check.
 * @returns {{ decision: "APPROVE"|"REJECT", reasonCode: string }}
 * @throws GatekeeperInputError on malformed input (server maps to REJECT).
 */
function decideGatekeeper(input, opts = {}) {
  const n = normalizeGatekeeperInput(input);
  if (n.proofVk !== n.registeredVk) {
    return { decision: "REJECT", reasonCode: REASON_CODES.VK_SUBSTITUTION };
  }
  if (n.publicBalance < n.minimum) {
    return { decision: "REJECT", reasonCode: REASON_CODES.THRESHOLD_MISMATCH };
  }
  if (n.currentBlock >= n.expiryBlock) {
    return { decision: "REJECT", reasonCode: REASON_CODES.EXPIRED_CONDITION };
  }
  if (n.recipient !== n.conditionRecipient) {
    return { decision: "REJECT", reasonCode: REASON_CODES.RECIPIENT_MISMATCH };
  }
  if (n.amount > n.maxTransfer) {
    return { decision: "REJECT", reasonCode: REASON_CODES.AMOUNT_OVERFLOW };
  }
  if (opts.isProofReused) {
    return { decision: "REJECT", reasonCode: REASON_CODES.PROOF_REUSED };
  }
  return { decision: "APPROVE", reasonCode: REASON_CODES.VALID };
}

/**
 * In-memory set of accepted proof_tx values, keyed per mode (competition vs
 * practice) so a practice acceptance never flags a competition task.
 * A proof_tx is marked only when its task is APPROVED ("accepted"); a
 * rejected task does not consume the proof. In-memory only: a server
 * restart clears the set (documented limitation — see README).
 */
class SeenProofStore {
  constructor(maxEntries = 10000) {
    this.maxEntries = maxEntries;
    this.seen = new Set();
  }

  key(mode, proofTx) {
    return `${mode || "competition"}:${String(proofTx).toLowerCase()}`;
  }

  has(mode, proofTx) {
    if (!proofTx) return false;
    return this.seen.has(this.key(mode, proofTx));
  }

  mark(mode, proofTx) {
    if (!proofTx) return;
    if (this.seen.size >= this.maxEntries) {
      // Simple FIFO eviction: drop the oldest entry.
      const oldest = this.seen.values().next().value;
      this.seen.delete(oldest);
    }
    this.seen.add(this.key(mode, proofTx));
  }

  get size() {
    return this.seen.size;
  }
}

module.exports = {
  REASON_CODES,
  GatekeeperInputError,
  toBigInt,
  normalizeGatekeeperInput,
  evaluateCircuitConditions,
  decideGatekeeper,
  SeenProofStore,
};
