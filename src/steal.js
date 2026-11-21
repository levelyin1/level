"use strict";
/**
 * steal.js — Steal the VFY 20-turn policy + response builder.
 *
 * Match: 100 VFY each, 20 turns, highest balance wins. Actions:
 *   HOLD     — steals 0.
 *   FORTIFY  — costs 2 VFY, blocks up to 6 incoming extraction that turn.
 *   EXTRACT N — steals up to N (max 10).
 * `action.amount` must be OMITTED entirely for HOLD/FORTIFY (the schema
 * rejects the field even when it is 0).
 *
 * Committed policy (littletang):
 *   - EXTRACT min(10, floor(opponentBalance * 0.10)) when ahead-or-even
 *     AND the opponent is not fortified (and the computed amount is >= 1).
 *   - FORTIFY when behind AND we can afford the 2 VFY cost.
 *   - HOLD otherwise.
 *
 * Golden rule: a missing proof scores −2 per the field guide's "common
 * mistakes" ("every such turn is −2 and resolved as HOLD"); the brief
 * says it resolves as HOLD (0 points). Either way, sending NO proof is
 * never worse than sending an INVALID one — so when in doubt we send
 * no proof rather than a wrong one. Steal proofs cannot be generated
 * at all right now (vfyPolicy's 8 private input names are unpublished
 * — see SPEC.md), so the response carries the published
 * publicInputsHash and no proof. That is honest, not a placeholder.
 */
const crypto = require("node:crypto");
const { computeStealPublicInputsHash } = require("./proving");

const MAX_EXTRACT = 10;
const FORTIFY_COST = 2;
const MATCH_TURNS = 20;

class StealInputError extends Error {
  constructor(message) {
    super(message);
    this.name = "StealInputError";
  }
}

function toNumber(value, field) {
  const n = typeof value === "string" ? Number(value.trim()) : value;
  if (typeof n !== "number" || !Number.isFinite(n) || !Number.isInteger(n) || n < 0) {
    throw new StealInputError(`${field}: must be a non-negative integer, got ${JSON.stringify(value)}`);
  }
  return n;
}

/**
 * Is the opponent fortified on this turn? `fortifiedUntilTurn` is the last
 * turn the fortification covers (inclusive); null/undefined means not
 * fortified. (ASSUMPTION — the platform does not publish whether the
 * boundary turn is inclusive; inclusive is the conservative reading: when
 * in doubt we HOLD instead of extracting into a fortify.)
 */
function isFortified(fortifiedUntilTurn, turn) {
  if (fortifiedUntilTurn === null || fortifiedUntilTurn === undefined) return false;
  const until = toNumber(fortifiedUntilTurn, "fortifiedUntilTurn");
  return until >= turn;
}

/**
 * Decide one turn. Pure function of the visible game state.
 * @param {{ selfBalance, opponentBalance, opponentFortifiedUntilTurn, turn }}
 * @returns {{ type: "HOLD"|"FORTIFY"|"EXTRACT", amount?: number }}
 *   (amount present ONLY for EXTRACT — never for HOLD/FORTIFY).
 */
function decideSteal(state) {
  const self = toNumber(state.selfBalance, "selfBalance");
  const opp = toNumber(state.opponentBalance, "opponentBalance");
  const turn = toNumber(state.turn, "turn");
  const opponentFortified = isFortified(state.opponentFortifiedUntilTurn, turn);

  const aheadOrEven = self >= opp;
  if (aheadOrEven && !opponentFortified) {
    const amount = Math.min(MAX_EXTRACT, Math.floor(opp * 0.1));
    if (amount >= 1) return { type: "EXTRACT", amount };
    return { type: "HOLD" };
  }
  if (self < opp && self >= FORTIFY_COST) {
    return { type: "FORTIFY" };
  }
  return { type: "HOLD" };
}

/**
 * Validate a Steal turn envelope and return the normalized state.
 * @throws StealInputError on missing/malformed fields.
 */
function parseStealEnvelope(envelope) {
  if (!envelope || typeof envelope !== "object") {
    throw new StealInputError("envelope must be an object");
  }
  const { matchId, turn, state } = envelope;
  if (typeof matchId !== "string" || matchId.length === 0) {
    throw new StealInputError("matchId must be a non-empty string");
  }
  if (!/^[0-9a-fA-F-]{36}$/.test(matchId)) {
    throw new StealInputError(`matchId must be a UUID, got ${JSON.stringify(matchId)}`);
  }
  const turnNum = toNumber(turn, "turn");
  if (!state || typeof state !== "object") {
    throw new StealInputError("state must be an object");
  }
  const selfBalance = toNumber(state.selfBalance, "state.selfBalance");
  const opponentBalance = toNumber(state.opponentBalance, "state.opponentBalance");
  return {
    matchId,
    turn: turnNum,
    selfBalance,
    opponentBalance,
    opponentFortifiedUntilTurn: state.opponentFortifiedUntilTurn ?? null,
    selfFortifiedUntilTurn: state.selfFortifiedUntilTurn ?? null,
  };
}

/**
 * Build the signed-response body for one Steal turn.
 * @param {object} envelope the platform turn envelope.
 * @param {object} opts { strategyCommitmentHash?: string } — fallback when
 *   the envelope carries no strategyCommitment.hash.
 * @returns the response object (matchId/turn echoed exactly).
 */
function buildStealResponse(envelope, opts = {}) {
  const parsed = parseStealEnvelope(envelope);
  const action = decideSteal(parsed);

  const commitmentHash =
    (envelope.strategyCommitment && envelope.strategyCommitment.hash) ||
    opts.strategyCommitmentHash ||
    "";

  const policyProof = { circuitVersion: "v1" };
  // No proof/public_signals: vfyPolicy proofs cannot be generated (8
  // private input names unpublished). The publicInputsHash is still
  // included when computable — the platform can check it without a proof.
  if (commitmentHash) {
    policyProof.publicInputsHash = computeStealPublicInputsHash({
      strategyCommitmentHash: commitmentHash,
      matchId: parsed.matchId,
      turn: parsed.turn,
      selfBalance: parsed.selfBalance,
      opponentBalance: parsed.opponentBalance,
      action: action.type,
      amount: action.type === "EXTRACT" ? action.amount : 0,
      circuitVersion: "v1",
    });
  }

  const actionOut = { type: action.type };
  if (action.type === "EXTRACT") actionOut.amount = action.amount;

  return {
    matchId: parsed.matchId,
    turn: parsed.turn,
    action: actionOut,
    policyProof,
    agentTimestamp: new Date().toISOString(),
    // Unique per turn: only the first submission per key is accepted.
    idempotencyKey: `${parsed.matchId}:${parsed.turn}:${crypto.randomUUID()}`,
  };
}

module.exports = {
  MAX_EXTRACT,
  FORTIFY_COST,
  MATCH_TURNS,
  StealInputError,
  isFortified,
  decideSteal,
  parseStealEnvelope,
  buildStealResponse,
};
