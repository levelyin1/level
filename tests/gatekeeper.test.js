"use strict";
const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const {
  REASON_CODES,
  GatekeeperInputError,
  decideGatekeeper,
  evaluateCircuitConditions,
  normalizeGatekeeperInput,
  SeenProofStore,
} = require("../src/gatekeeper");

const VALID = {
  registered_vk: "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
  proof_vk: "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
  minimum: "1000",
  public_balance: "1460",
  expiry_block: 8430000,
  current_block: 8420000,
  recipient: "0x1111111111111111111111111111111111111111",
  condition_recipient: "0x1111111111111111111111111111111111111111",
  amount: "500",
  max_transfer: "1000",
  proof_tx: "0xabc123",
};

describe("gatekeeper decisions", () => {
  it("APPROVEs a fully valid condition", () => {
    assert.deepEqual(decideGatekeeper(VALID), {
      decision: "APPROVE",
      reasonCode: REASON_CODES.VALID,
    });
  });

  it("REJECTs VK_SUBSTITUTION", () => {
    const r = decideGatekeeper({
      ...VALID,
      proof_vk: "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    });
    assert.deepEqual(r, { decision: "REJECT", reasonCode: REASON_CODES.VK_SUBSTITUTION });
  });

  it("REJECTs THRESHOLD_MISMATCH (balance below minimum)", () => {
    const r = decideGatekeeper({ ...VALID, public_balance: "999" });
    assert.deepEqual(r, { decision: "REJECT", reasonCode: REASON_CODES.THRESHOLD_MISMATCH });
  });

  it("APPROVEs when balance exactly equals the minimum", () => {
    const r = decideGatekeeper({ ...VALID, public_balance: "1000" });
    assert.equal(r.decision, "APPROVE");
  });

  it("REJECTs EXPIRED_CONDITION when current_block > expiry_block", () => {
    const r = decideGatekeeper({ ...VALID, current_block: 8430001 });
    assert.deepEqual(r, { decision: "REJECT", reasonCode: REASON_CODES.EXPIRED_CONDITION });
  });

  it("REJECTs EXPIRED_CONDITION when current_block == expiry_block (circuit-verified boundary)", () => {
    const r = decideGatekeeper({ ...VALID, current_block: 8430000 });
    assert.deepEqual(r, { decision: "REJECT", reasonCode: REASON_CODES.EXPIRED_CONDITION });
  });

  it("REJECTs RECIPIENT_MISMATCH — proof valid, recipient wrong", () => {
    const r = decideGatekeeper({
      ...VALID,
      recipient: "0x2222222222222222222222222222222222222222",
    });
    assert.deepEqual(r, { decision: "REJECT", reasonCode: REASON_CODES.RECIPIENT_MISMATCH });
  });

  it("REJECTs AMOUNT_OVERFLOW when amount > max_transfer", () => {
    const r = decideGatekeeper({ ...VALID, amount: "1001" });
    assert.deepEqual(r, { decision: "REJECT", reasonCode: REASON_CODES.AMOUNT_OVERFLOW });
  });

  it("APPROVEs when amount exactly equals max_transfer", () => {
    const r = decideGatekeeper({ ...VALID, amount: "1000" });
    assert.equal(r.decision, "APPROVE");
  });

  it("APPROVEs amount == 0 (the circuit treats it as valid — verified live)", () => {
    const r = decideGatekeeper({ ...VALID, amount: "0" });
    assert.equal(r.decision, "APPROVE");
  });

  it("REJECTs PROOF_REUSED when the proof_tx was already accepted", () => {
    const r = decideGatekeeper(VALID, { isProofReused: true });
    assert.deepEqual(r, { decision: "REJECT", reasonCode: REASON_CODES.PROOF_REUSED });
  });

  it("checks on-circuit violations before PROOF_REUSED (so a REJECT stays provable)", () => {
    const r = decideGatekeeper({ ...VALID, amount: "1500" }, { isProofReused: true });
    assert.equal(r.reasonCode, REASON_CODES.AMOUNT_OVERFLOW);
  });

  it("treats hex and decimal spellings of the same value as equal", () => {
    const r = decideGatekeeper({
      ...VALID,
      recipient: "0x1111111111111111111111111111111111111111",
      condition_recipient: BigInt("0x1111111111111111111111111111111111111111").toString(10),
      minimum: 1000,
      public_balance: 1460,
      amount: 500,
      max_transfer: 1000,
    });
    assert.equal(r.decision, "APPROVE");
  });

  it("throws GatekeeperInputError on missing fields", () => {
    const { amount, ...rest } = VALID;
    assert.throws(() => decideGatekeeper(rest), GatekeeperInputError);
  });

  it("throws GatekeeperInputError on negative or non-numeric values", () => {
    assert.throws(() => decideGatekeeper({ ...VALID, amount: "-5" }), GatekeeperInputError);
    assert.throws(() => decideGatekeeper({ ...VALID, amount: "lots" }), GatekeeperInputError);
    assert.throws(() => decideGatekeeper({ ...VALID, current_block: 1.5 }), GatekeeperInputError);
  });

  it("evaluateCircuitConditions agrees with decideGatekeeper on APPROVE", () => {
    assert.equal(evaluateCircuitConditions(normalizeGatekeeperInput(VALID)), true);
    assert.equal(
      evaluateCircuitConditions(
        normalizeGatekeeperInput({ ...VALID, current_block: 8430000 }),
      ),
      false,
    );
  });
});

describe("SeenProofStore", () => {
  it("tracks proof_tx per mode", () => {
    const store = new SeenProofStore();
    assert.equal(store.has("competition", "0xabc"), false);
    store.mark("competition", "0xabc");
    assert.equal(store.has("competition", "0xabc"), true);
    assert.equal(store.has("practice", "0xabc"), false);
    assert.equal(store.has("competition", "0xdef"), false);
  });

  it("matches case-insensitively and ignores empty tx", () => {
    const store = new SeenProofStore();
    store.mark("competition", "0xABC");
    assert.equal(store.has("competition", "0xabc"), true);
    assert.equal(store.has("competition", ""), false);
    assert.equal(store.has("competition", null), false);
  });

  it("evicts the oldest entry at capacity", () => {
    const store = new SeenProofStore(2);
    store.mark("competition", "0x1");
    store.mark("competition", "0x2");
    store.mark("competition", "0x3");
    assert.equal(store.size, 2);
    assert.equal(store.has("competition", "0x1"), false);
    assert.equal(store.has("competition", "0x3"), true);
  });
});
