"use strict";
const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const {
  generateProof,
  verifyProofLocally,
  buildGatekeeperCircuitInputs,
  computeStealPublicInputsHash,
  PUBLISHED_VK_HASH,
} = require("../src/proving");

const VK = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const RECIPIENT = "0x1111111111111111111111111111111111111111";

function validInputs(overrides = {}) {
  return {
    registered_vk: VK,
    proof_vk: VK,
    minimum: "1000",
    public_balance: "1460",
    expiry_block: 8430000,
    current_block: 8420000,
    recipient: RECIPIENT,
    condition_recipient: RECIPIENT,
    amount: "500",
    max_transfer: "1000",
    task_id: "gk_test_1",
    proof_tx: "0xabc123", // must be dropped by the translator
    ...overrides,
  };
}

describe("buildGatekeeperCircuitInputs", () => {
  it("translates envelope inputs to the 13 circuit signals", () => {
    const out = buildGatekeeperCircuitInputs(validInputs({ salt: "7" }));
    assert.deepEqual(Object.keys(out).sort(), [
      "amount",
      "conditionRecipient",
      "currentBlock",
      "decision",
      "expiryBlock",
      "maxTransfer",
      "minimum",
      "proofVkHash",
      "publicBalance",
      "recipient",
      "registeredVkHash",
      "salt",
      "taskId",
    ]);
    assert.equal(out.decision, "1");
    assert.equal(out.salt, "7");
    assert.equal(out.registeredVkHash, BigInt(VK).toString());
    assert.equal(out.recipient, BigInt(RECIPIENT).toString());
    assert.ok(!("proof_tx" in out) && !("proofTx" in out));
  });

  it("derives decision=0 when a condition fails", () => {
    const out = buildGatekeeperCircuitInputs(validInputs({ amount: "1500" }));
    assert.equal(out.decision, "0");
  });

  it("derives decision=0 at the expiry boundary (current == expiry)", () => {
    const out = buildGatekeeperCircuitInputs(validInputs({ current_block: 8430000 }));
    assert.equal(out.decision, "0");
  });

  it("derives decision=1 for amount == 0 (circuit treats it as valid)", () => {
    const out = buildGatekeeperCircuitInputs(validInputs({ amount: "0" }));
    assert.equal(out.decision, "1");
  });

  it("encodes an alphanumeric taskId as the big-endian integer of its UTF-8 bytes", () => {
    const out = buildGatekeeperCircuitInputs(validInputs({ task_id: "gk_24_9d1" }));
    assert.equal(
      out.taskId,
      BigInt(`0x${Buffer.from("gk_24_9d1", "utf8").toString("hex")}`).toString(),
    );
  });

  it("draws a random salt when none is supplied", () => {
    const a = buildGatekeeperCircuitInputs(validInputs());
    const b = buildGatekeeperCircuitInputs(validInputs());
    assert.notEqual(a.salt, b.salt);
    assert.ok(BigInt(a.salt) > 0n);
  });

  it("throws on missing required fields", () => {
    const { minimum, ...rest } = validInputs();
    assert.throws(() => buildGatekeeperCircuitInputs(rest), /missing required field/);
  });
});

describe("groth16 proving round-trip (real snarkjs + official circuit)", () => {
  it("proves and locally verifies an APPROVE decision", async () => {
    const { proof, publicSignals, circuit, circuitVersion } = await generateProof({
      track: "gatekeeper",
      circuitInputs: validInputs({ decision: "APPROVE", salt: "7" }),
    });
    assert.equal(circuit, "gatekeeper");
    assert.equal(circuitVersion, PUBLISHED_VK_HASH.gatekeeper);
    assert.equal(publicSignals.length, 13);
    // Public-signal order: [Poseidon(salt, taskId), registeredVkHash,
    // proofVkHash, minimum, publicBalance, expiryBlock, currentBlock,
    // recipient, conditionRecipient, amount, maxTransfer, decision, taskId]
    // The vk hash exceeds the BN128 field modulus, so snarkjs reduces it
    // mod p before it reaches the circuit (both sides reduce identically,
    // so the equality check still works). Expect the reduced value.
    const FIELD_P =
      21888242871839275222246405745257275088548364400416034343698204186575808495617n;
    const vkField = (BigInt(VK) % FIELD_P).toString();
    assert.deepEqual(publicSignals.slice(1), [
      vkField,
      vkField,
      "1000",
      "1460",
      "8430000",
      "8420000",
      BigInt(RECIPIENT).toString(),
      BigInt(RECIPIENT).toString(),
      "500",
      "1000",
      "1",
      BigInt(`0x${Buffer.from("gk_test_1", "utf8").toString("hex")}`).toString(),
    ]);
    assert.equal(await verifyProofLocally(proof, publicSignals, "gatekeeper"), true);
  });

  it("proves and locally verifies a REJECT decision (amount overflow)", async () => {
    const { proof, publicSignals } = await generateProof({
      track: "gatekeeper",
      circuitInputs: validInputs({ amount: "1500", decision: "REJECT", salt: "7" }),
    });
    assert.equal(publicSignals[11], "0");
    assert.equal(await verifyProofLocally(proof, publicSignals, "gatekeeper"), true);
  });

  it("proves a REJECT at the expiry boundary (current == expiry)", async () => {
    const { proof, publicSignals } = await generateProof({
      track: "gatekeeper",
      circuitInputs: validInputs({ current_block: 8430000, decision: "REJECT", salt: "7" }),
    });
    assert.equal(publicSignals[11], "0");
    assert.equal(await verifyProofLocally(proof, publicSignals, "gatekeeper"), true);
  });

  it("proves an APPROVE with amount == 0", async () => {
    const { proof, publicSignals } = await generateProof({
      track: "gatekeeper",
      circuitInputs: validInputs({ amount: "0", decision: "APPROVE", salt: "7" }),
    });
    assert.equal(publicSignals[11], "1");
    assert.equal(await verifyProofLocally(proof, publicSignals, "gatekeeper"), true);
  });

  it("fails witness generation for a WRONG decision (circuit is the referee)", async () => {
    await assert.rejects(
      generateProof({
        track: "gatekeeper",
        circuitInputs: validInputs({ amount: "1500", decision: "APPROVE", salt: "7" }),
      }),
      /Assert Failed/,
    );
    await assert.rejects(
      generateProof({
        track: "gatekeeper",
        circuitInputs: validInputs({ decision: "REJECT", salt: "7" }),
      }),
      /Assert Failed/,
    );
  });

  it("changing the salt changes only public signal 0 (Poseidon commitment)", async () => {
    const a = await generateProof({
      track: "gatekeeper",
      circuitInputs: validInputs({ decision: "APPROVE", salt: "7" }),
    });
    const b = await generateProof({
      track: "gatekeeper",
      circuitInputs: validInputs({ decision: "APPROVE", salt: "8" }),
    });
    assert.notEqual(a.publicSignals[0], b.publicSignals[0]);
    assert.deepEqual(a.publicSignals.slice(1), b.publicSignals.slice(1));
  });

  it("generateProof('steal') throws an honest error (input names unpublished)", async () => {
    await assert.rejects(
      generateProof({ track: "steal", circuitInputs: {} }),
      /not fully published/,
    );
  });
});

describe("computeStealPublicInputsHash", () => {
  // Reference vectors computed independently with pycryptodome keccak
  // (Python) + manual ABI packing — see circuits/PROBE.md.
  const VECTORS = [
    {
      input: {
        strategyCommitmentHash:
          "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        matchId: "9f4e1b2a-0000-4000-8000-000000000001",
        turn: 3,
        selfBalance: 95,
        opponentBalance: 105,
        action: "EXTRACT",
        amount: 5,
      },
      expected: "0x79a0d3317cc5a7bb592ffe3a22ec637e1f1c32bc905b5dacb5ffcb833dc6ffa1",
    },
    {
      input: {
        strategyCommitmentHash: "0x0",
        matchId: "00000000-0000-0000-0000-000000000000",
        turn: 0,
        selfBalance: 0,
        opponentBalance: 0,
        action: "HOLD",
        amount: 0,
      },
      expected: "0x11934057fe979f7d236d4bfe0cfcb7b2b1d5f4145867576ef0d8026fdcb33ab0",
    },
    {
      input: {
        strategyCommitmentHash:
          "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        matchId: "ffffffff-ffff-4fff-8fff-ffffffffffff",
        turn: 20,
        selfBalance: 2,
        opponentBalance: 198,
        action: "FORTIFY",
        amount: 0,
      },
      expected: "0xca5c292858fd141e32437d35db9ddeed69f3d7534afa8f0e1d51634fa2d3c4de",
    },
  ];

  for (const [i, { input, expected }] of VECTORS.entries()) {
    it(`matches independent reference vector ${i + 1}`, () => {
      assert.equal(computeStealPublicInputsHash(input), expected);
    });
  }

  it("forces amount to 0 for HOLD/FORTIFY even if a nonzero amount is passed", () => {
    const base = {
      strategyCommitmentHash: "0x1234",
      matchId: "9f4e1b2a-0000-4000-8000-000000000001",
      turn: 1,
      selfBalance: 100,
      opponentBalance: 100,
      action: "HOLD",
      amount: 0,
    };
    assert.equal(
      computeStealPublicInputsHash({ ...base, amount: 99 }),
      computeStealPublicInputsHash(base),
    );
  });

  it("accepts string balances and rejects unknown actions", () => {
    const h1 = computeStealPublicInputsHash({
      strategyCommitmentHash: "0x1234",
      matchId: "9f4e1b2a-0000-4000-8000-000000000001",
      turn: 1,
      selfBalance: "100",
      opponentBalance: "100",
      action: "HOLD",
      amount: 0,
    });
    const h2 = computeStealPublicInputsHash({
      strategyCommitmentHash: "0x1234",
      matchId: "9f4e1b2a-0000-4000-8000-000000000001",
      turn: 1,
      selfBalance: 100,
      opponentBalance: 100,
      action: "HOLD",
      amount: 0,
    });
    assert.equal(h1, h2);
    assert.throws(
      () =>
        computeStealPublicInputsHash({
          strategyCommitmentHash: "0x1234",
          matchId: "9f4e1b2a-0000-4000-8000-000000000001",
          turn: 1,
          selfBalance: 100,
          opponentBalance: 100,
          action: "STEAL",
          amount: 0,
        }),
      /unknown action/,
    );
  });
});
