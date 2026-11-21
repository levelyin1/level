"use strict";
const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const {
  decideSteal,
  isFortified,
  buildStealResponse,
  StealInputError,
} = require("../src/steal");
const { computeStealPublicInputsHash } = require("../src/proving");

const COMMITMENT = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
const MATCH_ID = "9f4e1b2a-0000-4000-8000-000000000001";

function envelope(overrides = {}) {
  return {
    protocolVersion: "v1",
    eventId: "steal-the-vfy",
    mode: "competition",
    matchId: MATCH_ID,
    turn: 3,
    state: {
      selfBalance: "95",
      opponentBalance: "105",
      selfFortifiedUntilTurn: null,
      opponentFortifiedUntilTurn: null,
    },
    strategyCommitment: { hash: COMMITMENT },
    ...overrides,
  };
}

describe("steal policy", () => {
  it("EXTRACTs min(10, floor(opp * 0.10)) when ahead and opponent unfortified", () => {
    assert.deepEqual(
      decideSteal({ selfBalance: 105, opponentBalance: 95, turn: 1, opponentFortifiedUntilTurn: null }),
      { type: "EXTRACT", amount: 9 },
    );
    assert.deepEqual(
      decideSteal({ selfBalance: 100, opponentBalance: 100, turn: 1, opponentFortifiedUntilTurn: null }),
      { type: "EXTRACT", amount: 10 },
    );
    // Cap at 10 even when 10% of the opponent exceeds it.
    assert.deepEqual(
      decideSteal({ selfBalance: 150, opponentBalance: 190, turn: 1, opponentFortifiedUntilTurn: null }),
      // behind (150 < 190) -> FORTIFY, not EXTRACT
      { type: "FORTIFY" },
    );
    assert.deepEqual(
      decideSteal({ selfBalance: 190, opponentBalance: 150, turn: 1, opponentFortifiedUntilTurn: null }),
      { type: "EXTRACT", amount: 10 },
    );
  });

  it("HOLDs when ahead-or-even but the computed EXTRACT is 0", () => {
    assert.deepEqual(
      decideSteal({ selfBalance: 100, opponentBalance: 9, turn: 1, opponentFortifiedUntilTurn: null }),
      { type: "HOLD" },
    );
  });

  it("HOLDs when ahead-or-even but the opponent is fortified", () => {
    assert.deepEqual(
      decideSteal({ selfBalance: 120, opponentBalance: 80, turn: 5, opponentFortifiedUntilTurn: 5 }),
      { type: "HOLD" },
    );
    assert.deepEqual(
      decideSteal({ selfBalance: 120, opponentBalance: 80, turn: 5, opponentFortifiedUntilTurn: 6 }),
      { type: "HOLD" },
    );
  });

  it("EXTRACTs again once the opponent fortification has expired", () => {
    assert.deepEqual(
      decideSteal({ selfBalance: 120, opponentBalance: 80, turn: 6, opponentFortifiedUntilTurn: 5 }),
      { type: "EXTRACT", amount: 8 },
    );
  });

  it("FORTIFies when behind and able to afford the 2 VFY cost", () => {
    assert.deepEqual(
      decideSteal({ selfBalance: 90, opponentBalance: 110, turn: 2, opponentFortifiedUntilTurn: null }),
      { type: "FORTIFY" },
    );
  });

  it("HOLDs when behind but unable to afford FORTIFY", () => {
    assert.deepEqual(
      decideSteal({ selfBalance: 1, opponentBalance: 199, turn: 2, opponentFortifiedUntilTurn: null }),
      { type: "HOLD" },
    );
  });

  it("isFortified treats the boundary turn as fortified (inclusive)", () => {
    assert.equal(isFortified(5, 5), true);
    assert.equal(isFortified(5, 6), false);
    assert.equal(isFortified(null, 5), false);
    assert.equal(isFortified(undefined, 5), false);
  });
});

describe("steal 20-turn simulation", () => {
  it("plays a full match against a passive opponent without errors", () => {
    // Opponent always HOLDs; we extract 10% while ahead-or-even.
    let self = 100;
    let opp = 100;
    let extracts = 0;
    let fortifies = 0;
    let holds = 0;
    for (let turn = 1; turn <= 20; turn++) {
      const action = decideSteal({
        selfBalance: self,
        opponentBalance: opp,
        turn,
        opponentFortifiedUntilTurn: null,
      });
      if (action.type === "EXTRACT") {
        extracts++;
        self += action.amount;
        opp -= action.amount;
        assert.ok(action.amount >= 1 && action.amount <= 10);
      } else if (action.type === "FORTIFY") {
        fortifies++;
        self -= 2;
      } else {
        holds++;
      }
      assert.ok(self >= 0 && opp >= 0, `balances went negative on turn ${turn}`);
    }
    assert.equal(extracts + fortifies + holds, 20);
    assert.ok(self > 100, "we should have gained VFY against a passive opponent");
    assert.equal(self + opp, 200, "VFY is conserved (no fortify cost was paid)");
  });

  it("fortifies through a losing stretch and never goes below zero", () => {
    // Opponent extracts 10/turn from us; we fortify (blocks 6) when behind.
    let self = 90;
    let opp = 110;
    let fortifies = 0;
    for (let turn = 1; turn <= 20; turn++) {
      const action = decideSteal({
        selfBalance: self,
        opponentBalance: opp,
        turn,
        opponentFortifiedUntilTurn: null,
      });
      let incoming = 10;
      if (action.type === "FORTIFY") {
        fortifies++;
        self -= 2;
        incoming = Math.max(0, incoming - 6);
      } else if (action.type === "EXTRACT") {
        self += action.amount;
        opp -= action.amount;
      }
      const stolen = Math.min(incoming, self);
      self -= stolen;
      opp += stolen;
      assert.ok(self >= 0, `balance negative on turn ${turn}`);
    }
    assert.ok(fortifies > 0, "expected at least one FORTIFY while behind");
    assert.ok(self >= 0 && opp <= 200);
  });
});

describe("steal response builder", () => {
  it("echoes matchId/turn and carries a correct publicInputsHash", () => {
    const res = buildStealResponse(envelope());
    assert.equal(res.matchId, MATCH_ID);
    assert.equal(res.turn, 3);
    // Behind (95 < 105) -> FORTIFY.
    assert.deepEqual(res.action, { type: "FORTIFY" });
    assert.ok(!("amount" in res.action), "FORTIFY must not carry amount");
    assert.equal(res.policyProof.circuitVersion, "v1");
    const expected = computeStealPublicInputsHash({
      strategyCommitmentHash: COMMITMENT,
      matchId: MATCH_ID,
      turn: 3,
      selfBalance: 95,
      opponentBalance: 105,
      action: "FORTIFY",
      amount: 0,
    });
    assert.equal(res.policyProof.publicInputsHash, expected);
    assert.match(res.idempotencyKey, new RegExp(`^${MATCH_ID}:3:`));
  });

  it("omits amount for HOLD and FORTIFY, includes it for EXTRACT", () => {
    const hold = buildStealResponse(
      envelope({
        turn: 1,
        state: {
          selfBalance: "1",
          opponentBalance: "199",
          selfFortifiedUntilTurn: null,
          opponentFortifiedUntilTurn: null,
        },
      }),
    );
    assert.deepEqual(hold.action, { type: "HOLD" });
    assert.ok(!("amount" in hold.action));

    const extract = buildStealResponse(
      envelope({
        turn: 2,
        state: {
          selfBalance: "110",
          opponentBalance: "90",
          selfFortifiedUntilTurn: null,
          opponentFortifiedUntilTurn: null,
        },
      }),
    );
    assert.deepEqual(extract.action, { type: "EXTRACT", amount: 9 });
  });

  it("generates a unique idempotencyKey per call", () => {
    const a = buildStealResponse(envelope());
    const b = buildStealResponse(envelope());
    assert.notEqual(a.idempotencyKey, b.idempotencyKey);
  });

  it("omits publicInputsHash when no commitment hash is available", () => {
    const env = envelope();
    delete env.strategyCommitment;
    const res = buildStealResponse(env, {});
    assert.equal(res.policyProof.publicInputsHash, undefined);
    assert.equal(res.policyProof.circuitVersion, "v1");
  });

  it("falls back to the configured strategy commitment", () => {
    const env = envelope();
    delete env.strategyCommitment;
    const res = buildStealResponse(env, { strategyCommitmentHash: COMMITMENT });
    assert.ok(res.policyProof.publicInputsHash);
  });

  it("rejects malformed envelopes", () => {
    assert.throws(() => buildStealResponse(envelope({ matchId: "not-a-uuid" })), StealInputError);
    assert.throws(() => buildStealResponse(envelope({ turn: "three" })), StealInputError);
    assert.throws(
      () =>
        buildStealResponse(
          envelope({ state: { selfBalance: "-1", opponentBalance: "5" } }),
        ),
      StealInputError,
    );
  });
});
