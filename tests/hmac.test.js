"use strict";
const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { sign, verify } = require("../src/hmac");

const SECRET = "test-secret-do-not-use-in-production";
const BODY = JSON.stringify({ type: "agent-games.preflight.v1", nonce: "abc123" });

describe("hmac", () => {
  it("signs and verifies a valid signature", () => {
    const sig = sign(BODY, SECRET);
    assert.equal(sig.length, 64);
    assert.equal(verify(BODY, sig, SECRET), true);
  });

  it("accepts Buffer and string bodies identically", () => {
    const fromString = sign(BODY, SECRET);
    const fromBuffer = sign(Buffer.from(BODY, "utf8"), SECRET);
    assert.equal(fromString, fromBuffer);
    assert.equal(verify(Buffer.from(BODY, "utf8"), fromString, SECRET), true);
  });

  it("rejects a tampered body", () => {
    const sig = sign(BODY, SECRET);
    assert.equal(verify(`${BODY} `, sig, SECRET), false);
    assert.equal(verify(BODY.replace("abc123", "abc124"), sig, SECRET), false);
  });

  it("rejects a tampered signature", () => {
    const sig = sign(BODY, SECRET);
    const flipped = (sig[0] === "0" ? "1" : "0") + sig.slice(1);
    assert.equal(verify(BODY, flipped, SECRET), false);
  });

  it("rejects a missing signature", () => {
    assert.equal(verify(BODY, undefined, SECRET), false);
    assert.equal(verify(BODY, "", SECRET), false);
    assert.equal(verify(BODY, null, SECRET), false);
  });

  it("rejects the wrong secret", () => {
    const sig = sign(BODY, SECRET);
    assert.equal(verify(BODY, sig, "another-secret"), false);
  });

  it("rejects non-hex and wrong-length signatures without throwing", () => {
    assert.equal(verify(BODY, "zzzz", SECRET), false);
    assert.equal(verify(BODY, "ab".repeat(10), SECRET), false);
    assert.equal(verify(BODY, "ab".repeat(64), SECRET), false);
  });

  it("rejects an empty secret", () => {
    const sig = sign(BODY, SECRET);
    assert.equal(verify(BODY, sig, ""), false);
  });
});
