"use strict";
/**
 * hmac.js — HMAC-SHA256 signing over RAW request/response bodies.
 *
 * Header: `x-agent-games-signature`, hex-encoded HMAC-SHA256 over the raw
 * body bytes, keyed by AGENT_GAMES_HMAC_SECRET. Verification happens BEFORE
 * any JSON parsing (see src/server.js) and uses a constant-time compare.
 */
const crypto = require("node:crypto");

const SIGNATURE_HEADER = "x-agent-games-signature";

/** Sign raw body bytes (Buffer|string) with the secret. Returns hex. */
function sign(rawBody, secret) {
  const body = Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(rawBody, "utf8");
  return crypto.createHmac("sha256", secret).update(body).digest("hex");
}

/**
 * Verify a hex signature against the raw body. Returns false (never throws)
 * for missing, malformed, or wrong-length signatures.
 */
function verify(rawBody, signature, secret) {
  if (typeof signature !== "string" || typeof secret !== "string" || secret.length === 0) {
    return false;
  }
  const expectedHex = sign(rawBody, secret);
  // Reject non-hex / wrong-length input before the constant-time compare
  // (timingSafeEqual throws on length mismatch).
  if (!/^[0-9a-fA-F]+$/.test(signature) || signature.length !== expectedHex.length) {
    return false;
  }
  const expected = Buffer.from(expectedHex, "hex");
  const actual = Buffer.from(signature, "hex");
  return crypto.timingSafeEqual(expected, actual);
}

module.exports = { SIGNATURE_HEADER, sign, verify };
