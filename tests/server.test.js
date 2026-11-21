"use strict";
const { describe, it, before, after } = require("node:test");
const assert = require("node:assert/strict");
const { createServer } = require("../src/server");
const hmac = require("../src/hmac");

const SECRET = "server-test-secret-do-not-use-in-production";
const VK = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const RECIPIENT = "0x1111111111111111111111111111111111111111";

let server;
let baseUrl;

function validGatekeeperInput(overrides = {}) {
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
    proof_tx: "0xservertx1",
    ...overrides,
  };
}

async function postAgent(envelope, { secret = SECRET, signIt = true } = {}) {
  const body = JSON.stringify(envelope);
  const headers = { "content-type": "application/json" };
  if (signIt) headers[hmac.SIGNATURE_HEADER] = hmac.sign(body, secret);
  const res = await fetch(`${baseUrl}/agent`, { method: "POST", headers, body });
  const text = await res.text();
  return { res, text, json: text ? JSON.parse(text) : null };
}

before(async () => {
  server = createServer({
    port: 0,
    hmacSecret: SECRET,
    allowUnsigned: false,
    kurierApiKey: "",
    kurierApiUrl: "https://api.kurier.xyz",
    kurierStatusPath: "/api/v1/proof-status",
    strategyCommitment: "",
    circuitDir: "",
    internalBudgetMs: 55000,
    maxBodyBytes: 1024 * 1024,
  });
  await new Promise((resolve) => server.listen(0, resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  await new Promise((resolve) => server.close(resolve));
});

describe("server", () => {
  it("GET /health returns ok + protocolVersion", async () => {
    const res = await fetch(`${baseUrl}/health`);
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { ok: true, protocolVersion: "v1" });
  });

  it("answers a signed preflight with a signed response", async () => {
    const { res, text, json } = await postAgent({
      type: "agent-games.preflight.v1",
      agent_id: "agt_test",
      issued_at: new Date().toISOString(),
      nonce: "abc123",
    });
    assert.equal(res.status, 200);
    assert.deepEqual(json, { ok: true, protocolVersion: "v1" });
    const sig = res.headers.get(hmac.SIGNATURE_HEADER);
    assert.ok(sig, "response must be signed");
    assert.equal(hmac.verify(text, sig, SECRET), true);
  });

  it("rejects an unsigned request with 401", async () => {
    const { res, json } = await postAgent(
      { type: "agent-games.preflight.v1", nonce: "x" },
      { signIt: false },
    );
    assert.equal(res.status, 401);
    assert.equal(json.error, "invalid_signature");
  });

  it("rejects a request signed with the wrong secret with 401", async () => {
    const { res } = await postAgent(
      { type: "agent-games.preflight.v1", nonce: "x" },
      { secret: "wrong-secret" },
    );
    assert.equal(res.status, 401);
  });

  it("rejects an unknown type with 400", async () => {
    const { res, json } = await postAgent({ type: "agent-games.unknown.v9" });
    assert.equal(res.status, 400);
    assert.equal(json.error, "unknown_type");
  });

  it("handles a full gatekeeper APPROVE with a real proof", async () => {
    const { res, text, json } = await postAgent({
      type: "agent-games.proof-gatekeeper.v1",
      task_id: "gk_server_approve",
      mode: "competition",
      issued_at: new Date().toISOString(),
      input: validGatekeeperInput(),
    });
    assert.equal(res.status, 200);
    assert.equal(json.decision, "APPROVE");
    assert.equal(json.reason_code, "VALID_CONDITION");
    assert.ok(json.proof, "proof must be present");
    assert.equal(json.public_signals.length, 13);
    assert.equal(json.public_signals[11], "1");
    assert.equal(json.proof_tx, null, "no Kurier key -> proof_tx null");
    assert.equal(json.proof_status, "verified_locally");
    const sig = res.headers.get(hmac.SIGNATURE_HEADER);
    assert.equal(hmac.verify(text, sig, SECRET), true);
  });

  it("returns the cached response on a task_id resend", async () => {
    const envelope = {
      type: "agent-games.proof-gatekeeper.v1",
      task_id: "gk_server_resend",
      mode: "competition",
      issued_at: new Date().toISOString(),
      input: validGatekeeperInput({ proof_tx: "0xservertx2" }),
    };
    const first = await postAgent(envelope);
    const second = await postAgent(envelope);
    assert.equal(first.res.status, 200);
    assert.equal(second.res.status, 200);
    assert.equal(second.text, first.text, "resend must return the identical body");
  });

  it("REJECTs a reused proof_tx with no proof (PROOF_REUSED)", async () => {
    // First task APPROVEs and consumes proof_tx 0xservertx1 (see APPROVE test).
    const { res, json } = await postAgent({
      type: "agent-games.proof-gatekeeper.v1",
      task_id: "gk_server_reused",
      mode: "competition",
      issued_at: new Date().toISOString(),
      input: validGatekeeperInput(), // same proof_tx as the APPROVE test
    });
    assert.equal(res.status, 200);
    assert.equal(json.decision, "REJECT");
    assert.equal(json.reason_code, "PROOF_REUSED");
    assert.equal(json.proof, null);
    assert.equal(json.proof_status, "unprovable_reject");
  });

  it("REJECTs recipient mismatch WITH a real proof", async () => {
    const { res, json } = await postAgent({
      type: "agent-games.proof-gatekeeper.v1",
      task_id: "gk_server_recipient",
      mode: "competition",
      issued_at: new Date().toISOString(),
      input: validGatekeeperInput({
        recipient: "0x2222222222222222222222222222222222222222",
        proof_tx: "0xservertx3",
      }),
    });
    assert.equal(res.status, 200);
    assert.equal(json.decision, "REJECT");
    assert.equal(json.reason_code, "RECIPIENT_MISMATCH");
    assert.ok(json.proof, "on-circuit REJECTs are provable");
    assert.equal(json.public_signals[11], "0");
  });

  it("REJECTs malformed gatekeeper input (fail closed, no crash)", async () => {
    const { amount, ...rest } = validGatekeeperInput();
    const { res, json } = await postAgent({
      type: "agent-games.proof-gatekeeper.v1",
      task_id: "gk_server_malformed",
      mode: "competition",
      issued_at: new Date().toISOString(),
      input: rest,
    });
    assert.equal(res.status, 200);
    assert.equal(json.decision, "REJECT");
    assert.equal(json.reason_code, "INVALID_INPUT");
    assert.equal(json.proof, null);
  });

  it("handles a Steal turn end to end (signed, schema-valid)", async () => {
    const { res, text, json } = await postAgent({
      protocolVersion: "v1",
      eventId: "steal-the-vfy",
      mode: "competition",
      matchId: "9f4e1b2a-0000-4000-8000-000000000001",
      turn: 3,
      state: {
        selfBalance: "110",
        opponentBalance: "90",
        selfFortifiedUntilTurn: null,
        opponentFortifiedUntilTurn: null,
      },
      strategyCommitment: {
        hash: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
      },
    });
    assert.equal(res.status, 200);
    assert.equal(json.matchId, "9f4e1b2a-0000-4000-8000-000000000001");
    assert.equal(json.turn, 3);
    assert.deepEqual(json.action, { type: "EXTRACT", amount: 9 });
    assert.equal(json.policyProof.circuitVersion, "v1");
    assert.match(json.policyProof.publicInputsHash, /^0x[0-9a-f]{64}$/);
    assert.ok(json.idempotencyKey);
    const sig = res.headers.get(hmac.SIGNATURE_HEADER);
    assert.equal(hmac.verify(text, sig, SECRET), true);
  });

  it("returns the cached response on a Steal resend (same matchId:turn)", async () => {
    const envelope = {
      protocolVersion: "v1",
      eventId: "steal-the-vfy",
      mode: "competition",
      matchId: "9f4e1b2a-0000-4000-8000-000000000002",
      turn: 1,
      state: {
        selfBalance: "100",
        opponentBalance: "100",
        selfFortifiedUntilTurn: null,
        opponentFortifiedUntilTurn: null,
      },
      strategyCommitment: {
        hash: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
      },
    };
    const first = await postAgent(envelope);
    const second = await postAgent(envelope);
    assert.equal(first.res.status, 200);
    assert.equal(second.text, first.text, "resend must return the identical body");
    assert.equal(
      JSON.parse(second.text).idempotencyKey,
      JSON.parse(first.text).idempotencyKey,
    );
  });
});
