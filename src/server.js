"use strict";
/**
 * server.js — HTTP service: POST /agent + GET /health.
 *
 * Pipeline for every POST /agent request:
 *   1. Read the RAW body (size-capped).
 *   2. Verify HMAC-SHA256 over the raw body BEFORE parsing (401 on failure).
 *   3. Route by envelope type (preflight / gatekeeper / steal).
 *   4. Sign every JSON response the same way.
 *
 * Fail-closed throughout: internal timeout (55 s, inside the platform's
 * 60 s hard deadline) -> HTTP 503; malformed gatekeeper input -> REJECT;
 * proof failure -> decision still returned with proof: null and a
 * proof_status explaining why (a proof is never faked).
 *
 * Idempotency: task_id (gatekeeper) and matchId:turn (steal) are cache
 * keys — a platform resend returns the exact cached response.
 */
const http = require("node:http");
const { loadConfig } = require("./config");
const hmac = require("./hmac");
const {
  REASON_CODES,
  GatekeeperInputError,
  decideGatekeeper,
  SeenProofStore,
} = require("./gatekeeper");
const { StealInputError, buildStealResponse } = require("./steal");
const { generateProof, verifyProofLocally, PUBLISHED_VK_HASH } = require("./proving");
const kurier = require("./kurier");

const PROTOCOL_VERSION = "v1";
const RESPONSE_CACHE_MAX = 2000;

/** Tiny FIFO cache: key -> { status, body } (body is the JSON string). */
class ResponseCache {
  constructor(maxEntries = RESPONSE_CACHE_MAX) {
    this.maxEntries = maxEntries;
    this.map = new Map();
  }

  get(key) {
    return key ? this.map.get(key) : undefined;
  }

  set(key, value) {
    if (!key) return;
    if (this.map.size >= this.maxEntries) {
      this.map.delete(this.map.keys().next().value);
    }
    this.map.set(key, value);
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function log(...args) {
  console.log(new Date().toISOString(), ...args);
}

/**
 * Create the HTTP server. `deps.submitProof` may override the Kurier
 * submission (used by tests to avoid real network calls).
 */
function createServer(config, deps = {}) {
  const submitProofFn = deps.submitProof || kurier.submitProof;
  const responseCache = new ResponseCache();
  const seenProofs = new SeenProofStore();

  function sendJson(res, status, obj) {
    const body = JSON.stringify(obj);
    const headers = { "content-type": "application/json" };
    if (config.hmacSecret) {
      headers[hmac.SIGNATURE_HEADER] = hmac.sign(body, config.hmacSecret);
    }
    res.writeHead(status, headers);
    res.end(body);
    return body;
  }

  function sendCached(res, cached) {
    const headers = { "content-type": "application/json" };
    if (config.hmacSecret) {
      headers[hmac.SIGNATURE_HEADER] = hmac.sign(cached.body, config.hmacSecret);
    }
    res.writeHead(cached.status, headers);
    res.end(cached.body);
  }

  // -- Gatekeeper ---------------------------------------------------------

  async function handleGatekeeper(envelope) {
    const started = Date.now();
    const taskId = typeof envelope.task_id === "string" ? envelope.task_id : "";
    const mode = typeof envelope.mode === "string" ? envelope.mode : "competition";
    const input = envelope.input || {};

    const cached = responseCache.get(taskId);
    if (cached) {
      log(`gatekeeper ${taskId} resend -> cached response`);
      return { status: cached.status, cached: true, cacheEntry: cached };
    }

    let decision;
    let reasonCode;
    try {
      const isProofReused = seenProofs.has(mode, input.proof_tx);
      ({ decision, reasonCode } = decideGatekeeper(input, { isProofReused }));
    } catch (err) {
      if (err instanceof GatekeeperInputError) {
        const body = {
          decision: "REJECT",
          reason_code: REASON_CODES.INVALID_INPUT,
          proof: null,
          public_signals: null,
          proof_tx: null,
          proof_status: "invalid_input",
          proof_error: err.message,
        };
        log(`gatekeeper ${taskId} REJECT INVALID_INPUT: ${err.message}`);
        return { status: 200, body };
      }
      throw err;
    }

    // An APPROVED task consumes its proof_tx ("accepted"); a rejected task
    // does not. Marked before proving: the decision is made either way.
    if (decision === "APPROVE") seenProofs.mark(mode, input.proof_tx);

    let proof = null;
    let publicSignals = null;
    let proofTx = null;
    let proofStatus;
    let proofError;

    if (decision === "REJECT" && reasonCode === REASON_CODES.PROOF_REUSED) {
      // No witness exists for this REJECT: all on-circuit conditions hold,
      // so the circuit only admits decision=1. Never fake a proof.
      proofStatus = "unprovable_reject";
      proofError =
        "PROOF_REUSED has no witness: all on-circuit conditions hold, so the circuit only admits decision=1 (APPROVE).";
    } else {
      try {
        const generated = await generateProof({
          track: "gatekeeper",
          circuitInputs: { ...input, task_id: taskId, decision },
        });
        const verified = await verifyProofLocally(
          generated.proof,
          generated.publicSignals,
          "gatekeeper",
        );
        if (!verified) throw new Error("local groth16.verify failed on generated proof");
        proof = generated.proof;
        publicSignals = generated.publicSignals;
        proofStatus = "verified_locally";
      } catch (err) {
        proofStatus = "proving_failed";
        proofError = err.message;
        log(`gatekeeper ${taskId} proving failed: ${err.message}`);
      }
    }

    // Optional on-chain submission (bounded; never blocks past the budget).
    if (proof && config.kurierApiKey) {
      try {
        const submitted = await submitProofFn(
          { proof, publicSignals, vkHash: PUBLISHED_VK_HASH.gatekeeper },
          {
            apiKey: config.kurierApiKey,
            apiUrl: config.kurierApiUrl,
            statusPath: config.kurierStatusPath,
          },
        );
        if (submitted.proofTx) {
          proofTx = submitted.proofTx;
          proofStatus = `submitted_${submitted.status.replace(/[^A-Za-z]/g, "")}`;
        } else {
          proofStatus = "verified_locally_kurier_failed";
          proofError = `Kurier job ${submitted.jobId || "?"}: ${submitted.status}, no tx hash`;
        }
      } catch (err) {
        proofStatus = "verified_locally_kurier_failed";
        proofError = `Kurier submit failed: ${err.message}`;
        log(`gatekeeper ${taskId} kurier failed: ${err.message}`);
      }
    }

    const body = {
      decision,
      reason_code: reasonCode,
      proof,
      public_signals: publicSignals,
      proof_tx: proofTx,
      proof_status: proofStatus,
      ...(proofError ? { proof_error: proofError } : {}),
    };
    log(
      `gatekeeper ${taskId} ${decision} ${reasonCode} ${proofStatus} ` +
        `(${Date.now() - started}ms)`,
    );
    return { status: 200, body };
  }

  // -- Steal the VFY ------------------------------------------------------

  function handleSteal(envelope) {
    const matchId = typeof envelope.matchId === "string" ? envelope.matchId : "";
    const turn = envelope.turn;
    const cacheKey = matchId && Number.isInteger(turn) ? `${matchId}:${turn}` : "";
    const cached = responseCache.get(cacheKey);
    if (cached) {
      log(`steal ${cacheKey} resend -> cached response`);
      return { status: cached.status, cached: true, cacheEntry: cached };
    }

    let body;
    try {
      body = buildStealResponse(envelope, {
        strategyCommitmentHash: config.strategyCommitment,
      });
    } catch (err) {
      if (err instanceof StealInputError) {
        // Fail safe: if matchId/turn echo cleanly, answer a minimal HOLD
        // (no hash, no proof) instead of dropping the turn entirely.
        if (matchId && Number.isInteger(turn)) {
          body = {
            matchId,
            turn,
            action: { type: "HOLD" },
            policyProof: { circuitVersion: "v1" },
            agentTimestamp: new Date().toISOString(),
            idempotencyKey: `${matchId}:${turn}:${require("node:crypto").randomUUID()}`,
          };
          log(`steal ${cacheKey} malformed state (${err.message}) -> minimal HOLD`);
        } else {
          log(`steal envelope invalid: ${err.message}`);
          return { status: 400, body: { error: "invalid_steal_envelope", detail: err.message } };
        }
      } else {
        throw err;
      }
    }

    log(
      `steal ${body.matchId}:${body.turn} ${body.action.type}` +
        (body.action.amount !== undefined ? ` ${body.action.amount}` : ""),
    );
    return { status: 200, body, cacheKey };
  }

  // -- Dispatcher ---------------------------------------------------------

  async function dispatch(envelope) {
    if (!envelope || typeof envelope !== "object") {
      return { status: 400, body: { error: "invalid_envelope" } };
    }
    if (envelope.type === "agent-games.preflight.v1") {
      return { status: 200, body: { ok: true, protocolVersion: PROTOCOL_VERSION } };
    }
    if (envelope.type === "agent-games.proof-gatekeeper.v1") {
      return handleGatekeeper(envelope);
    }
    if (
      envelope.eventId === "steal-the-vfy" ||
      envelope.type === "agent-games.steal-the-vfy.v1"
    ) {
      return handleSteal(envelope);
    }
    return { status: 400, body: { error: "unknown_type", type: envelope.type || null } };
  }

  // -- HTTP plumbing ------------------------------------------------------

  function readRawBody(req) {
    return new Promise((resolve, reject) => {
      const chunks = [];
      let size = 0;
      req.on("data", (chunk) => {
        size += chunk.length;
        if (size > config.maxBodyBytes) {
          reject(Object.assign(new Error("body too large"), { code: "BODY_TOO_LARGE" }));
          req.destroy();
          return;
        }
        chunks.push(chunk);
      });
      req.on("end", () => resolve(Buffer.concat(chunks)));
      req.on("error", reject);
    });
  }

  const server = http.createServer(async (req, res) => {
    try {
      if (req.method === "GET" && req.url === "/health") {
        sendJson(res, 200, { ok: true, protocolVersion: PROTOCOL_VERSION });
        return;
      }
      if (req.method !== "POST" || req.url !== "/agent") {
        sendJson(res, 404, { error: "not_found" });
        return;
      }

      const rawBody = await readRawBody(req);

      // HMAC gate FIRST — before parsing, before any work.
      if (!config.allowUnsigned) {
        const signature = req.headers[hmac.SIGNATURE_HEADER];
        if (!hmac.verify(rawBody, signature, config.hmacSecret)) {
          sendJson(res, 401, { error: "invalid_signature" });
          return;
        }
      }

      let envelope;
      try {
        envelope = JSON.parse(rawBody.toString("utf8"));
      } catch {
        sendJson(res, 400, { error: "invalid_json" });
        return;
      }

      // Internal 55 s budget; the platform's hard deadline is 60 s.
      const result = await Promise.race([
        dispatch(envelope),
        sleep(config.internalBudgetMs).then(() => ({ timeout: true })),
      ]);
      if (result.timeout) {
        log("internal budget exceeded -> 503 (fail closed)");
        sendJson(res, 503, { error: "internal_timeout" });
        return;
      }
      if (result.cached) {
        sendCached(res, result.cacheEntry);
        return;
      }
      const body = sendJson(res, result.status, result.body);
      // Cache successful gatekeeper/steal responses for resends.
      if (result.status === 200) {
        if (envelope.type === "agent-games.proof-gatekeeper.v1" && envelope.task_id) {
          responseCache.set(envelope.task_id, { status: 200, body });
        } else if (result.cacheKey) {
          responseCache.set(result.cacheKey, { status: 200, body });
        }
      }
    } catch (err) {
      if (err && err.code === "BODY_TOO_LARGE") {
        if (!res.writableEnded) sendJson(res, 413, { error: "body_too_large" });
        return;
      }
      log("unhandled error:", err && err.stack ? err.stack : err);
      if (!res.writableEnded) sendJson(res, 500, { error: "internal_error" });
    }
  });

  return server;
}

if (require.main === module) {
  const config = loadConfig();
  const server = createServer(config);
  server.listen(config.port, () => {
    log(`littletang-agent listening on :${config.port}`);
    if (config.allowUnsigned) {
      log("WARNING: ALLOW_UNSIGNED=1 — HMAC verification DISABLED (dev only)");
    }
    if (!config.kurierApiKey) {
      log("KURIER_API_KEY not set — proofs returned locally, proof_tx null");
    }
  });
}

module.exports = { createServer, PROTOCOL_VERSION };
