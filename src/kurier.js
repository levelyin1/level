"use strict";
/**
 * kurier.js — Kurier proof submission (zkVerify relayer, REST).
 *
 *   POST https://api.kurier.xyz/api/v1/submit-proof/${KURIER_API_KEY}
 *   {"proofType":"groth16","vkRegistered":true,
 *    "proofOptions":{"library":"snarkjs","curve":"bn128"},
 *    "proofData":{"proof":...,"publicSignals":...,"vk":"<registeredVkHash>"}}
 *
 * Poll Submitted -> IncludedInBlock -> Finalized. The tx hash is already
 * final-shaped at IncludedInBlock, so we return as soon as a tx hash
 * exists at IncludedInBlock or Finalized (waiting for Finalized alone can
 * exceed the platform's ~30 s delivery window).
 *
 * ASSUMPTION (the guide publishes the submit endpoint but NOT the
 * job-status path): polling uses GET
 * `${KURIER_API_URL}${KURIER_STATUS_PATH}/${jobId}` with the API key as an
 * `x-api-key` header. The path is configurable via KURIER_STATUS_PATH
 * (default "/api/v1/proof-status") so a wrong guess is a one-line fix.
 *
 * Without KURIER_API_KEY the server still runs: proofs are returned in the
 * response and proof_tx stays null. The API key is sent in the URL path
 * (per spec) and is NEVER logged.
 *
 * submitProof() throws on failure; the server catches and maps to
 * proof_status — a failed submission is reported, never faked.
 */

const KURIER_SUBMIT_PATH = "/api/v1/submit-proof";
/** Total budget for submit + poll, ms (inside the 55 s internal budget). */
const KURIER_TOTAL_TIMEOUT_MS = 20000;
/** Delay between status polls, ms. */
const KURIER_POLL_INTERVAL_MS = 2000;

class KurierNotConfiguredError extends Error {
  constructor() {
    super("Kurier not configured: set KURIER_API_KEY (and optionally KURIER_API_URL)");
    this.name = "KurierNotConfiguredError";
  }
}

function extractJobId(body) {
  const v = body.jobId ?? body.job_id ?? body.id ?? body.proofId ?? body.proof_id;
  return typeof v === "string" && v.length > 0 ? v : undefined;
}

function extractProofTx(body) {
  const v = body.proofTx ?? body.proof_tx ?? body.txHash ?? body.tx_hash;
  return typeof v === "string" && v.length > 0 ? v : null;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Submit a proof for on-chain verification and wait until a tx hash exists
 * (IncludedInBlock or Finalized).
 * @param {{ proof, publicSignals: string[], vkHash: string }} req
 * @param {{ apiKey, apiUrl, statusPath? }} opts
 * @returns {{ jobId: string, proofTx: string|null, status: string }}
 * @throws KurierNotConfiguredError when no API key is configured.
 * @throws on network/HTTP errors or when no tx appears within the budget.
 */
async function submitProof(req, opts) {
  if (!opts.apiKey) throw new KurierNotConfiguredError();
  const base = opts.apiUrl.replace(/\/+$/, "");
  const statusPath = opts.statusPath || "/api/v1/proof-status";
  const deadline = Date.now() + KURIER_TOTAL_TIMEOUT_MS;

  const submitRes = await fetch(
    `${base}${KURIER_SUBMIT_PATH}/${encodeURIComponent(opts.apiKey)}`,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        proofType: "groth16",
        vkRegistered: true,
        proofOptions: { library: "snarkjs", curve: "bn128" },
        proofData: {
          proof: req.proof,
          publicSignals: req.publicSignals,
          vk: req.vkHash,
        },
      }),
      signal: AbortSignal.timeout(KURIER_TOTAL_TIMEOUT_MS),
    },
  );
  if (!submitRes.ok) {
    throw new Error(`Kurier submit failed: HTTP ${submitRes.status}`);
  }
  const submitted = await submitRes.json();
  const jobId = extractJobId(submitted);
  let status = typeof submitted.status === "string" ? submitted.status : "Submitted";
  let proofTx = extractProofTx(submitted);
  if ((status === "Finalized" || status === "IncludedInBlock") && proofTx) {
    return { jobId: jobId || "", proofTx, status };
  }
  if (!jobId) {
    throw new Error("Kurier submit response has no job id");
  }

  // Poll until a tx hash exists at IncludedInBlock/Finalized, or timeout.
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${base}${statusPath}/${encodeURIComponent(jobId)}`, {
        method: "GET",
        headers: { "x-api-key": opts.apiKey },
        signal: AbortSignal.timeout(KURIER_POLL_INTERVAL_MS + 1000),
      });
      if (res.ok) {
        const job = await res.json();
        if (typeof job.status === "string") status = job.status;
        proofTx = extractProofTx(job) || proofTx;
        if ((status === "Finalized" || status === "IncludedInBlock") && proofTx) {
          return { jobId, proofTx, status };
        }
      }
    } catch {
      // Transient poll failure: keep polling until the deadline.
    }
    await sleep(KURIER_POLL_INTERVAL_MS);
  }
  // Timed out: report what we know, never a fake tx.
  return { jobId, proofTx, status: `${status} (poll timeout)` };
}

module.exports = {
  KURIER_SUBMIT_PATH,
  KURIER_TOTAL_TIMEOUT_MS,
  KURIER_POLL_INTERVAL_MS,
  KurierNotConfiguredError,
  submitProof,
};
