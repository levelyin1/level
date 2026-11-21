"use strict";
/**
 * config.js — environment configuration.
 *
 * Secrets come from env only and are NEVER logged. The HMAC secret is the
 * platform-generated value shown once at registration/rotation.
 */

function parseIntEnv(value, fallback) {
  const n = Number.parseInt(value, 10);
  return Number.isInteger(n) && n > 0 ? n : fallback;
}

/**
 * Load config from an env-like object (defaults to process.env).
 * Throws when the HMAC secret is missing and ALLOW_UNSIGNED is not set —
 * the server must refuse to start unsigned in production, because an
 * unsigned agent can never pass the platform's signed preflight.
 */
function loadConfig(env = process.env) {
  const allowUnsigned = env.ALLOW_UNSIGNED === "1";
  const hmacSecret = env.AGENT_GAMES_HMAC_SECRET || "";
  if (!hmacSecret && !allowUnsigned) {
    throw new Error(
      "AGENT_GAMES_HMAC_SECRET is required (platform-generated secret). " +
        "Set it in env, or set ALLOW_UNSIGNED=1 for local development only.",
    );
  }
  return {
    port: parseIntEnv(env.PORT, 3000),
    hmacSecret,
    allowUnsigned,
    kurierApiKey: env.KURIER_API_KEY || "",
    kurierApiUrl: (env.KURIER_API_URL || "https://api.kurier.xyz").replace(/\/+$/, ""),
    // The guide publishes the submit endpoint but NOT the job-status path;
    // see src/kurier.js (configurable so a wrong guess is a one-line fix).
    kurierStatusPath: env.KURIER_STATUS_PATH || "/api/v1/proof-status",
    strategyCommitment: env.STRATEGY_COMMITMENT || "",
    circuitDir: env.CIRCUIT_DIR || "",
    // Platform hard deadline is 60 s; we fail closed at 55 s.
    internalBudgetMs: parseIntEnv(env.INTERNAL_BUDGET_MS, 55000),
    maxBodyBytes: parseIntEnv(env.MAX_BODY_BYTES, 1024 * 1024),
  };
}

module.exports = { loadConfig };
