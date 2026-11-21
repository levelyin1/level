# littletang-agent

Agent **littletang** for the zkVerify **Agent Games Season 01** — dual
track: **Proof Gatekeeper** + **Steal the VFY**.

Plain Node.js (no build step, no web framework), Groth16 proofs via
`snarkjs` against the platform's official circuits. Every decision is
deterministic; every response is HMAC-signed; a proof is never faked.

## Quick start

```sh
npm install
bash scripts/download-artifacts.sh   # official .wasm/.zkey (checksum-verified)
cp .env.example .env                 # fill AGENT_GAMES_HMAC_SECRET
npm start                            # POST /agent + GET /health on :3000
npm test                             # 73 tests, ~9 s
```

Requires Node 20+. `AGENT_GAMES_HMAC_SECRET` is the platform-generated
secret shown once at registration/rotation — the server refuses to start
without it (unless `ALLOW_UNSIGNED=1`, local dev only).

## How it works

```
POST /agent
  ├─ 1. HMAC-SHA256 over the RAW body vs x-agent-games-signature
  │     (verified BEFORE JSON parsing; mismatch → HTTP 401)
  ├─ 2. type = "agent-games.preflight.v1"
  │     → signed { ok: true, protocolVersion: "v1" }
  ├─ 3. type = "agent-games.proof-gatekeeper.v1"
  │     ├─ idempotency cache (same task_id → cached response)
  │     ├─ deterministic policy (src/gatekeeper.js) → decision + reason_code
  │     ├─ snarkjs fullProve with the official gatekeeper circuit
  │     │    (skipped only for PROOF_REUSED — it has no witness)
  │     ├─ local groth16.verify sanity check
  │     ├─ optional Kurier submit + bounded poll (≤20 s) → proof_tx
  │     └─ signed JSON response (55 s internal budget, 503 on timeout)
  └─ 4. eventId = "steal-the-vfy"
        ├─ idempotency cache (same matchId:turn → cached response)
        ├─ committed policy (src/steal.js) → HOLD / FORTIFY / EXTRACT
        ├─ publicInputsHash (keccak256, published 8-field spec)
        └─ signed JSON response (no policy proof — see Limitations)
```

### Gatekeeper decision rule

APPROVE only when ALL hold: `proof_vk == registered_vk`,
`public_balance >= minimum`, `current_block < expiry_block`,
`recipient == condition_recipient`, `amount <= max_transfer`, and the
incoming `proof_tx` was not previously accepted. Otherwise REJECT with
`VK_SUBSTITUTION`, `THRESHOLD_MISMATCH`, `EXPIRED_CONDITION`,
`RECIPIENT_MISMATCH`, `AMOUNT_OVERFLOW`, or `PROOF_REUSED`.

Two boundaries were settled by **live probes against the official
circuit** (see `circuits/PROBE.md`), not by reading docs:
`current_block == expiry_block` is EXPIRED, and `amount == 0` is VALID.
The circuit is the referee — a decision it disagrees with cannot even
produce a witness.

### Steal policy (committed)

- **EXTRACT** `min(10, floor(opponent × 0.10))` when ahead-or-even and the
  opponent is not fortified.
- **FORTIFY** (costs 2, blocks up to 6) when behind and we can afford it.
- **HOLD** otherwise.

Golden rule: a missing proof resolves as HOLD, but an *invalid* proof
costs −2/turn — so we send no proof rather than a wrong one.

## Deploy (Fly.io)

```sh
fly launch --no-deploy            # or: fly apps create littletang-agent
fly secrets set AGENT_GAMES_HMAC_SECRET=<platform secret>
fly secrets set KURIER_API_KEY=<key>        # optional
fly deploy
curl https://littletang-agent.fly.dev/health
```

`fly.toml` pins region `sin`, always-on (`min_machines_running = 1`,
`auto_stop_machines = "off"`), health check `GET /health`. The Dockerfile
downloads the circuit artifacts at build time (checksum-verified), so the
image is self-contained.

## Register

1. Deploy and confirm `GET /health` returns
   `{ ok: true, protocolVersion: "v1" }`.
2. In the Agent Games dashboard, register the agent with the public
   endpoint `https://<app>.fly.dev/agent` (full path) and the repository URL
   (`https://github.com/levelyin1/level`).
3. Copy the platform-generated HMAC secret into
   `fly secrets set AGENT_GAMES_HMAC_SECRET=...` and redeploy.
4. Pass the signed preflight, then run a practice task/turn.
5. For Steal: register the strategy commitment before Swiss Round 1 opens
   (the platform cannot pair an agent without an active commitment).

## Layout

| Path | Job |
|---|---|
| `src/server.js` | HTTP server: raw body, HMAC gate, routing, 55 s budget |
| `src/hmac.js` | HMAC-SHA256 sign/verify (constant-time compare) |
| `src/gatekeeper.js` | Gatekeeper decision policy + proof_tx replay store |
| `src/steal.js` | Steal 20-turn policy + response builder |
| `src/proving.js` | Groth16 proving (snarkjs) + Steal publicInputsHash |
| `src/kurier.js` | Kurier proof submission + Finalized polling |
| `src/config.js` | Env config (secrets from env only, never logged) |
| `circuits/` | Official circuit docs, verification keys, checksums, probes |
| `scripts/download-artifacts.sh` | Idempotent artifact download + checksum verify |
| `tests/` | `node:test` suites (HMAC, gatekeeper, steal, proving, server) |
| `SPEC.md` | Protocol summary + implementation decisions |

## Limitations (honest)

- **Steal policy proofs cannot be generated.** The vfyPolicy circuit has
  17 inputs but only 9 names are recoverable from the published material;
  the 8 private policy input names are unpublished and cannot be guessed.
  `generateProof("steal")` throws an honest error; Steal responses carry
  the published `publicInputsHash` and no proof. Per the field guide, a
  turn without a proof is resolved as HOLD — so Steal turns currently
  score through the action + hash only. If the platform publishes the
  missing input names, proving can be switched on in `src/proving.js`
  (config + constants, no new ceremony).
- **Steal entry may already be closed.** Per the spec snapshot (15 Nov),
  the Steal tournament was already paired (Round 2) and entries lock once
  paired. The track is implemented fully, but registration may refuse a
  new Steal entry.
- **Gatekeeper rounds lock entries while open** (17:30–03:30 WIB daily);
  registration can only complete between rounds.
- **Replay + idempotency state is in-memory.** A server restart clears
  the seen `proof_tx` set and the response cache. A restart could miss
  one PROOF_REUSED trap; a resend after a restart is recomputed (same
  deterministic decision, fresh proof/salt).
- **taskId encoding is an assumption.** Alphanumeric task ids are encoded
  as the big-endian integer of their UTF-8 bytes (the platform's encoding
  is unpublished). The proof verifies cryptographically either way; only
  the platform's reading of public signal 12 depends on the encoding.
- **Kurier job-status path is an assumption.** The guide publishes the
  submit endpoint but not the status path; polling uses
  `GET /api/v1/proof-status/{jobId}` (configurable via
  `KURIER_STATUS_PATH`). A wrong guess costs only the on-chain `proof_tx`
  — the local proof is still returned.
- **Fortification boundary is an assumption.** `opponentFortifiedUntilTurn`
  is treated as inclusive (fortified through that turn). The conservative
  reading: when in doubt we HOLD instead of extracting into a fortify.
- **Missing-proof scoring is ambiguous.** The task brief says a missing
  Steal proof resolves as HOLD (0 points); the field guide's "common
  mistakes" section says such turns score −2. Either way, sending no proof
  is never worse than sending an invalid one, and a valid one cannot be
  built until the platform publishes the missing input names.

## Security

- No secrets in code, logs, or the repo. Secrets come from env /
  `fly secrets` only. The vkHashes are public platform constants.
- HMAC is verified on the raw body before any parsing; every response is
  signed the same way.
- A proof is never fabricated: proving failures return `proof: null` with
  a `proof_status` explaining why, and the decision is still returned.
