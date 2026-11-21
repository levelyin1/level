# SPEC.md — protocol summary + implementation decisions

Source of truth for the protocol implemented in this repo. Summarized from
the official Builder Field Guide (https://agentgames.zkverify.io/build),
the live `/api/circuit-info` endpoint (read 2026-11-21), and the
transcribed official spec in the public reference repo
`xomplex/muse-agent` (SPEC.md, read 2026-11-15). Where this repo's live
probes contradict the written spec, the **circuit wins** — see
"Circuit-verified facts" below.

## Timeline

- Season 01: 21 Oct – 21 Nov 2026. Judgement/results: 22–30 Nov 2026.
- Gatekeeper: 8 daily scored rounds 13–21 Nov, 17:30–03:30 WIB,
  8 tasks/agent/round, cumulative score. Entries LOCK while a round is open.
- Steal the VFY: Swiss rounds + Top 16 knockout. As of 15 Nov the
  tournament was already paired (Round 2) — a new Steal entry is very
  likely CLOSED (see README Limitations).
- Entry requires: authenticated account + prize-eligibility identity
  (connected GitHub account + connected wallet address), registered HTTPS
  endpoint passing health check, completed signed preflight, ≥1 practice
  task/turn (+ registered strategy commitment for Steal).
- One agent per owner per arena event. Practice mode: 10 dispatches per
  active agent per hour, no leaderboard effect.

## Endpoint + HMAC

- JSON POST to the registered public HTTPS endpoint with full handler path
  (e.g. `/agent`). No localhost, no private IP, no custom port.
  Response 200 `application/json`.
- `task_id` is the idempotency key; the platform may resend after network
  failure — the server answers a resend deterministically (cached response).
- **Every inbound request** carries header `x-agent-games-signature` =
  **HMAC-SHA256 (hex) over the RAW body**. Verified BEFORE parsing.
- **Every response** is signed the same way (same header, over the raw
  response body).
- Secret: a 32-byte random created by the platform, shown ONCE at
  registration/rotation, rotatable from agent settings. Env:
  `AGENT_GAMES_HMAC_SECRET`. Never committed.

## Preflight

Inbound: `{"type": "agent-games.preflight.v1", "agent_id": "agt_...",
"issued_at": "...", "nonce": "abc123"}`
Reply: `{"ok": true, "protocolVersion": "v1"}` with a valid signature header.

## Proof Gatekeeper

Inbound envelope:

```json
{"type": "agent-games.proof-gatekeeper.v1", "task_id": "gk_...",
 "mode": "competition", "issued_at": "...", "deadline_at": "...",
 "input": {"registered_vk": "...", "proof_vk": "...", "minimum": "1000",
 "public_balance": "1460", "expiry_block": 8430000, "current_block": 8420000,
 "recipient": "0x...", "condition_recipient": "0x...", "amount": "500",
 "max_transfer": "1000", "proof_tx": "0x..."}}
```

Response: `{"decision": "APPROVE"|"REJECT", "reason_code": "..."}` plus
on every provable task the Groth16 `proof` + `public_signals`; `proof_tx`
is optional if the proof was already submitted to zkVerify. This repo
also returns `proof_status` (and `proof_error` when the proof is null)
to explain the proof state honestly.

**Decision rule (exact, circuit-verified):** APPROVE ONLY when ALL hold —
`proof_vk == registered_vk` AND `public_balance >= minimum` AND
`current_block < expiry_block` AND `recipient == condition_recipient` AND
`amount <= max_transfer` AND the incoming proof is not reused.
Otherwise REJECT with the matching reason code.

Reason codes: `VALID_CONDITION`, `VK_SUBSTITUTION`, `THRESHOLD_MISMATCH`,
`PROOF_REUSED`, `EXPIRED_CONDITION`, `RECIPIENT_MISMATCH`,
`AMOUNT_OVERFLOW`. (`INVALID_INPUT` is this repo's own code for malformed
envelopes — not a trap code.)

Scoring: correct decision +12, incorrect APPROVE −6, incorrect REJECT −3,
missing/invalid proof −2, timeout −2, reliability bonus +0..+5.
Timeout: 60 seconds hard (`deadline_at`). This repo fails closed at 55 s
(HTTP 503).

## Steal the VFY

Inbound turn envelope:

```json
{"protocolVersion": "v1", "eventId": "steal-the-vfy", "mode": "competition",
 "matchId": "9f4e1b2a-...", "turn": 3, "issuedAt": "...", "deadlineAt": "...",
 "state": {"selfBalance": "95", "opponentBalance": "105",
 "selfFortifiedUntilTurn": null, "opponentFortifiedUntilTurn": null},
 "strategyCommitment": {"hash": "0x..."}, "resolverVersion": "v1", "nonce": "..."}
```

Response:

```json
{"matchId": "...", "turn": 3, "action": {"type": "EXTRACT", "amount": 5},
 "policyProof": {"circuitVersion": "v1", "proofReference": "0x...",
 "publicInputsHash": "0x..."}, "agentTimestamp": "...", "idempotencyKey": "..."}
```

- **Actions:** HOLD (steals 0), FORTIFY (costs 2 VFY, blocks up to 6
  incoming extraction that turn), EXTRACT N (steals up to N, **max 10**).
  `action.amount` must be **OMITTED entirely** for HOLD/FORTIFY.
- `idempotencyKey` must never repeat across turns. `matchId`/`turn` must
  echo the envelope exactly. Turn deadline 5 minutes; platform waits ~30 s
  per push. Missed turn = HOLD −1; invalid policy proof −2/turn. Match is
  20 turns. Scores: win +18, draw +9, loss +3, reliability +0..+2.
- **Policy (this repo):** EXTRACT `min(10, floor(opponent × 0.10))` when
  ahead-or-even and the opponent is not fortified; FORTIFY when behind
  and the 2 VFY cost is affordable; HOLD otherwise.

## Groth16 circuits (official, published)

Circuit-info API: https://agentgames.zkverify.io/api/circuit-info

- gatekeeper vkHash:
  `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`
- vfyPolicy vkHash:
  `0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047`

Groth16 / BN128, Circom 2.x, snarkjs, prove locally. Artifacts:
`https://agentgames.zkverify.io/circuits/{gatekeeper.wasm,
gatekeeper_final.zkey, vfy-policy.wasm, vfy-policy_final.zkey}`.
Checksums: `circuits/CHECKSUMS.txt`.

**Steal publicInputsHash (PUBLISHED — implemented exactly):** keccak256
over 8 fields, each 32-byte big-endian, in this order:
1. `strategyCommitment.hash`
2. `matchId` (hyphens stripped, as integer)
3. `turn`
4. `selfBalance`
5. `opponentBalance`
6. `action` (HOLD=0, FORTIFY=1, EXTRACT=2)
7. `amount` (0 for HOLD/FORTIFY)
8. circuitVersion `"v1"` (=1)

**Gatekeeper ordered public_signals (VERIFIED LIVE):**
`[Poseidon(salt, taskId), registeredVkHash, proofVkHash, minimum,
publicBalance, expiryBlock, currentBlock, recipient, conditionRecipient,
amount, maxTransfer, decision, taskId]`. All 13 input names:
`registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
currentBlock, recipient, conditionRecipient, amount, maxTransfer,
decision, taskId, salt` (`salt` is the only private input). `decision`
is 1 = APPROVE, 0 = REJECT, and the circuit asserts
`decision == evaluated condition`.

**vfyPolicy input names: 9/17 recovered** (`commitment, matchId,
turnNumber, selfBalance, opponentBalance, action, amount,
circuitVersion, salt`); the remaining 8 inputs are private policy inputs
whose names are NOT published and cannot be guessed. Steal proofs
therefore cannot be generated — `generateProof("steal")` throws an
honest error, never a fake proof. The Steal response still carries the
published `publicInputsHash`.

## Circuit-verified facts (live probes, 2026-11-21 — circuits/PROBE.md)

These override the written spec where they conflict; each was established
by a real fullProve + local-verify round-trip:

1. `current_block == expiry_block` is EXPIRED (decision=1 fails witness
   generation; decision=0 verifies). The written spec's `<=` is wrong at
   the boundary; the implementation uses strict `<` for APPROVE.
2. `amount == 0` is VALID (decision=1 verifies; decision=0 fails).
3. A wrong decision cannot produce a witness at all.
4. Public-signal order confirmed as above; signal 0 changes with `salt`
   only (Poseidon commitment).
5. vk hashes exceed the BN128 field modulus and are reduced mod p by
   snarkjs (both sides reduce identically; equality checks still work).
6. `fullProve` takes ~0.4 s on the build VM — far inside the 60 s budget.

## Proof submission (Kurier — recommended)

- `POST https://api.kurier.xyz/api/v1/submit-proof/${KURIER_API_KEY}` with
  `{"proofType": "groth16", "vkRegistered": true,
    "proofOptions": {"library": "snarkjs", "curve": "bn128"},
    "proofData": {"proof": ..., "publicSignals": ...,
    "vk": "<registeredVkHash>"}}`.
- Poll Submitted → IncludedInBlock → Finalized ("Safe to return as
  confirmed"). This repo returns as soon as a tx hash exists at
  IncludedInBlock or Finalized (the hash is final-shaped at inclusion;
  waiting for Finalized alone can exceed the platform's ~30 s window).
- `KURIER_API_KEY` comes from env; without it the server still runs with
  local proofs and `proof_tx: null`. zkVerifyJS is the alternative path.

## Implementation decisions (this repo)

1. **Reason-code priority:** on-circuit violations are checked before
   PROOF_REUSED (VK → THRESHOLD → EXPIRED → RECIPIENT → AMOUNT →
   PROOF_REUSED), so a REJECT the circuit can prove is proven. A
   PROOF_REUSED reject has no witness when all on-circuit conditions hold
   (the circuit only admits decision=1 there), so it returns
   `proof: null` + `proof_status: "unprovable_reject"`.
2. **Replay marking:** a `proof_tx` is marked seen only when its task is
   APPROVED ("accepted"), keyed per mode (competition vs practice).
   In-memory only (see README Limitations).
3. **Local verification:** every generated proof is verified locally with
   `groth16.verify` before being attached to the response.
4. **Fail-closed timeout:** 55 s internal budget → HTTP 503. Malformed
   gatekeeper input → REJECT + `INVALID_INPUT`. Malformed Steal state
   with a clean matchId/turn → minimal HOLD response.
5. **No secrets in the repo.** `.wasm`/`.zkey` artifacts are gitignored
   and downloaded at build time with checksum verification;
   `verification_key.json` files are committed for local verification.

## Assumptions (not published anywhere — do NOT treat as spec)

- `taskId` encoding: alphanumeric ids → big-endian integer of UTF-8 bytes.
- Kurier job-status path: `GET /api/v1/proof-status/{jobId}`
  (configurable via `KURIER_STATUS_PATH`).
- `opponentFortifiedUntilTurn` is inclusive (fortified through that turn).
- Missing-Steal-proof scoring: brief says HOLD/0, field guide says −2
  (see README Limitations).
- `matchId` must be a UUID (`parseStealEnvelope` in `src/steal.js`):
  an implicit assumption, consistent with the hash input needs; the
  server falls back to a minimal HOLD response if the envelope is
  rejected.
- Whether a registered agent can be edited later, and the "3 agent slots"
  rule, are not stated anywhere readable.
