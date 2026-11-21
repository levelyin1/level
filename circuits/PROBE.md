# PROBE.md — live evidence for the gatekeeper circuit

Probed 2026-11-21 against the official artifacts
(`scripts/probe-boundary.mjs`, snarkjs 0.7.6, Node 24). Every claim below
was established by a real `fullProve` + local `groth16.verify` round-trip,
not by reading documentation.

## Setup

- `gatekeeper.wasm` sha256 `be00aefe…92764f`, `gatekeeper_final.zkey`
  sha256 `adfe95a4…af80d` (both match the published checksums).
- Exported VK: `nPublic: 13`, curve `bn128`, protocol `groth16`.
- `vfy-policy` VK: `nPublic: 9`, curve `bn128`, protocol `groth16`.

## Results (9 probe cases)

| # | Case | Outcome |
|---|---|---|
| A | All conditions true, decision=1 | WITNESS OK, verify: true |
| B | `current == expiry`, decision=1 | WITNESS FAILED (Assert Failed, GatekeeperEvaluation line 102) |
| C | `current == expiry`, decision=0 | WITNESS OK, verify: true |
| D | `amount = 0`, decision=1 | WITNESS OK, verify: true |
| E | `amount = 0`, decision=0 | WITNESS FAILED (Assert Failed) |
| F | `amount > max`, decision=0 | WITNESS OK, verify: true |
| G | `amount > max`, decision=1 | WITNESS FAILED (Assert Failed) |
| H | All conditions true, decision=0 | WITNESS FAILED (Assert Failed) |
| I | Same as A with a different salt | WITNESS OK; only signal 0 changed |

## Conclusions (encoded in src/gatekeeper.js)

1. **Expiry boundary: `current_block >= expiry_block` is EXPIRED.**
   The spec text says APPROVE requires `current_block <= expiry_block`,
   but the circuit disagrees at the boundary (B fails, C verifies). The
   circuit is the referee — a decision it disagrees with cannot even
   produce a witness — so the implementation uses strict `<` for APPROVE.
2. **`amount == 0` is VALID** (D verifies, E fails). No lower bound on
   amount is enforced on-circuit. Negative amounts cannot be circuit
   inputs at all and are rejected as malformed (`INVALID_INPUT`, no proof).
3. **A wrong decision cannot produce a witness** (G, H). The circuit
   asserts `decision == evaluated condition`.
4. **Public-signal order confirmed:** signals[1..12] =
   `[registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
   currentBlock, recipient, conditionRecipient, amount, maxTransfer,
   decision, taskId]`. Signal 0 changes with `salt` only (Poseidon
   commitment over `[salt, taskId]`).
5. **vk hashes exceed the field modulus** and are reduced mod p by snarkjs
   before reaching the circuit (e.g. `0x6b79…77b0` becomes
   `4836144126…2814510`). Both sides reduce identically, so the equality
   check still works. `tests/proving.test.js` asserts the reduced value.
6. **Timing:** ~0.4 s per `fullProve` on this VM — far inside the 60 s
   platform budget.

## Steal publicInputsHash reference vectors

Computed independently with pycryptodome keccak (Python) + manual ABI
packing; asserted in `tests/proving.test.js`:

| # | Inputs (commitment, matchId, turn, self, opp, action, amount) | Hash |
|---|---|---|
| V1 | `0x1234…cdef`, `9f4e1b2a-0000-4000-8000-000000000001`, 3, 95, 105, EXTRACT, 5 | `0x79a0d3317cc5a7bb592ffe3a22ec637e1f1c32bc905b5dacb5ffcb833dc6ffa1` |
| V2 | `0x0`, `00000000-0000-0000-0000-000000000000`, 0, 0, 0, HOLD, 0 | `0x11934057fe979f7d236d4bfe0cfcb7b2b1d5f4145867576ef0d8026fdcb33ab0` |
| V3 | `0xffff…ffff`, `ffffffff-ffff-4fff-8fff-ffffffffffff`, 20, 2, 198, FORTIFY, 0 | `0xca5c292858fd141e32437d35db9ddeed69f3d7534afa8f0e1d51634fa2d3c4de` |
