# littletang-agent — circuits

Official zkVerify Agent Games Groth16 circuits (BN128, Circom 2.x), used
via `snarkjs`. No local Circom build, no trusted setup — the platform
publishes the artifacts and we prove against them.

## Layout

| Path | Committed? | Notes |
|---|---|---|
| `artifacts/gatekeeper.wasm` | No (gitignored) | Proving witness generator |
| `artifacts/gatekeeper_final.zkey` | No (gitignored) | Proving key |
| `artifacts/vfy-policy.wasm` | No (gitignored) | Steal policy circuit |
| `artifacts/vfy-policy_final.zkey` | No (gitignored) | Steal proving key |
| `artifacts/circuit-info.json` | No (gitignored) | Live copy of `/api/circuit-info` |
| `artifacts/CHECKSUMS.txt` | No (generated) | SHA-256 of the downloaded files |
| `gatekeeper.vkey.json` | **Yes** | Verification key exported from the zkey (`snarkjs zkey export verificationkey`) — used for local proof verification |
| `vfy-policy.vkey.json` | **Yes** | Same, for the Steal circuit (nPublic 9) |
| `CHECKSUMS.txt` | **Yes** | Expected SHA-256 checksums |
| `PROBE.md` | **Yes** | Live probe evidence (input names, signal order, boundaries) |

## Download

```sh
bash scripts/download-artifacts.sh   # idempotent; verifies checksums
```

Source: https://agentgames.zkverify.io/api/circuit-info

```json
{"network":"mainnet","circuits":{
 "gatekeeper":{"vkHash":"0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
  "artifacts":{"wasm":"https://agentgames.zkverify.io/circuits/gatekeeper.wasm",
               "zkey":"https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey"}},
 "vfyPolicy":{"vkHash":"0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047",
  "artifacts":{"wasm":"https://agentgames.zkverify.io/circuits/vfy-policy.wasm",
               "zkey":"https://agentgames.zkverify.io/circuits/vfy-policy_final.zkey"}}}}
```

## Gatekeeper circuit (fully usable)

- 13 public signals, 13 inputs, 1 private (`salt`).
- Input names: `registeredVkHash, proofVkHash, minimum, publicBalance,
  expiryBlock, currentBlock, recipient, conditionRecipient, amount,
  maxTransfer, decision, taskId, salt`.
- Public-signal order: `[Poseidon(salt, taskId), registeredVkHash,
  proofVkHash, minimum, publicBalance, expiryBlock, currentBlock,
  recipient, conditionRecipient, amount, maxTransfer, decision, taskId]`.
- `decision`: 1 = APPROVE, 0 = REJECT. The circuit asserts
  `decision == evaluated condition` — a wrong decision cannot even produce
  a witness (verified live, see PROBE.md).
- Boundaries verified live: `current_block == expiry_block` is EXPIRED;
  `amount == 0` is VALID.

## vfyPolicy circuit (Steal — proofs blocked)

- 9 public signals, 17 inputs, 8 private.
- Recovered names (9/17): `commitment, matchId, turnNumber, selfBalance,
  opponentBalance, action, amount, circuitVersion, salt`.
- The remaining 8 private policy input names are NOT published anywhere
  and cannot be guessed. Steal proofs therefore cannot be generated;
  `generateProof("steal")` throws an honest error and the Steal response
  carries only the published `publicInputsHash`. See SPEC.md.
