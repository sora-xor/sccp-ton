# sccp-ton

SORA Cross-Chain Protocol (SCCP) components for TON (Jetton-based).

This repo contains:
- The canonical SCCP message format (`SPEC.md`)
- A Jetton master + wallet implementation in **Tolk** with SCCP extensions (burn records + verifier-gated minting)
- A trustless SORA->TON verifier contract (`contracts/sccp-sora-verifier.tolk`) that implements a BEEFY+MMR light client on TON

Compiler/tooling:
- `@ton/tolk-js` (Tolk v1.2.0)

## Notes

TON does not share EVM's log/event model; SCCP "proof of burn" is expected to be based on
state (burn record cells) and/or transaction proofs, verified by a dedicated on-chain
verifier/light client on the destination chain.

For SORA->TON, this repo uses the same approach as the EVM/Solana SCCP verifiers:
- finalized SORA MMR roots are imported permissionlessly by verifying BEEFY commitments (validator signatures + merkle membership proofs)
- SCCP burn proofs are verified via MMR inclusion + auxiliary digest commitment, then forwarded to the Jetton master for minting
- verifier hardening: ECDSA signatures must have non-zero `r/s` and canonical low-`s` (`s <= secp256k1n/2`)
- verifier hardening: duplicate validator signer addresses in a commitment proof are rejected (fail-closed)
- router hardening: TON jetton wallet/master reject unsupported SCCP domain ids in burn/mint/pause flows

## Non-SORA -> TON (Via SORA Attestation)

TON minting is not restricted to burns that originated on SORA.

If SORA verifies a burn that originated on another chain (e.g., `ETH -> TON`) and commits the burn `messageId`
into its auxiliary digest (via the SORA runtime extrinsic `sccp.attest_burn`), this repo can mint on TON by sending
the verifier message:

- `SccpVerifierMintFromSoraProofV2` (opcode `0x1a9b2c7e`)

This message includes an explicit `sourceDomain` and computes `messageId` as:

`keccak256("sccp:burn:v1" || BurnPayloadV1(sourceDomain, DOMAIN_TON, ...))`

## Proofs To SORA (TON As Source Chain)

Inbound proofs from TON to SORA are defined on SORA as:

- default mode: `TonLightClient` for `DOMAIN_TON`
- semantics: shard burn inclusion + masterchain finality verification
- current runtime status: fail-closed on SORA until TON masterchain light-client verification is integrated
- practical fallback: SORA governance can switch `DOMAIN_TON` to `AttesterQuorum` (CCTP-style threshold signatures over `messageId`)

This repo already provides trustless SORA -> TON verification (BEEFY+MMR on TON), while TON -> SORA mint/attestation remains intentionally disabled until the SORA-side TON light client is integrated.

### AttesterQuorum Proof Bytes

When SORA uses `InboundFinalityMode::AttesterQuorum`, users submit only attester signatures to SORA (no TON light-client proof).

Signatures are over:

`attestHash = keccak256("sccp:attest:v1" || messageId)`

Proof bytes passed to `sccp.mint_from_proof` are:

`0x01 || SCALE(Vec<[u8;65]>)`

Helper (encode from signatures or sign locally for testing):

```bash
npm run encode-attester-proof -- --message-id 0x<messageId32> --sig 0x<sig65> --sig 0x<sig65>
# or:
npm run encode-attester-proof -- --message-id 0x<messageId32> --privkey 0x<key32> --privkey 0x<key32>
```

## Proof Inputs From `bridge-relayer`

Use the sibling `bridge-relayer` repo to fetch SORA-finality proof components:

- `sccp ton init --query-id 0 --block <sora_block>`
- `sccp ton import-root --justification-block <beefy_block> --query-id 0`
- `sccp ton mint-proof --burn-block <burn_block> --beefy-block <beefy_block> --message-id 0x...`

`sccp ton init` outputs verifier-ready initialize message body:
- `message_body_boc_hex` / `message_body_boc_base64`

`sccp ton import-root` outputs verifier-ready cells:
- `validator_proof_cell_boc_hex` / `validator_proof_cell_boc_base64`
- `latest_leaf_proof_cell_boc_hex` / `latest_leaf_proof_cell_boc_base64`
- `submit_message_body_boc_hex` / `submit_message_body_boc_base64`

This command already outputs the verifier-ready proof cell BOC:
- `proof_cell_boc_hex`
- `proof_cell_boc_base64`

The helper script is still available for re-encoding historical JSON:
- `node scripts/encode_sora_proof_cell.mjs --input ./mint-proof.json --format both`
- `npm run encode-proof-cell -- --input ./mint-proof.json --format both`

## Build

```bash
npm install
npm run build
```

Artifacts are written to `artifacts/` as JSON (`*.compiled.json`) and include `codeBoc64`.

## Derive IDs For SORA Config

For SORA SCCP configuration for TON:
- `remote_token_id` (32 bytes) is the Jetton master **account-id** (`address.hash`) hex.
- `domain_endpoint` (32 bytes) can be set to the SCCP Jetton master **code hash** (`codeHashHex`) as a stable identifier.

Helper:

```bash
node scripts/derive_master_address.mjs --governor <ton_addr> --sora-asset-id <64hex>
```
