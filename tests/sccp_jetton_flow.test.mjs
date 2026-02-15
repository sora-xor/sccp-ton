import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { Blockchain } from '@ton/sandbox';
import {
  beginCell,
  Cell,
  contractAddress,
  Dictionary,
  SendMode,
} from '@ton/core';
import { ethers } from 'ethers';

const repoRoot = resolve(import.meta.dirname, '..');

// Opcodes from `contracts/messages.tolk`.
const TOP_UP_TONS = 0xd372158c;
const SCCP_SET_VERIFIER = 0x0f95e281;
const SCCP_SET_INBOUND_PAUSED = 0x3bf64dc2;
const SCCP_SET_OUTBOUND_PAUSED = 0x91f4c2a7;
const SCCP_INVALIDATE_INBOUND = 0x4a28c9d7;
const SCCP_MINT_FROM_VERIFIER = 0x23e4c1a0;
const SCCP_BURN_TO_DOMAIN = 0x4f80d7e1;
const SCCP_VERIFIER_INITIALIZE = 0x35f2bca1;
const SCCP_VERIFIER_SUBMIT_SIGNATURE_COMMITMENT = 0x6a4df0b3;
const SCCP_VERIFIER_MINT_FROM_SORA_PROOF = 0x1a9b2c7d;
const SCCP_VERIFIER_MINT_FROM_SORA_PROOF_V2 = 0x1a9b2c7e;

// SCCP domains (must match other repos + SORA pallet).
const DOMAIN_SORA = 0;
const DOMAIN_ETH = 1;
const DOMAIN_TON = 4;

// Errors from `contracts/errors.tolk`.
const ERROR_SCCP_DOMAIN_UNSUPPORTED = 1000;
const ERROR_SCCP_INBOUND_PAUSED = 1001;
const ERROR_SCCP_MESSAGE_INVALIDATED = 1002;
const ERROR_SCCP_MESSAGE_ALREADY_PROCESSED = 1003;
const ERROR_SCCP_VERIFIER_NOT_SET = 1004;
const ERROR_SCCP_RECIPIENT_NOT_CANONICAL = 1009;
const ERROR_SCCP_UNKNOWN_MMR_ROOT = 1010;
const ERROR_SCCP_COMMITMENT_NOT_FOUND = 1012;
const ERROR_SCCP_VERIFIER_NOT_INITIALIZED = 1015;
const ERROR_SCCP_INVALID_VALIDATOR_PROOF = 1019;
const ERROR_SCCP_INVALID_SIGNATURE = 1020;
const ERROR_SCCP_OUTBOUND_PAUSED = 1021;
const SECP256K1N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

function loadArtifact(name) {
  return JSON.parse(readFileSync(resolve(repoRoot, 'artifacts', name), 'utf8'));
}

function codeFromArtifact(artifact) {
  return Cell.fromBoc(Buffer.from(artifact.codeBoc64, 'base64'))[0];
}

function addressToU256(addr) {
  return BigInt('0x' + addr.hash.toString('hex'));
}

function txExitCode(tx) {
  if (tx.description?.computePhase?.type === 'vm') {
    return tx.description.computePhase.exitCode;
  }
  return null;
}

function findTxByAddress(txs, addr) {
  const target = BigInt('0x' + addr.hash.toString('hex'));
  return txs.find((t) => t.address === target);
}

function buildMasterData({ governor, verifier, walletCode, metadataUri, soraAssetIdU256 }) {
  const emptyBoolMap = Dictionary.empty(Dictionary.Keys.BigUint(256), Dictionary.Values.Bool());
  const emptyBurnsMap = Dictionary.empty(Dictionary.Keys.BigUint(256), Dictionary.Values.Cell());

  const sccpExtraB = beginCell();
  sccpExtraB.storeUint(soraAssetIdU256, 256);
  sccpExtraB.storeUint(0, 64); // nonce
  sccpExtraB.storeUint(0, 64); // inboundPausedMask
  sccpExtraB.storeUint(0, 64); // outboundPausedMask
  emptyBoolMap.store(sccpExtraB); // invalidatedInbound
  emptyBoolMap.store(sccpExtraB); // processedInbound
  emptyBurnsMap.store(sccpExtraB); // burns
  const sccpExtra = sccpExtraB.endCell();

  const metadataCell = beginCell()
    .storeBuffer(Buffer.from(metadataUri ?? '', 'utf8'))
    .endCell();

  return beginCell()
    .storeCoins(0n) // totalSupply
    .storeAddress(governor)
    .storeAddress(verifier ?? null)
    .storeRef(walletCode)
    .storeRef(metadataCell)
    .storeRef(sccpExtra)
    .endCell();
}

class SccpJettonMaster {
  constructor(address, init) {
    this.address = address;
    this.init = init;
  }

  static createFromArtifacts(masterCode, walletCode, governor, soraAssetIdU256, workchain = 0) {
    const data = buildMasterData({
      governor,
      verifier: null,
      walletCode,
      metadataUri: '',
      soraAssetIdU256,
    });
    const init = { code: masterCode, data };
    return new SccpJettonMaster(contractAddress(workchain, init), init);
  }

  async sendDeploy(provider, via, value) {
    await provider.internal(via, {
      value,
      sendMode: SendMode.PAY_GAS_SEPARATELY,
      body: beginCell().storeUint(TOP_UP_TONS, 32).endCell(),
    });
  }

  async sendSetVerifier(provider, via, value, newVerifier) {
    const body = beginCell()
      .storeUint(SCCP_SET_VERIFIER, 32)
      .storeUint(0, 64)
      .storeAddress(newVerifier ?? null)
      .endCell();
    await provider.internal(via, { value, sendMode: SendMode.PAY_GAS_SEPARATELY, body });
  }

  async sendSetInboundPaused(provider, via, value, sourceDomain, paused) {
    const body = beginCell()
      .storeUint(SCCP_SET_INBOUND_PAUSED, 32)
      .storeUint(0, 64)
      .storeUint(sourceDomain, 32)
      .storeBit(paused)
      .endCell();
    await provider.internal(via, { value, sendMode: SendMode.PAY_GAS_SEPARATELY, body });
  }

  async sendSetOutboundPaused(provider, via, value, destDomain, paused) {
    const body = beginCell()
      .storeUint(SCCP_SET_OUTBOUND_PAUSED, 32)
      .storeUint(0, 64)
      .storeUint(destDomain, 32)
      .storeBit(paused)
      .endCell();
    await provider.internal(via, { value, sendMode: SendMode.PAY_GAS_SEPARATELY, body });
  }

  async sendInvalidateInbound(provider, via, value, messageIdU256) {
    const body = beginCell()
      .storeUint(SCCP_INVALIDATE_INBOUND, 32)
      .storeUint(0, 64)
      .storeUint(messageIdU256, 256)
      .endCell();
    await provider.internal(via, { value, sendMode: SendMode.PAY_GAS_SEPARATELY, body });
  }

  async sendMintFromVerifier(provider, via, value, { sourceDomain, burnNonce, jettonAmount, recipient32 }) {
    const body = beginCell()
      .storeUint(SCCP_MINT_FROM_VERIFIER, 32)
      .storeUint(0, 64)
      .storeUint(sourceDomain, 32)
      .storeUint(burnNonce, 64)
      .storeCoins(jettonAmount)
      .storeUint(recipient32, 256)
      .storeAddress(null) // sendExcessesTo
      .endCell();
    await provider.internal(via, { value, sendMode: SendMode.PAY_GAS_SEPARATELY, body });
  }

  async getSccpConfig(provider) {
    const res = await provider.get('get_sccp_config');
    const governor = res.stack.readAddress();
    const verifier = res.stack.readAddressOpt();
    const soraAssetId = res.stack.readBigNumber();
    const nonce = res.stack.readBigNumber();
    const inboundPausedMask = res.stack.readBigNumber();
    const outboundPausedMask = res.stack.readBigNumber();
    return { governor, verifier, soraAssetId, nonce, inboundPausedMask, outboundPausedMask };
  }

  async getWalletAddress(provider, owner) {
    const arg = beginCell().storeAddress(owner).endCell();
    const res = await provider.get('get_wallet_address', [{ type: 'slice', cell: arg }]);
    return res.stack.readAddress();
  }

  async getOutboundMessageId(provider, destDomain, nonce, jettonAmount, recipient32) {
    const res = await provider.get('get_sccp_message_id', [
      { type: 'int', value: BigInt(destDomain) },
      { type: 'int', value: BigInt(nonce) },
      { type: 'int', value: BigInt(jettonAmount) },
      { type: 'int', value: BigInt(recipient32) },
    ]);
    return res.stack.readBigNumber();
  }

  async getInboundMessageId(provider, sourceDomain, burnNonce, jettonAmount, recipient32) {
    const res = await provider.get('get_sccp_inbound_message_id', [
      { type: 'int', value: BigInt(sourceDomain) },
      { type: 'int', value: BigInt(burnNonce) },
      { type: 'int', value: BigInt(jettonAmount) },
      { type: 'int', value: BigInt(recipient32) },
    ]);
    return res.stack.readBigNumber();
  }

  async getBurnRecord(provider, messageIdU256) {
    const res = await provider.get('get_sccp_burn_record', [{ type: 'int', value: BigInt(messageIdU256) }]);
    return res.stack.readCellOpt();
  }
}

class SccpJettonWallet {
  constructor(address, init) {
    this.address = address;
    this.init = init;
  }

  async sendSccpBurnToDomain(provider, via, value, { jettonAmount, destDomain, recipient32 }) {
    const body = beginCell()
      .storeUint(SCCP_BURN_TO_DOMAIN, 32)
      .storeUint(0, 64)
      .storeCoins(jettonAmount)
      .storeUint(destDomain, 32)
      .storeUint(recipient32, 256)
      .storeAddress(null) // sendExcessesTo
      .endCell();
    await provider.internal(via, { value, sendMode: SendMode.PAY_GAS_SEPARATELY, body });
  }

  async getWalletData(provider) {
    const res = await provider.get('get_wallet_data');
    const jettonBalance = res.stack.readBigNumber();
    const ownerAddress = res.stack.readAddress();
    const minterAddress = res.stack.readAddress();
    const jettonWalletCode = res.stack.readCell();
    return { jettonBalance, ownerAddress, minterAddress, jettonWalletCode };
  }
}

function buildVerifierData({ governor, jettonMaster, soraAssetIdU256 }) {
  const emptyMmrRootsMap = Dictionary.empty(Dictionary.Keys.Uint(16), Dictionary.Values.BigUint(256));
  const emptyKnownRootsMap = Dictionary.empty(Dictionary.Keys.BigUint(256), Dictionary.Values.Bool());

  // LightClientState (stored as a ref in VerifierStorage).
  const stB = beginCell();
  stB.storeBit(0); // initialized
  stB.storeUint(0, 64); // latestBeefyBlock
  // currentValidatorSet
  stB.storeUint(0, 64); // id
  stB.storeUint(0, 32); // len
  stB.storeUint(0n, 256); // root
  // nextValidatorSet
  stB.storeUint(0, 64); // id
  stB.storeUint(0, 32); // len
  stB.storeUint(0n, 256); // root
  stB.storeUint(0, 16); // mmrRootsPos
  emptyMmrRootsMap.store(stB); // mmrRoots ring
  emptyKnownRootsMap.store(stB); // knownRoots
  const stCell = stB.endCell();

  return beginCell()
    .storeAddress(governor)
    .storeAddress(jettonMaster)
    .storeUint(soraAssetIdU256, 256)
    .storeRef(stCell)
    .endCell();
}

function u256ToBufferBE(v) {
  const hex = v.toString(16).padStart(64, '0');
  return Buffer.from(hex, 'hex');
}

function buildSoraLeafProofWithDigest({ digestScaleBytes, nextAuthoritySetId, nextAuthoritySetLen, nextAuthoritySetRootU256 }) {
  // Proof format expected by `contracts/sccp-sora-verifier.tolk` (Substrate MMR single-leaf proof).
  // Keep it minimal: 1-leaf MMR => root == leafHash, no proof items.
  const itemsRef = beginCell().storeUint(0, 16).endCell(); // totalCount = 0
  const digestRef = beginCell().storeBuffer(digestScaleBytes).endCell();

  // Leaf fields are stored in a separate cell to avoid 1023-bit overflow when adding (leafIndex, leafCount).
  const leafRef = beginCell()
    .storeUint(0, 8) // leafVersion
    .storeUint(0, 32) // parentNumber
    .storeUint(0n, 256) // parentHash
    .storeUint(nextAuthoritySetId, 64)
    .storeUint(nextAuthoritySetLen, 32)
    .storeUint(nextAuthoritySetRootU256, 256)
    .storeUint(0n, 256) // randomSeed
    .storeRef(digestRef)
    .endCell();

  return beginCell()
    .storeUint(0, 64) // leafIndex
    .storeUint(1, 64) // leafCount
    .storeRef(itemsRef)
    .storeRef(leafRef)
    .endCell();
}

class SccpSoraVerifier {
  constructor(address, init) {
    this.address = address;
    this.init = init;
  }

  static createFromArtifacts(verifierCode, governor, jettonMaster, soraAssetIdU256, workchain = 0) {
    const data = buildVerifierData({ governor, jettonMaster, soraAssetIdU256 });
    const init = { code: verifierCode, data };
    return new SccpSoraVerifier(contractAddress(workchain, init), init);
  }

  async sendDeploy(provider, via, value) {
    await provider.internal(via, {
      value,
      sendMode: SendMode.PAY_GAS_SEPARATELY,
      body: beginCell().storeUint(TOP_UP_TONS, 32).endCell(),
    });
  }

  async sendInitialize(provider, via, value, {
    latestBeefyBlock,
    currentValidatorSetId,
    currentValidatorSetLen,
    currentValidatorSetRootU256,
    nextValidatorSetId,
    nextValidatorSetLen,
    nextValidatorSetRootU256,
  }) {
    const body = beginCell()
      .storeUint(SCCP_VERIFIER_INITIALIZE, 32)
      .storeUint(0, 64)
      .storeUint(latestBeefyBlock, 64)
      .storeUint(currentValidatorSetId, 64)
      .storeUint(currentValidatorSetLen, 32)
      .storeUint(currentValidatorSetRootU256, 256)
      .storeUint(nextValidatorSetId, 64)
      .storeUint(nextValidatorSetLen, 32)
      .storeUint(nextValidatorSetRootU256, 256)
      .endCell();
    await provider.internal(via, { value, sendMode: SendMode.PAY_GAS_SEPARATELY, body });
  }

  async sendSubmitSignatureCommitment(provider, via, value, {
    commitmentMmrRootU256,
    commitmentBlockNumber,
    commitmentValidatorSetId,
    validatorProofCell,
    latestLeafProofCell,
  }) {
    const body = beginCell()
      .storeUint(SCCP_VERIFIER_SUBMIT_SIGNATURE_COMMITMENT, 32)
      .storeUint(0, 64)
      .storeUint(commitmentMmrRootU256, 256)
      .storeUint(commitmentBlockNumber, 32)
      .storeUint(commitmentValidatorSetId, 64)
      .storeRef(validatorProofCell)
      .storeRef(latestLeafProofCell)
      .endCell();
    await provider.internal(via, { value, sendMode: SendMode.PAY_GAS_SEPARATELY, body });
  }

  async sendMintFromSoraProof(provider, via, value, { burnNonce, jettonAmount, recipient32, proofCell }) {
    const body = beginCell()
      .storeUint(SCCP_VERIFIER_MINT_FROM_SORA_PROOF, 32)
      .storeUint(0, 64)
      .storeUint(burnNonce, 64)
      .storeCoins(jettonAmount)
      .storeUint(recipient32, 256)
      .storeAddress(null) // sendExcessesTo
      .storeRef(proofCell)
      .endCell();
    await provider.internal(via, { value, sendMode: SendMode.PAY_GAS_SEPARATELY, body });
  }

  async sendMintFromSoraProofV2(provider, via, value, { sourceDomain, burnNonce, jettonAmount, recipient32, proofCell }) {
    const body = beginCell()
      .storeUint(SCCP_VERIFIER_MINT_FROM_SORA_PROOF_V2, 32)
      .storeUint(0, 64)
      .storeUint(sourceDomain, 32)
      .storeUint(burnNonce, 64)
      .storeCoins(jettonAmount)
      .storeUint(recipient32, 256)
      .storeAddress(null) // sendExcessesTo
      .storeRef(proofCell)
      .endCell();
    await provider.internal(via, { value, sendMode: SendMode.PAY_GAS_SEPARATELY, body });
  }
}

test('SCCP Jetton master is fail-closed until verifier is set', async () => {
  const masterArtifact = loadArtifact('sccp-jetton-master.compiled.json');
  const walletArtifact = loadArtifact('sccp-jetton-wallet.compiled.json');
  const masterCode = codeFromArtifact(masterArtifact);
  const walletCode = codeFromArtifact(walletArtifact);

  const blockchain = await Blockchain.create();
  const governor = await blockchain.treasury('governor');
  const verifier = await blockchain.treasury('verifier');
  const alice = await blockchain.treasury('alice');

  const soraAssetIdU256 = BigInt('0x' + '11'.repeat(32));
  const master = blockchain.openContract(
    SccpJettonMaster.createFromArtifacts(masterCode, walletCode, governor.address, soraAssetIdU256),
  );
  await master.sendDeploy(governor.getSender(), 1_000_000_000n);

  const aliceRecipient32 = addressToU256(alice.address);
  const out = await master.sendMintFromVerifier(verifier.getSender(), 1_000_000_000n, {
    sourceDomain: DOMAIN_SORA,
    burnNonce: 1n,
    jettonAmount: 10n,
    recipient32: aliceRecipient32,
  });

  const tx = findTxByAddress(out.transactions, master.address);
  assert.ok(tx, 'expected a master tx');
  assert.equal(txExitCode(tx), ERROR_SCCP_VERIFIER_NOT_SET);
});

test('SCCP Jetton master rejects unsupported verifier source domains', async () => {
  const masterArtifact = loadArtifact('sccp-jetton-master.compiled.json');
  const walletArtifact = loadArtifact('sccp-jetton-wallet.compiled.json');
  const masterCode = codeFromArtifact(masterArtifact);
  const walletCode = codeFromArtifact(walletArtifact);

  const blockchain = await Blockchain.create();
  const governor = await blockchain.treasury('governor');
  const verifier = await blockchain.treasury('verifier');
  const alice = await blockchain.treasury('alice');

  const soraAssetIdU256 = BigInt('0x' + '11'.repeat(32));
  const master = blockchain.openContract(
    SccpJettonMaster.createFromArtifacts(masterCode, walletCode, governor.address, soraAssetIdU256),
  );
  await master.sendDeploy(governor.getSender(), 1_000_000_000n);
  await master.sendSetVerifier(governor.getSender(), 1_000_000_000n, verifier.address);

  const aliceRecipient32 = addressToU256(alice.address);
  const out = await master.sendMintFromVerifier(verifier.getSender(), 1_000_000_000n, {
    sourceDomain: 99,
    burnNonce: 1n,
    jettonAmount: 10n,
    recipient32: aliceRecipient32,
  });

  const tx = findTxByAddress(out.transactions, master.address);
  assert.ok(tx, 'expected a master tx');
  assert.equal(txExitCode(tx), ERROR_SCCP_DOMAIN_UNSUPPORTED);
});

test('SCCP verifier V2 rejects unsupported source domains', async () => {
  const verifierArtifact = loadArtifact('sccp-sora-verifier.compiled.json');
  const verifierCode = codeFromArtifact(verifierArtifact);

  const blockchain = await Blockchain.create();
  const governor = await blockchain.treasury('governor');
  const alice = await blockchain.treasury('alice');
  const dummyMaster = await blockchain.treasury('dummy_master');

  const soraAssetIdU256 = BigInt('0x' + '11'.repeat(32));
  const verifier = blockchain.openContract(
    SccpSoraVerifier.createFromArtifacts(verifierCode, governor.address, dummyMaster.address, soraAssetIdU256),
  );
  await verifier.sendDeploy(governor.getSender(), 1_000_000_000n);

  // Initialize light client so V2 path reaches domain guard.
  await verifier.sendInitialize(governor.getSender(), 1_000_000_000n, {
    latestBeefyBlock: 0,
    currentValidatorSetId: 1n,
    currentValidatorSetLen: 1,
    currentValidatorSetRootU256: 0n,
    nextValidatorSetId: 2n,
    nextValidatorSetLen: 1,
    nextValidatorSetRootU256: 0n,
  });

  const proofCell = buildSoraLeafProofWithDigest({
    digestScaleBytes: Buffer.from([0x00]), // empty digest vec
    nextAuthoritySetId: 2n,
    nextAuthoritySetLen: 1,
    nextAuthoritySetRootU256: 0n,
  });

  const out = await verifier.sendMintFromSoraProofV2(alice.getSender(), 1_000_000_000n, {
    sourceDomain: 99,
    burnNonce: 1n,
    jettonAmount: 1n,
    recipient32: BigInt(1),
    proofCell,
  });
  const tx = findTxByAddress(out.transactions, verifier.address);
  assert.ok(tx, 'expected a verifier tx');
  assert.equal(txExitCode(tx), ERROR_SCCP_DOMAIN_UNSUPPORTED);
});

test('SCCP Jetton flow: mint (verifier-gated), replay blocked, pause+invalidation enforced, burn record stored', async () => {
  const masterArtifact = loadArtifact('sccp-jetton-master.compiled.json');
  const walletArtifact = loadArtifact('sccp-jetton-wallet.compiled.json');
  const verifierArtifact = loadArtifact('sccp-sora-verifier.compiled.json');
  const masterCode = codeFromArtifact(masterArtifact);
  const walletCode = codeFromArtifact(walletArtifact);
  const verifierCode = codeFromArtifact(verifierArtifact);

  const blockchain = await Blockchain.create();
  const governor = await blockchain.treasury('governor');
  const alice = await blockchain.treasury('alice');

  const soraAssetIdU256 = BigInt('0x' + '11'.repeat(32));
  const master = blockchain.openContract(
    SccpJettonMaster.createFromArtifacts(masterCode, walletCode, governor.address, soraAssetIdU256),
  );
  await master.sendDeploy(governor.getSender(), 1_000_000_000n);

  const aliceRecipient32 = addressToU256(alice.address);
  const verifier = blockchain.openContract(
    SccpSoraVerifier.createFromArtifacts(verifierCode, governor.address, master.address, soraAssetIdU256),
  );
  await verifier.sendDeploy(governor.getSender(), 1_000_000_000n);

  // Configure verifier (governor-controlled).
  await master.sendSetVerifier(governor.getSender(), 1_000_000_000n, verifier.address);

  // Build a single SORA "leaf provider" digest that commits to multiple SCCP messageIds.
  const mintNonce1 = 777n;
  const mintAmount1 = 1000n;
  const mintNonceEth = 666n;
  const mintAmountEth = 7n;
  const mintNonce2 = 888n;
  const mintAmount2 = 1n;

  const msgId1 = await master.getInboundMessageId(DOMAIN_SORA, mintNonce1, mintAmount1, aliceRecipient32);
  const msgIdEth = await master.getInboundMessageId(DOMAIN_ETH, mintNonceEth, mintAmountEth, aliceRecipient32);
  const msgId2 = await master.getInboundMessageId(DOMAIN_SORA, mintNonce2, mintAmount2, aliceRecipient32);

  function buildDigestScaleForMessageIds(messageIds) {
    // SCALE Vec<AuxiliaryDigestItem>, where we only support AuxiliaryDigestItem::Commitment(GenericNetworkId::EVMLegacy(u32), H256).
    // Compact length (mode 0) for small n: first byte = n * 4.
    const n = messageIds.length;
    assert.ok(n > 0 && n < 64, 'n out of range');

    const out = [];
    out.push(n * 4); // compact u32 (mode 0)
    for (const m of messageIds) {
      out.push(0x00); // AuxiliaryDigestItem::Commitment
      out.push(0x02); // GenericNetworkId::EVMLegacy
      out.push(0x50, 0x43, 0x43, 0x53); // u32 LE of 0x53434350 ('SCCP')
      out.push(...u256ToBufferBE(m));
    }
    return Buffer.from(out);
  }

  const digestScale = buildDigestScaleForMessageIds([msgId1, msgIdEth, msgId2]);
  const digestHash32 = Buffer.from(ethers.keccak256(digestScale).slice(2), 'hex');

  // --- Synthetic validator set (BEEFY) ---
  //
  // Build a 4-validator set so >=2/3 threshold is 3 signatures.
  const validatorPrivKeys = [
    '0x' + '11'.repeat(32),
    '0x' + '22'.repeat(32),
    '0x' + '33'.repeat(32),
    '0x' + '44'.repeat(32),
  ];

  const validators = validatorPrivKeys.map((pk) => {
    const w = new ethers.Wallet(pk);
    const addr160 = BigInt(w.address);
    const addr20 = Buffer.from(w.address.slice(2).padStart(40, '0'), 'hex');
    return { pk, address: w.address, addr160, addr20 };
  }).sort((a, b) => (a.addr160 < b.addr160 ? -1 : 1));

  function keccak256Buf(data) {
    return Buffer.from(ethers.keccak256(data).slice(2), 'hex');
  }

  function keccakPair(a32, b32) {
    // Substrate `binary_merkle_tree`: ordered hashing (no sorting).
    return keccak256Buf(Buffer.concat([a32, b32]));
  }

  function buildMerkleRootAndProofs(leaves) {
    let level = leaves.slice();
    const levels = [level];
    while (level.length > 1) {
      const next = [];
      for (let i = 0; i < level.length; i += 2) {
        if (i + 1 >= level.length) {
          next.push(level[i]); // promote odd leaf
        } else {
          next.push(keccakPair(level[i], level[i + 1]));
        }
      }
      level = next;
      levels.push(level);
    }

    const root = levels[levels.length - 1][0];

    const proofs = leaves.map((_leaf, leafIndex) => {
      const out = [];
      let idx = leafIndex;
      for (let d = 0; d < levels.length - 1; d++) {
        const layer = levels[d];
        const sib = idx % 2 === 1 ? idx - 1 : idx + 1;
        if (sib < layer.length) {
          out.push(layer[sib]);
        }
        idx = Math.floor(idx / 2);
      }
      return out;
    });

    return { root, proofs };
  }

  const leaves = validators.map((v) => keccak256Buf(v.addr20));
  const { root: validatorSetRoot32, proofs: validatorProofs32 } = buildMerkleRootAndProofs(leaves);
  const validatorSetRootU256 = BigInt('0x' + validatorSetRoot32.toString('hex'));

  const currentValidatorSetId = 1n;
  const nextValidatorSetId = 2n;
  const validatorSetLen = 4;

  // Burn proof leaf must advertise the next validator set (we keep it equal to `next` so no rotation happens).
  const nextAuthoritySetId = nextValidatorSetId;
  const nextAuthoritySetLen = validatorSetLen;
  const nextAuthoritySetRootU256 = validatorSetRootU256;

  const proofCell = buildSoraLeafProofWithDigest({
    digestScaleBytes: digestScale,
    nextAuthoritySetId,
    nextAuthoritySetLen,
    nextAuthoritySetRootU256,
  });

  // Verifier must be initialized by governor before any operation.
  const mintNotInit = await verifier.sendMintFromSoraProof(alice.getSender(), 1_000_000_000n, {
    burnNonce: mintNonce1,
    jettonAmount: mintAmount1,
    recipient32: aliceRecipient32,
    proofCell,
  });
  {
    const tx = findTxByAddress(mintNotInit.transactions, verifier.address);
    assert.ok(tx, 'expected a verifier tx');
    assert.equal(txExitCode(tx), ERROR_SCCP_VERIFIER_NOT_INITIALIZED);
  }

  await verifier.sendInitialize(governor.getSender(), 1_000_000_000n, {
    latestBeefyBlock: 0,
    currentValidatorSetId,
    currentValidatorSetLen: validatorSetLen,
    currentValidatorSetRootU256: validatorSetRootU256,
    nextValidatorSetId,
    nextValidatorSetLen: validatorSetLen,
    nextValidatorSetRootU256: validatorSetRootU256,
  });

  // Root is unknown until a valid commitment is submitted.
  const mintUnknownRoot = await verifier.sendMintFromSoraProof(alice.getSender(), 1_000_000_000n, {
    burnNonce: mintNonce1,
    jettonAmount: mintAmount1,
    recipient32: aliceRecipient32,
    proofCell,
  });
  {
    const tx = findTxByAddress(mintUnknownRoot.transactions, verifier.address);
    assert.ok(tx, 'expected a verifier tx');
    assert.equal(txExitCode(tx), ERROR_SCCP_UNKNOWN_MMR_ROOT);
  }

  // --- Submit a synthetic BEEFY commitment that imports the proof root as a known MMR root ---
  const leafScale = Buffer.alloc(145);
  leafScale[0] = 0; // version
  leafScale.writeUInt32LE(0, 1); // parentNumber
  // parentHash[32] @ 5..37 => already zero
  leafScale.writeBigUInt64LE(nextAuthoritySetId, 37);
  leafScale.writeUInt32LE(nextAuthoritySetLen, 45);
  Buffer.from(nextAuthoritySetRootU256.toString(16).padStart(64, '0'), 'hex').copy(leafScale, 49);
  // randomSeed[32] @ 81..113 => zero
  digestHash32.copy(leafScale, 113);
  const mmrRoot32 = keccak256Buf(leafScale);
  const commitmentMmrRootU256 = BigInt('0x' + mmrRoot32.toString('hex'));

  const commitmentBlockNumber = 10;
  const commitmentValidatorSetId = currentValidatorSetId;

  const commitmentScale = Buffer.alloc(48);
  commitmentScale[0] = 0x04;
  commitmentScale[1] = 'm'.charCodeAt(0);
  commitmentScale[2] = 'h'.charCodeAt(0);
  commitmentScale[3] = 0x80;
  mmrRoot32.copy(commitmentScale, 4);
  commitmentScale.writeUInt32LE(commitmentBlockNumber, 36);
  commitmentScale.writeBigUInt64LE(commitmentValidatorSetId, 40);
  const commitmentHashHex = ethers.keccak256(commitmentScale);

  // Use 3 signatures (>=2/3 of 4) from the first 3 validators (already sorted by address).
  const signingValidators = validators.slice(0, 3).map((v, idx) => {
    const sk = new ethers.SigningKey(v.pk);
    const sig = sk.sign(commitmentHashHex);
    const v27 = 27 + sig.yParity;
    return {
      addr160: v.addr160,
      v: v27,
      r: BigInt(sig.r),
      s: BigInt(sig.s),
      pos: idx,
      merkleProofSiblings32: validatorProofs32[idx],
    };
  });

  function buildMerkleProofCell(siblings32) {
    const b = beginCell();
    b.storeUint(siblings32.length, 16);
    for (const sib of siblings32) {
      b.storeUint(BigInt('0x' + sib.toString('hex')), 256);
    }
    return b.endCell();
  }

  function buildValidatorProofCell(entries) {
    // Linked list: each entry cell holds one signature + merkle proof + maybeRef(next).
    let next = null;
    for (let i = entries.length - 1; i >= 0; i--) {
      const e = entries[i];
      const merkleProofCell = buildMerkleProofCell(e.merkleProofSiblings32);
      next = beginCell()
        .storeUint(e.v, 8)
        .storeUint(e.r, 256)
        .storeUint(e.s, 256)
        .storeUint(e.pos, 32)
        .storeRef(merkleProofCell)
        .storeMaybeRef(next)
        .endCell();
    }

    return beginCell()
      .storeUint(entries.length, 16)
      .storeRef(next)
      .endCell();
  }

  const validatorProofCell = buildValidatorProofCell(signingValidators);

  const submitOut = await verifier.sendSubmitSignatureCommitment(alice.getSender(), 1_000_000_000n, {
    commitmentMmrRootU256,
    commitmentBlockNumber,
    commitmentValidatorSetId,
    validatorProofCell,
    latestLeafProofCell: proofCell,
  });
  {
    const tx = findTxByAddress(submitOut.transactions, verifier.address);
    assert.ok(tx, 'expected a verifier tx');
    assert.equal(txExitCode(tx), 0);
  }

  // Mint to alice (must go through verifier contract + proof).
  const mint1 = await verifier.sendMintFromSoraProof(alice.getSender(), 1_000_000_000n, {
    burnNonce: mintNonce1,
    jettonAmount: mintAmount1,
    recipient32: aliceRecipient32,
    proofCell,
  });
  {
    const tx = findTxByAddress(mint1.transactions, master.address);
    assert.ok(tx, 'expected a master tx');
    assert.equal(txExitCode(tx), 0);
  }

  // Mint from a non-SORA sourceDomain: ETH -> TON, attested/committed by SORA.
  const mintEth = await verifier.sendMintFromSoraProofV2(alice.getSender(), 1_000_000_000n, {
    sourceDomain: DOMAIN_ETH,
    burnNonce: mintNonceEth,
    jettonAmount: mintAmountEth,
    recipient32: aliceRecipient32,
    proofCell,
  });
  {
    const tx = findTxByAddress(mintEth.transactions, master.address);
    assert.ok(tx, 'expected a master tx');
    assert.equal(txExitCode(tx), 0);
  }

  const walletAddr = await master.getWalletAddress(alice.address);
  const wallet = blockchain.openContract(new SccpJettonWallet(walletAddr));

  const w0 = await wallet.getWalletData();
  assert.equal(w0.jettonBalance, mintAmount1 + mintAmountEth);
  assert.equal(w0.ownerAddress.toRawString(), alice.address.toRawString());
  assert.equal(w0.minterAddress.toRawString(), master.address.toRawString());

  // Replay the same inbound mint must be blocked.
  const mint2 = await verifier.sendMintFromSoraProof(alice.getSender(), 1_000_000_000n, {
    burnNonce: mintNonce1,
    jettonAmount: mintAmount1,
    recipient32: aliceRecipient32,
    proofCell,
  });
  {
    const tx = findTxByAddress(mint2.transactions, master.address);
    assert.ok(tx, 'expected a master tx');
    assert.equal(txExitCode(tx), ERROR_SCCP_MESSAGE_ALREADY_PROCESSED);
  }

  // Replay the same inbound mint (ETH) must be blocked.
  const mintEthReplay = await verifier.sendMintFromSoraProofV2(alice.getSender(), 1_000_000_000n, {
    sourceDomain: DOMAIN_ETH,
    burnNonce: mintNonceEth,
    jettonAmount: mintAmountEth,
    recipient32: aliceRecipient32,
    proofCell,
  });
  {
    const tx = findTxByAddress(mintEthReplay.transactions, master.address);
    assert.ok(tx, 'expected a master tx');
    assert.equal(txExitCode(tx), ERROR_SCCP_MESSAGE_ALREADY_PROCESSED);
  }

  // Pause inbound from SORA; mint must fail even if proof is valid.
  await master.sendSetInboundPaused(governor.getSender(), 1_000_000_000n, DOMAIN_SORA, true);
  const mintPaused = await verifier.sendMintFromSoraProof(alice.getSender(), 1_000_000_000n, {
    burnNonce: mintNonce2,
    jettonAmount: mintAmount2,
    recipient32: aliceRecipient32,
    proofCell,
  });
  {
    const tx = findTxByAddress(mintPaused.transactions, master.address);
    assert.ok(tx, 'expected a master tx');
    assert.equal(txExitCode(tx), ERROR_SCCP_INBOUND_PAUSED);
  }
  await master.sendSetInboundPaused(governor.getSender(), 1_000_000_000n, DOMAIN_SORA, false);

  // Invalidate a specific messageId; mint must fail.
  await master.sendInvalidateInbound(governor.getSender(), 1_000_000_000n, msgId2);

  const mintInvalidated = await verifier.sendMintFromSoraProof(alice.getSender(), 1_000_000_000n, {
    burnNonce: mintNonce2,
    jettonAmount: mintAmount2,
    recipient32: aliceRecipient32,
    proofCell,
  });
  {
    const tx = findTxByAddress(mintInvalidated.transactions, master.address);
    assert.ok(tx, 'expected a master tx');
    assert.equal(txExitCode(tx), ERROR_SCCP_MESSAGE_INVALIDATED);
  }

  // Burn from TON -> SORA and verify burn record is stored on-chain (in master state).
  const cfg0 = await master.getSccpConfig();
  assert.equal(cfg0.nonce, 0n);

  // Outbound pause must block burns to that destination; wallet balance must be restored via bounce.
  await master.sendSetOutboundPaused(governor.getSender(), 1_000_000_000n, DOMAIN_SORA, true);
  const burnPaused = await wallet.sendSccpBurnToDomain(alice.getSender(), 1_000_000_000n, {
    jettonAmount: 1n,
    destDomain: DOMAIN_SORA,
    recipient32: BigInt('0x' + '22'.repeat(32)),
  });
  {
    const tx = findTxByAddress(burnPaused.transactions, master.address);
    assert.ok(tx, 'expected a master tx');
    assert.equal(txExitCode(tx), ERROR_SCCP_OUTBOUND_PAUSED);
  }
  const wPaused = await wallet.getWalletData();
  assert.equal(wPaused.jettonBalance, mintAmount1 + mintAmountEth);
  const cfgPaused = await master.getSccpConfig();
  assert.equal(cfgPaused.nonce, 0n);
  await master.sendSetOutboundPaused(governor.getSender(), 1_000_000_000n, DOMAIN_SORA, false);

  const burnAmount = 10n;
  const soraRecipient32 = BigInt('0x' + '22'.repeat(32));
  const burnOut = await wallet.sendSccpBurnToDomain(alice.getSender(), 1_000_000_000n, {
    jettonAmount: burnAmount,
    destDomain: DOMAIN_SORA,
    recipient32: soraRecipient32,
  });
  {
    const tx = findTxByAddress(burnOut.transactions, wallet.address);
    assert.ok(tx, 'expected a wallet tx');
    assert.equal(txExitCode(tx), 0);
  }

  const w1 = await wallet.getWalletData();
  assert.equal(w1.jettonBalance, mintAmount1 + mintAmountEth - burnAmount);

  const cfg = await master.getSccpConfig();
  assert.equal(cfg.nonce, 1n);

  const outMsgId = await master.getOutboundMessageId(DOMAIN_SORA, cfg.nonce, burnAmount, soraRecipient32);
  const burnCell = await master.getBurnRecord(outMsgId);
  assert.ok(burnCell, 'expected burn record to exist');

  const s = burnCell.beginParse();
  const burnInitiator = s.loadAddress();
  const destDomain = s.loadUint(32);
  const recipient32 = s.loadUintBig(256);
  const jettonAmount = s.loadCoins();
  const nonce = s.loadUintBig(64);

  assert.equal(burnInitiator.toRawString(), alice.address.toRawString());
  assert.equal(destDomain, DOMAIN_SORA);
  assert.equal(recipient32, soraRecipient32);
  assert.equal(jettonAmount, burnAmount);
  assert.equal(nonce, 1n);

  // Burn to an EVM domain must enforce canonical recipient encoding (high 12 bytes must be zero).
  const badEvmRecipient32 = BigInt('0x' + '11'.repeat(32)); // non-zero high 12 bytes => non-canonical
  const burnBad = await wallet.sendSccpBurnToDomain(alice.getSender(), 1_000_000_000n, {
    jettonAmount: 1n,
    destDomain: DOMAIN_ETH,
    recipient32: badEvmRecipient32,
  });
  {
    const tx = findTxByAddress(burnBad.transactions, wallet.address);
    assert.ok(tx, 'expected a wallet tx');
    assert.equal(txExitCode(tx), ERROR_SCCP_RECIPIENT_NOT_CANONICAL);
  }

  // Burn to an unsupported destination domain must fail-closed.
  const burnUnsupported = await wallet.sendSccpBurnToDomain(alice.getSender(), 1_000_000_000n, {
    jettonAmount: 1n,
    destDomain: 99,
    recipient32: BigInt('0x' + '22'.repeat(32)),
  });
  {
    const tx = findTxByAddress(burnUnsupported.transactions, wallet.address);
    assert.ok(tx, 'expected a wallet tx');
    assert.equal(txExitCode(tx), ERROR_SCCP_DOMAIN_UNSUPPORTED);
  }

  // Governance pause controls must reject unsupported domain ids.
  const pauseInboundUnsupported = await master.sendSetInboundPaused(
    governor.getSender(),
    1_000_000_000n,
    99,
    true,
  );
  {
    const tx = findTxByAddress(pauseInboundUnsupported.transactions, master.address);
    assert.ok(tx, 'expected a master tx');
    assert.equal(txExitCode(tx), ERROR_SCCP_DOMAIN_UNSUPPORTED);
  }

  const pauseOutboundUnsupported = await master.sendSetOutboundPaused(
    governor.getSender(),
    1_000_000_000n,
    99,
    true,
  );
  {
    const tx = findTxByAddress(pauseOutboundUnsupported.transactions, master.address);
    assert.ok(tx, 'expected a master tx');
    assert.equal(txExitCode(tx), ERROR_SCCP_DOMAIN_UNSUPPORTED);
  }
});

test('SCCP verifier rejects duplicate validator signer addresses even with valid merkle proofs', async () => {
  const verifierArtifact = loadArtifact('sccp-sora-verifier.compiled.json');
  const verifierCode = codeFromArtifact(verifierArtifact);

  const blockchain = await Blockchain.create();
  const governor = await blockchain.treasury('governor');
  const alice = await blockchain.treasury('alice');
  const dummyMaster = await blockchain.treasury('dummy_master');

  const soraAssetIdU256 = BigInt('0x' + '11'.repeat(32));
  const verifier = blockchain.openContract(
    SccpSoraVerifier.createFromArtifacts(verifierCode, governor.address, dummyMaster.address, soraAssetIdU256),
  );
  await verifier.sendDeploy(governor.getSender(), 1_000_000_000n);

  function keccak256Buf(data) {
    return Buffer.from(ethers.keccak256(data).slice(2), 'hex');
  }

  function keccakPair(a32, b32) {
    return keccak256Buf(Buffer.concat([a32, b32]));
  }

  function buildMerkleRootAndProofs(leaves) {
    let level = leaves.slice();
    const levels = [level];
    while (level.length > 1) {
      const next = [];
      for (let i = 0; i < level.length; i += 2) {
        if (i + 1 >= level.length) {
          next.push(level[i]);
        } else {
          next.push(keccakPair(level[i], level[i + 1]));
        }
      }
      level = next;
      levels.push(level);
    }

    const root = levels[levels.length - 1][0];
    const proofs = leaves.map((_leaf, leafIndex) => {
      const out = [];
      let idx = leafIndex;
      for (let d = 0; d < levels.length - 1; d++) {
        const layer = levels[d];
        const sib = idx % 2 === 1 ? idx - 1 : idx + 1;
        if (sib < layer.length) {
          out.push(layer[sib]);
        }
        idx = Math.floor(idx / 2);
      }
      return out;
    });
    return { root, proofs };
  }

  // Intentionally duplicate validator key at positions 0 and 1.
  const validatorPrivKeys = [
    '0x' + '11'.repeat(32),
    '0x' + '11'.repeat(32),
    '0x' + '22'.repeat(32),
    '0x' + '33'.repeat(32),
  ];
  const validators = validatorPrivKeys.map((pk) => {
    const w = new ethers.Wallet(pk);
    const addr20 = Buffer.from(w.address.slice(2).padStart(40, '0'), 'hex');
    return { pk, addr20 };
  });

  const leaves = validators.map((v) => keccak256Buf(v.addr20));
  const { root: validatorSetRoot32, proofs: validatorProofs32 } = buildMerkleRootAndProofs(leaves);
  const validatorSetRootU256 = BigInt('0x' + validatorSetRoot32.toString('hex'));

  const currentValidatorSetId = 1n;
  const nextValidatorSetId = 2n;
  const validatorSetLen = 4;

  await verifier.sendInitialize(governor.getSender(), 1_000_000_000n, {
    latestBeefyBlock: 0,
    currentValidatorSetId,
    currentValidatorSetLen: validatorSetLen,
    currentValidatorSetRootU256: validatorSetRootU256,
    nextValidatorSetId,
    nextValidatorSetLen: validatorSetLen,
    nextValidatorSetRootU256: validatorSetRootU256,
  });

  const digestScale = Buffer.concat([
    Buffer.from([0x04, 0x00, 0x02, 0x50, 0x43, 0x43, 0x53]),
    Buffer.alloc(32, 0xAB),
  ]);
  const digestHash32 = Buffer.from(ethers.keccak256(digestScale).slice(2), 'hex');
  const proofCell = buildSoraLeafProofWithDigest({
    digestScaleBytes: digestScale,
    nextAuthoritySetId: nextValidatorSetId,
    nextAuthoritySetLen: validatorSetLen,
    nextAuthoritySetRootU256: validatorSetRootU256,
  });

  // Rebuild the leaf SCALE bytes to compute commitment.mmr_root exactly as verifier expects.
  const leafScale = Buffer.alloc(145);
  leafScale[0] = 0;
  leafScale.writeUInt32LE(0, 1);
  leafScale.writeBigUInt64LE(nextValidatorSetId, 37);
  leafScale.writeUInt32LE(validatorSetLen, 45);
  Buffer.from(validatorSetRootU256.toString(16).padStart(64, '0'), 'hex').copy(leafScale, 49);
  digestHash32.copy(leafScale, 113);
  const mmrRoot32 = keccak256Buf(leafScale);
  const commitmentMmrRootU256 = BigInt('0x' + mmrRoot32.toString('hex'));

  const commitmentBlockNumber = 10;
  const commitmentScale = Buffer.alloc(48);
  commitmentScale[0] = 0x04;
  commitmentScale[1] = 'm'.charCodeAt(0);
  commitmentScale[2] = 'h'.charCodeAt(0);
  commitmentScale[3] = 0x80;
  mmrRoot32.copy(commitmentScale, 4);
  commitmentScale.writeUInt32LE(commitmentBlockNumber, 36);
  commitmentScale.writeBigUInt64LE(currentValidatorSetId, 40);
  const commitmentHashHex = ethers.keccak256(commitmentScale);

  function buildMerkleProofCell(siblings32) {
    const b = beginCell();
    b.storeUint(siblings32.length, 16);
    for (const sib of siblings32) {
      b.storeUint(BigInt('0x' + sib.toString('hex')), 256);
    }
    return b.endCell();
  }

  function buildValidatorProofCell(entries) {
    let next = null;
    for (let i = entries.length - 1; i >= 0; i--) {
      const e = entries[i];
      const merkleProofCell = buildMerkleProofCell(e.merkleProofSiblings32);
      next = beginCell()
        .storeUint(e.v, 8)
        .storeUint(e.r, 256)
        .storeUint(e.s, 256)
        .storeUint(e.pos, 32)
        .storeRef(merkleProofCell)
        .storeMaybeRef(next)
        .endCell();
    }
    return beginCell()
      .storeUint(entries.length, 16)
      .storeRef(next)
      .endCell();
  }

  // Positions are unique and proofs are valid, but positions 0 and 1 are signed by the same validator.
  const signingEntries = [0, 1, 2].map((idx) => {
    const v = validators[idx];
    const sk = new ethers.SigningKey(v.pk);
    const sig = sk.sign(commitmentHashHex);
    return {
      v: 27 + sig.yParity,
      r: BigInt(sig.r),
      s: BigInt(sig.s),
      pos: idx,
      merkleProofSiblings32: validatorProofs32[idx],
    };
  });
  const validatorProofCell = buildValidatorProofCell(signingEntries);

  const submitOut = await verifier.sendSubmitSignatureCommitment(alice.getSender(), 1_000_000_000n, {
    commitmentMmrRootU256,
    commitmentBlockNumber,
    commitmentValidatorSetId: currentValidatorSetId,
    validatorProofCell,
    latestLeafProofCell: proofCell,
  });
  {
    const tx = findTxByAddress(submitOut.transactions, verifier.address);
    assert.ok(tx, 'expected a verifier tx');
    assert.equal(txExitCode(tx), ERROR_SCCP_INVALID_VALIDATOR_PROOF);
  }
});

test('SCCP verifier rejects malleable high-s signatures', async () => {
  const verifierArtifact = loadArtifact('sccp-sora-verifier.compiled.json');
  const verifierCode = codeFromArtifact(verifierArtifact);

  const blockchain = await Blockchain.create();
  const governor = await blockchain.treasury('governor');
  const alice = await blockchain.treasury('alice');
  const dummyMaster = await blockchain.treasury('dummy_master');

  const soraAssetIdU256 = BigInt('0x' + '11'.repeat(32));
  const verifier = blockchain.openContract(
    SccpSoraVerifier.createFromArtifacts(verifierCode, governor.address, dummyMaster.address, soraAssetIdU256),
  );
  await verifier.sendDeploy(governor.getSender(), 1_000_000_000n);

  function keccak256Buf(data) {
    return Buffer.from(ethers.keccak256(data).slice(2), 'hex');
  }

  function keccakPair(a32, b32) {
    return keccak256Buf(Buffer.concat([a32, b32]));
  }

  function buildMerkleRootAndProofs(leaves) {
    let level = leaves.slice();
    const levels = [level];
    while (level.length > 1) {
      const next = [];
      for (let i = 0; i < level.length; i += 2) {
        if (i + 1 >= level.length) {
          next.push(level[i]);
        } else {
          next.push(keccakPair(level[i], level[i + 1]));
        }
      }
      level = next;
      levels.push(level);
    }

    const root = levels[levels.length - 1][0];
    const proofs = leaves.map((_leaf, leafIndex) => {
      const out = [];
      let idx = leafIndex;
      for (let d = 0; d < levels.length - 1; d++) {
        const layer = levels[d];
        const sib = idx % 2 === 1 ? idx - 1 : idx + 1;
        if (sib < layer.length) {
          out.push(layer[sib]);
        }
        idx = Math.floor(idx / 2);
      }
      return out;
    });
    return { root, proofs };
  }

  const validatorPrivKeys = [
    '0x' + '11'.repeat(32),
    '0x' + '22'.repeat(32),
    '0x' + '33'.repeat(32),
    '0x' + '44'.repeat(32),
  ];
  const validators = validatorPrivKeys.map((pk) => {
    const w = new ethers.Wallet(pk);
    const addr20 = Buffer.from(w.address.slice(2).padStart(40, '0'), 'hex');
    return { pk, addr20 };
  });

  const leaves = validators.map((v) => keccak256Buf(v.addr20));
  const { root: validatorSetRoot32, proofs: validatorProofs32 } = buildMerkleRootAndProofs(leaves);
  const validatorSetRootU256 = BigInt('0x' + validatorSetRoot32.toString('hex'));

  const currentValidatorSetId = 1n;
  const nextValidatorSetId = 2n;
  const validatorSetLen = 4;

  await verifier.sendInitialize(governor.getSender(), 1_000_000_000n, {
    latestBeefyBlock: 0,
    currentValidatorSetId,
    currentValidatorSetLen: validatorSetLen,
    currentValidatorSetRootU256: validatorSetRootU256,
    nextValidatorSetId,
    nextValidatorSetLen: validatorSetLen,
    nextValidatorSetRootU256: validatorSetRootU256,
  });

  const digestScale = Buffer.concat([
    Buffer.from([0x04, 0x00, 0x02, 0x50, 0x43, 0x43, 0x53]),
    Buffer.alloc(32, 0xAB),
  ]);
  const digestHash32 = Buffer.from(ethers.keccak256(digestScale).slice(2), 'hex');
  const proofCell = buildSoraLeafProofWithDigest({
    digestScaleBytes: digestScale,
    nextAuthoritySetId: nextValidatorSetId,
    nextAuthoritySetLen: validatorSetLen,
    nextAuthoritySetRootU256: validatorSetRootU256,
  });

  const leafScale = Buffer.alloc(145);
  leafScale[0] = 0;
  leafScale.writeUInt32LE(0, 1);
  leafScale.writeBigUInt64LE(nextValidatorSetId, 37);
  leafScale.writeUInt32LE(validatorSetLen, 45);
  Buffer.from(validatorSetRootU256.toString(16).padStart(64, '0'), 'hex').copy(leafScale, 49);
  digestHash32.copy(leafScale, 113);
  const mmrRoot32 = keccak256Buf(leafScale);
  const commitmentMmrRootU256 = BigInt('0x' + mmrRoot32.toString('hex'));

  const commitmentBlockNumber = 10;
  const commitmentScale = Buffer.alloc(48);
  commitmentScale[0] = 0x04;
  commitmentScale[1] = 'm'.charCodeAt(0);
  commitmentScale[2] = 'h'.charCodeAt(0);
  commitmentScale[3] = 0x80;
  mmrRoot32.copy(commitmentScale, 4);
  commitmentScale.writeUInt32LE(commitmentBlockNumber, 36);
  commitmentScale.writeBigUInt64LE(currentValidatorSetId, 40);
  const commitmentHashHex = ethers.keccak256(commitmentScale);

  function buildMerkleProofCell(siblings32) {
    const b = beginCell();
    b.storeUint(siblings32.length, 16);
    for (const sib of siblings32) {
      b.storeUint(BigInt('0x' + sib.toString('hex')), 256);
    }
    return b.endCell();
  }

  function buildValidatorProofCell(entries) {
    let next = null;
    for (let i = entries.length - 1; i >= 0; i--) {
      const e = entries[i];
      const merkleProofCell = buildMerkleProofCell(e.merkleProofSiblings32);
      next = beginCell()
        .storeUint(e.v, 8)
        .storeUint(e.r, 256)
        .storeUint(e.s, 256)
        .storeUint(e.pos, 32)
        .storeRef(merkleProofCell)
        .storeMaybeRef(next)
        .endCell();
    }
    return beginCell()
      .storeUint(entries.length, 16)
      .storeRef(next)
      .endCell();
  }

  const signingEntries = [0, 1, 2].map((idx) => {
    const v = validators[idx];
    const sk = new ethers.SigningKey(v.pk);
    const sig = sk.sign(commitmentHashHex);
    return {
      v: 27 + sig.yParity,
      r: BigInt(sig.r),
      // Flip to malleable high-s form; verifier must fail-closed.
      s: idx === 0 ? (SECP256K1N - BigInt(sig.s)) : BigInt(sig.s),
      pos: idx,
      merkleProofSiblings32: validatorProofs32[idx],
    };
  });
  const validatorProofCell = buildValidatorProofCell(signingEntries);

  const submitOut = await verifier.sendSubmitSignatureCommitment(alice.getSender(), 1_000_000_000n, {
    commitmentMmrRootU256,
    commitmentBlockNumber,
    commitmentValidatorSetId: currentValidatorSetId,
    validatorProofCell,
    latestLeafProofCell: proofCell,
  });
  {
    const tx = findTxByAddress(submitOut.transactions, verifier.address);
    assert.ok(tx, 'expected a verifier tx');
    assert.equal(txExitCode(tx), ERROR_SCCP_INVALID_SIGNATURE);
  }
});
