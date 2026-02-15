import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { Address, beginCell, Cell, contractAddress, Dictionary } from '@ton/core';

const repoRoot = resolve(import.meta.dirname, '..');

function loadArtifact(name) {
  return JSON.parse(readFileSync(resolve(repoRoot, 'artifacts', name), 'utf8'));
}

function codeFromArtifact(artifact) {
  return Cell.fromBoc(Buffer.from(artifact.codeBoc64, 'base64'))[0];
}

function parseHexU256(s) {
  const hex = s.startsWith('0x') ? s.slice(2) : s;
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error(`Expected 32-byte hex (64 chars), got: ${s}`);
  }
  return BigInt('0x' + hex.toLowerCase());
}

function usageAndExit(code) {
  // eslint-disable-next-line no-console
  console.error(
    [
      'Usage:',
      '  node scripts/derive_master_address.mjs --governor <ton_addr> --sora-asset-id <64hex> [--verifier <ton_addr>] [--metadata-uri <string>]',
      '',
      'Outputs:',
      '  - master_address (friendly)',
      '  - master_account_id_hex (32 bytes)  => use as SORA `remote_token_id` for TON',
      '  - master_code_hash_hex (32 bytes)   => can be used as SORA TON `domain_endpoint` identifier',
    ].join('\n'),
  );
  process.exit(code);
}

function argValue(argv, key) {
  const i = argv.indexOf(key);
  if (i === -1) return null;
  if (i + 1 >= argv.length) return null;
  return argv[i + 1];
}

function buildMasterData({ governor, verifier, walletCode, metadataUri, soraAssetIdU256 }) {
  const emptyBoolMap = Dictionary.empty(Dictionary.Keys.BigUint(256), Dictionary.Values.Bool());
  const emptyBurnsMap = Dictionary.empty(Dictionary.Keys.BigUint(256), Dictionary.Values.Cell());

  const sccpExtraB = beginCell();
  sccpExtraB.storeUint(soraAssetIdU256, 256);
  sccpExtraB.storeUint(0, 64); // nonce
  sccpExtraB.storeUint(0, 64); // inboundPausedMask
  emptyBoolMap.store(sccpExtraB); // invalidatedInbound
  emptyBoolMap.store(sccpExtraB); // processedInbound
  emptyBurnsMap.store(sccpExtraB); // burns
  const sccpExtra = sccpExtraB.endCell();

  const metadataCell = beginCell().storeBuffer(Buffer.from(metadataUri ?? '', 'utf8')).endCell();

  return beginCell()
    .storeCoins(0n) // totalSupply
    .storeAddress(governor)
    .storeAddress(verifier ?? null)
    .storeRef(walletCode)
    .storeRef(metadataCell)
    .storeRef(sccpExtra)
    .endCell();
}

async function main() {
  const argv = process.argv.slice(2);
  if (argv.includes('--help') || argv.includes('-h')) {
    usageAndExit(0);
  }

  const governorStr = argValue(argv, '--governor');
  const soraAssetIdStr = argValue(argv, '--sora-asset-id');
  if (!governorStr || !soraAssetIdStr) {
    usageAndExit(2);
  }

  const verifierStr = argValue(argv, '--verifier');
  const metadataUri = argValue(argv, '--metadata-uri') ?? '';

  const governor = Address.parse(governorStr);
  const verifier = verifierStr ? Address.parse(verifierStr) : null;
  const soraAssetIdU256 = parseHexU256(soraAssetIdStr);

  const masterArtifact = loadArtifact('sccp-jetton-master.compiled.json');
  const walletArtifact = loadArtifact('sccp-jetton-wallet.compiled.json');
  const masterCode = codeFromArtifact(masterArtifact);
  const walletCode = codeFromArtifact(walletArtifact);

  const data = buildMasterData({ governor, verifier, walletCode, metadataUri, soraAssetIdU256 });
  const init = { code: masterCode, data };
  const addr = contractAddress(0, init);

  const out = {
    master_address: addr.toString(),
    master_account_id_hex: addr.hash.toString('hex'),
    master_code_hash_hex: masterArtifact.codeHashHex,
    wallet_code_hash_hex: walletArtifact.codeHashHex,
  };

  // eslint-disable-next-line no-console
  console.log(JSON.stringify(out, null, 2));
}

main().catch((e) => {
  // eslint-disable-next-line no-console
  console.error(e);
  process.exit(1);
});

