#!/usr/bin/env node
import fs from 'node:fs';
import { beginCell } from '@ton/core';

function parseIntLike(v) {
  if (typeof v === 'number') return v;
  if (typeof v === 'bigint') return Number(v);
  if (typeof v !== 'string') throw new Error(`cannot parse int from ${typeof v}`);
  if (v.startsWith('0x') || v.startsWith('0X')) return Number(BigInt(v));
  return Number(v);
}

function parseBigIntLike(v) {
  if (typeof v === 'bigint') return v;
  if (typeof v === 'number') return BigInt(v);
  if (typeof v !== 'string') throw new Error(`cannot parse bigint from ${typeof v}`);
  if (v.startsWith('0x') || v.startsWith('0X')) return BigInt(v);
  return BigInt(v);
}

function hexToBuffer(v, expectedLen) {
  if (typeof v !== 'string') throw new Error(`expected hex string, got ${typeof v}`);
  const raw = v.startsWith('0x') || v.startsWith('0X') ? v.slice(2) : v;
  const buf = Buffer.from(raw, 'hex');
  if (expectedLen !== undefined && buf.length !== expectedLen) {
    throw new Error(`expected ${expectedLen} bytes, got ${buf.length}`);
  }
  return buf;
}

function hexToU256(v) {
  return parseBigIntLike(v);
}

function buildItemsTail(items, startIndex) {
  const b = beginCell();
  let i = startIndex;
  while (i < items.length) {
    if (b.availableBits < 256) {
      b.storeRef(buildItemsTail(items, i));
      return b.endCell();
    }
    b.storeUint(items[i], 256);
    i += 1;
  }
  return b.endCell();
}

function buildItemsRef(itemsU256) {
  if (itemsU256.length > 0xffff) {
    throw new Error(`too many proof items: ${itemsU256.length}`);
  }
  const b = beginCell();
  b.storeUint(itemsU256.length, 16);
  let i = 0;
  while (i < itemsU256.length) {
    if (b.availableBits < 256) {
      b.storeRef(buildItemsTail(itemsU256, i));
      return b.endCell();
    }
    b.storeUint(itemsU256[i], 256);
    i += 1;
  }
  return b.endCell();
}

function buildProofCell(data) {
  const mmrProof = data.mmr_proof ?? data.proof;
  const leaf = data.mmr_leaf ?? data.latest_mmr_leaf ?? data.leaf;
  const digestScaleHex = data.digest_scale;
  if (!mmrProof) throw new Error('missing mmr_proof/proof');
  if (!leaf) throw new Error('missing mmr_leaf/latest_mmr_leaf/leaf');
  if (!digestScaleHex) throw new Error('missing digest_scale');

  const leafIndex = parseIntLike(mmrProof.leaf_index);
  const leafCount = parseIntLike(mmrProof.leaf_count);
  const itemsU256 = (mmrProof.items ?? []).map(hexToU256);

  const version = parseIntLike(leaf.version);
  const parentNumber = parseIntLike(leaf.parent_number);
  const parentHash = hexToU256(leaf.parent_hash);
  const nextSetId = parseIntLike(leaf.next_authority_set_id);
  const nextSetLen = parseIntLike(leaf.next_authority_set_len);
  const nextSetRoot = hexToU256(leaf.next_authority_set_root);
  const randomSeed = hexToU256(leaf.random_seed);

  const digestScale = hexToBuffer(digestScaleHex);
  const digestRef = beginCell().storeBuffer(digestScale).endCell();

  const leafRef = beginCell()
    .storeUint(version, 8)
    .storeUint(parentNumber, 32)
    .storeUint(parentHash, 256)
    .storeUint(nextSetId, 64)
    .storeUint(nextSetLen, 32)
    .storeUint(nextSetRoot, 256)
    .storeUint(randomSeed, 256)
    .storeRef(digestRef)
    .endCell();

  const itemsRef = buildItemsRef(itemsU256);
  return beginCell()
    .storeUint(leafIndex, 64)
    .storeUint(leafCount, 64)
    .storeRef(itemsRef)
    .storeRef(leafRef)
    .endCell();
}

function parseArgs(argv) {
  const out = { format: 'both' };
  for (let i = 2; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--input') out.input = argv[++i];
    else if (a === '--output') out.output = argv[++i];
    else if (a === '--format') out.format = argv[++i];
    else throw new Error(`unknown arg: ${a}`);
  }
  if (!out.input) throw new Error('missing --input <bridge-relayer-json>');
  if (!['hex', 'base64', 'both'].includes(out.format)) {
    throw new Error(`invalid --format: ${out.format}`);
  }
  return out;
}

function main() {
  const args = parseArgs(process.argv);
  const data = JSON.parse(fs.readFileSync(args.input, 'utf8'));
  const proofCell = buildProofCell(data);
  const boc = proofCell.toBoc({ idx: false });
  const hex = `0x${boc.toString('hex')}`;
  const b64 = boc.toString('base64');

  if (args.output) {
    fs.writeFileSync(args.output, boc);
  }

  if (args.format === 'hex' || args.format === 'both') {
    console.log(`boc_hex=${hex}`);
  }
  if (args.format === 'base64' || args.format === 'both') {
    console.log(`boc_base64=${b64}`);
  }
}

try {
  main();
} catch (e) {
  console.error(`error: ${e.message}`);
  process.exit(1);
}

