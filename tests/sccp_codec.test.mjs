import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { Blockchain } from '@ton/sandbox';
import { beginCell, Cell, contractAddress, SendMode } from '@ton/core';

const repoRoot = resolve(import.meta.dirname, '..');

function loadArtifact(name) {
  return JSON.parse(readFileSync(resolve(repoRoot, 'artifacts', name), 'utf8'));
}

function codeFromArtifact(artifact) {
  return Cell.fromBoc(Buffer.from(artifact.codeBoc64, 'base64'))[0];
}

class SccpCodecTest {
  constructor(address, init) {
    this.address = address;
    this.init = init;
  }

  static createFromCode(code, workchain = 0) {
    const data = beginCell().endCell();
    const init = { code, data };
    return new SccpCodecTest(contractAddress(workchain, init), init);
  }

  async sendDeploy(provider, via, value) {
    // TopUpTons opcode (same as in `messages.tolk`).
    const TOP_UP_TONS = 0xd372158c;
    await provider.internal(via, {
      value,
      sendMode: SendMode.PAY_GAS_SEPARATELY,
      body: beginCell().storeUint(TOP_UP_TONS, 32).endCell(),
    });
  }

  async getMessageId(provider, sourceDomain, destDomain, nonce, soraAssetId, amount, recipient32) {
    const res = await provider.get('get_message_id', [
      { type: 'int', value: BigInt(sourceDomain) },
      { type: 'int', value: BigInt(destDomain) },
      { type: 'int', value: BigInt(nonce) },
      { type: 'int', value: BigInt(soraAssetId) },
      { type: 'int', value: BigInt(amount) },
      { type: 'int', value: BigInt(recipient32) },
    ]);
    return res.stack.readBigNumber();
  }
}

test('SCCP messageId matches reference vector (ETH -> SORA fixture)', async () => {
  const artifact = loadArtifact('sccp-codec-test.compiled.json');
  const code = codeFromArtifact(artifact);

  const blockchain = await Blockchain.create();
  const deployer = await blockchain.treasury('deployer');

  const c = blockchain.openContract(SccpCodecTest.createFromCode(code));
  await c.sendDeploy(deployer.getSender(), 1_000_000_000n);

  const sourceDomain = 1; // ETH
  const destDomain = 0; // SORA
  const nonce = 777;
  const soraAssetId = BigInt('0x' + '11'.repeat(32));
  const amount = 10n;
  const recipient32 = BigInt('0x' + '22'.repeat(32));

  const expected = BigInt(
    '0x' +
      'f3cac8c5acfb0670a24e9ffeab7e409a9d54d1dc5e6dbaf0ee986462fe1ffb3a',
  );

  const got = await c.getMessageId(sourceDomain, destDomain, nonce, soraAssetId, amount, recipient32);
  assert.equal(got, expected);
});
