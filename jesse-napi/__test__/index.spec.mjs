import test from 'ava'

import {Account, fidOf, ownerOfFname, registerFid, transferFname} from '../index.js'

test('fid queries from fname', async (t) => {
  const fid = await ownerOfFname("harris-");
  t.is(fid, 402621);
});

test('fid queries from onchain address', async (t) => {
  const onChainFid = await fidOf("0x4aab70fea9b9991ae29f36dcea0367009b22f26d");
  t.is(onChainFid, 402621);
});

const mnemonic = "test test test test test test test test test test test junk";

test('registration via mnemonic', async (t) => {
  const account = Account.fromMnemonic(mnemonic);

  const newFid = await registerFid(account, null);

  t.not(newFid, 0);
})

test('transferring an fname', async (t) => {
  const account = Account.fromMnemonic(mnemonic);

  const transferResult = await transferFname(account, "dwr.eth", 42069);

  t.is(transferResult, true);

})