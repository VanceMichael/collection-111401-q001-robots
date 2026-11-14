import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createProvider } from '../provider/server.mjs';
import { receiveCurrent } from '../src/domain.mjs';
import { Archive } from '../src/archive.mjs';

async function controlled(provider, change) {
  const response = await fetch(provider.base + '/_control', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(change) });
  assert.equal(response.status, 200);
}

test('现有业务入口真实收存来源资料并可重新打开', async () => {
  const provider = await createProvider();
  const directory = await mkdtemp(join(tmpdir(), 'business-'));
  try {
    const result = await receiveCurrent(provider.base, directory);
    assert.ok(result);
    const archive = new Archive(directory);
    const receipts = await archive.list();
    assert.ok(receipts.length > 0);
    for (const receipt of receipts) assert.ok((await archive.read(receipt)).length > 0);
    assert.ok(provider.audit.some(request => !request.path.startsWith('/_')));
  } finally { await provider.close(); await rm(directory, { recursive: true, force: true }); }
});

test('政策有独立版本和明确分组', async () => {
 const provider = await createProvider();
 try {
const response = await fetch(provider.base + '/robots.txt'); assert.match(await response.text(), /User-agent: CollectionBot/); assert.equal(response.headers.get('etag'), '"policy-1"');
 } finally { await provider.close(); }
});

test('维护和缺少公告是不同响应', async () => {
 const provider = await createProvider();
 try {
await controlled(provider, {mode:'unavailable'}); assert.equal((await fetch(provider.base+'/robots.txt')).status,503); await controlled(provider,{mode:'absent'}); assert.equal((await fetch(provider.base+'/robots.txt')).status,404);
 } finally { await provider.close(); }
});

test('政策变更不修改资料身份', async () => {
 const provider = await createProvider();
 try {
await controlled(provider,{generation:2}); assert.match(await (await fetch(provider.base+'/robots.txt')).text(), /Disallow: \/public\//); assert.equal((await (await fetch(provider.base+'/public/a')).json()).id,'/public/a');
 } finally { await provider.close(); }
});
