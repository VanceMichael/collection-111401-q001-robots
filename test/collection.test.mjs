import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createProvider } from '../provider/server.mjs';
import { parseRobots, decidePath, PolicyManager } from '../src/policy.mjs';
import { createCollection, collect, receiveCurrent } from '../src/domain.mjs';
import { Archive } from '../src/archive.mjs';

const GENERATION_ONE = 'User-agent: *\nDisallow: /private\n\nUser-agent: CollectionBot\nDisallow: /public/private/\nAllow: /public/private/allow$\n';

function makeClock(start = 1_000_000) {
  const state = { tick: start };
  return { now: () => state.tick, advance: ms => { state.tick += ms; } };
}

async function controlled(provider, change) {
  const response = await fetch(provider.base + '/_control', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(change),
  });
  assert.equal(response.status, 200);
}

test('User-agent 分组、最长匹配与编码路径各自独立判断', () => {
  const groups = parseRobots(GENERATION_ONE);
  const decide = path => decidePath(groups, 'CollectionBot', path);
  // 分组隔离：* 组的 /private 不串用到 CollectionBot
  assert.equal(decide('/private/anything').allowed, true);
  // 本组规则与最长匹配
  assert.equal(decide('/public/a').allowed, true);
  assert.equal(decide('/public/private/x').allowed, false);
  assert.equal(decide('/public/private/x').rule.pattern, '/public/private/');
  assert.equal(decide('/public/private/allow').allowed, true);
  assert.equal(decide('/public/private/allow/deeper').allowed, false);
  // 编码路径不串用：%2f 是保留字，不等于字面的 /
  assert.equal(decide('/public/%2fprivate/y').allowed, true);
  assert.equal(decide('/public/%2Fprivate/y').allowed, true);
  // 非保留字编码不能用来绕过规则
  assert.equal(decide('/public/%70rivate/x').allowed, false);
  // 其他身份只落 * 组，判断互不串用
  const other = path => decidePath(groups, 'OtherBot', path);
  assert.equal(other('/private/anything').allowed, false);
  assert.equal(other('/public/private/x').allowed, true);
});

test('不支持的扩展字段不作为授权依据', () => {
  const groups = parseRobots('User-agent: CollectionBot\nCrawl-delay: 1\nDisallow: /tmp\nSitemap: http://127.0.0.1/sitemap.xml\n\nUser-agent: OtherBot\nDisallow:\n');
  assert.equal(groups.length, 2);
  assert.deepEqual(groups[0].rules, [{ type: 'disallow', pattern: '/tmp' }]);
  assert.deepEqual(groups[1].rules, []);
});

test('政策按来源隔离缓存，版本来自公告 ETag', async () => {
  const first = await createProvider();
  const second = await createProvider();
  try {
    await controlled(second, { generation: 2 });
    const manager = new PolicyManager({ now: makeClock().now });
    const open = await manager.evaluate(first.base + '/public/a');
    const closed = await manager.evaluate(second.base + '/public/a');
    assert.equal(open.allowed, true);
    assert.equal(open.version, '"policy-1"');
    assert.equal(closed.allowed, false);
    assert.equal(closed.version, '"policy-2"');
    // 再次评估第一个来源，不受第二个来源判断影响
    assert.equal((await manager.evaluate(first.base + '/public/a')).allowed, true);
  } finally {
    await first.close();
    await second.close();
  }
});

test('公告短时不可达沿用有效缓存，超出有效期等待确认', async () => {
  const provider = await createProvider();
  const clock = makeClock();
  try {
    const manager = new PolicyManager({ now: clock.now });
    assert.equal((await manager.evaluate(provider.base + '/public/a')).allowed, true);
    await controlled(provider, { mode: 'unavailable' });
    // 缓存仍在 max-age=2 有效期内：沿用尚有效的政策
    assert.equal((await manager.evaluate(provider.base + '/public/a')).allowed, true);
    // 超出有效期：进入等待确认，不当作没有限制
    clock.advance(3000);
    const decision = await manager.evaluate(provider.base + '/public/a');
    assert.equal(decision.allowed, false);
    assert.equal(decision.status, 'unconfirmed');
    assert.equal(decision.version, '"policy-1"');
    // 公告恢复后重新取得当前版本
    await controlled(provider, { mode: 'normal' });
    assert.equal((await manager.evaluate(provider.base + '/public/a')).allowed, true);
  } finally {
    await provider.close();
  }
});

test('404 表示没有公告，但不扩张来源白名单', async () => {
  const provider = await createProvider();
  const other = await createProvider();
  const directory = await mkdtemp(join(tmpdir(), 'absent-'));
  try {
    await controlled(provider, { mode: 'absent' });
    const collection = createCollection(provider.base, directory, { now: makeClock().now });
    await collection.enqueue(provider.base + '/public/a');
    await collection.enqueue(other.base + '/public/a');
    const report = await collection.drain();
    assert.deepEqual(report.claimed, [provider.base + '/public/a']);
    assert.deepEqual(report.rejected, [other.base + '/public/a']);
    assert.equal(report.decisions.find(decision => decision.action === 'claimed').policy.version, 'absent');
    // 白名单外的来源没有被请求
    assert.equal(other.audit.filter(entry => entry.path.startsWith('/public')).length, 0);
  } finally {
    await provider.close();
    await other.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test('批量采集全程受当前政策约束，恢复开放后继续工作', async () => {
  const provider = await createProvider();
  const directory = await mkdtemp(join(tmpdir(), 'collect-'));
  const clock = makeClock();
  try {
    const collection = createCollection(provider.base, directory, { now: clock.now });
    const run = () => collect(provider.base, directory, { collection, now: clock.now });

    // 首次批量采集（公告版本 "policy-1"）
    let report = await run();
    assert.ok(report.claimed.includes(provider.base + '/public/a'));
    assert.ok(report.claimed.includes(provider.base + '/public/private/allow'));
    assert.ok(report.claimed.includes(provider.base + '/public/%2fprivate/y'));
    assert.deepEqual(report.paused, [provider.base + '/public/private/x']);
    for (const decision of report.decisions) assert.equal(decision.policy.version, '"policy-1"');
    // 被禁止的路径从未被请求
    assert.equal(provider.audit.filter(entry => entry.path === '/public/private/x').length, 0);

    // 馆方临时关闭整个公开目录（"policy-2"），新发现的链接进入队列
    await controlled(provider, { generation: 2 });
    clock.advance(3000);
    await collection.enqueue(provider.base + '/public/b');
    report = await run();
    assert.equal(report.claimed.includes(provider.base + '/public/b'), false);
    assert.ok(report.paused.includes(provider.base + '/public/b'));
    assert.equal(report.decisions.filter(decision => decision.action === 'paused').at(-1).policy.version, '"policy-2"');
    // 关闭期间没有发出任何页面请求
    assert.equal(provider.audit.filter(entry => entry.path.startsWith('/public/')).length, 3);

    // 馆方恢复开放（回到 "policy-1"）：暂缓的资料继续领取，而不是被丢弃
    await controlled(provider, { generation: 1 });
    clock.advance(3000);
    report = await run();
    assert.ok(report.claimed.includes(provider.base + '/public/b'));
    assert.deepEqual(report.paused, [provider.base + '/public/private/x']);

    // 公告不可达：等待确认，不当作没有限制
    const servedBeforeOutage = provider.audit.filter(entry => entry.path.startsWith('/public/')).length;
    await controlled(provider, { mode: 'unavailable' });
    clock.advance(3000);
    report = await run();
    assert.deepEqual(report.paused, [provider.base + '/public/private/x']);
    const last = report.decisions.at(-1);
    assert.equal(last.action, 'paused');
    assert.equal(last.policy.status, 'unconfirmed');
    assert.equal(provider.audit.filter(entry => entry.path.startsWith('/public/')).length, servedBeforeOutage);

    // 公告恢复：队列仍在，按当前政策继续
    await controlled(provider, { mode: 'normal' });
    clock.advance(3000);
    report = await run();
    assert.deepEqual(report.paused, [provider.base + '/public/private/x']);

    // 决定日志持久化：每次领取或暂停都有版本依据
    const lines = (await readFile(join(directory, 'decisions.jsonl'), 'utf8')).trim().split('\n').map(JSON.parse);
    assert.equal(lines.length, report.decisions.length);
    for (const line of lines) {
      if (line.action === 'claimed' || line.action === 'paused') assert.ok(line.policy && line.policy.version);
    }
    // 收件凭据同样带来源政策版本
    const receipts = await new Archive(directory).list();
    assert.equal(receipts.length, 5);
    for (const receipt of receipts) assert.equal(receipt.source.policyVersion, '"policy-1"');
  } finally {
    await provider.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test('入口领取在公告不可达时暂缓而不是当作没有限制', async () => {
  const provider = await createProvider();
  const directory = await mkdtemp(join(tmpdir(), 'entry-'));
  try {
    await controlled(provider, { mode: 'unavailable' });
    await assert.rejects(() => receiveCurrent(provider.base, directory), /暂缓/);
    assert.equal(provider.audit.filter(entry => entry.path === '/index').length, 0);
  } finally {
    await provider.close();
    await rm(directory, { recursive: true, force: true });
  }
});
