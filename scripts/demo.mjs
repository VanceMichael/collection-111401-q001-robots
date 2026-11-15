import { createProvider } from '../provider/server.mjs';
import { createCollection, collect } from '../src/domain.mjs';
import { mkdtemp, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const directory = await mkdtemp(join(tmpdir(), 'collection-'));
const provider = await createProvider();
let tick = 1_000_000;
const now = () => tick;
const short = url => url.replace(provider.base, '');
const control = async change => {
  const response = await fetch(provider.base + '/_control', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(change),
  });
  if (!response.ok) throw new Error('演练控制失败：' + response.status);
};

try {
  const collection = createCollection(provider.base, directory, { now });
  const run = async phase => {
    const report = await collect(provider.base, directory, { collection, now });
    console.log(JSON.stringify({
      phase,
      claimed: report.claimed.map(short),
      paused: report.paused.map(short),
      依据: report.decisions.slice(-4).map(d => `${d.action} ${short(d.url)} ← ${d.policy?.version ?? '—'}（${d.reason}）`),
    }, null, 2));
    return report;
  };

  await run('首次批量采集（公告版本 "policy-1"）');

  await control({ generation: 2 });
  tick += 3000;
  await collection.enqueue(provider.base + '/public/b');
  await run('馆方临时关闭公开目录（"policy-2"），新链接 /public/b 进入队列');

  await control({ generation: 1 });
  tick += 3000;
  await run('馆方恢复开放（"policy-1"），暂缓资料继续领取');

  await control({ mode: 'unavailable' });
  tick += 3000;
  await run('公告临时不可达（503）：等待确认，不当作没有限制');

  await control({ mode: 'normal' });
  tick += 3000;
  await run('公告恢复');

  const forbidden = provider.audit.filter(entry => entry.path === '/public/private/x');
  const log = (await readFile(join(directory, 'decisions.jsonl'), 'utf8')).trim().split('\n');
  console.log(JSON.stringify({
    禁止路径请求次数: forbidden.length,
    决定日志条数: log.length,
    日志: 'decisions.jsonl 记录每次领取或暂停所依据的公告版本',
  }, null, 2));
} finally {
  await provider.close();
  await rm(directory, { recursive: true, force: true });
}
