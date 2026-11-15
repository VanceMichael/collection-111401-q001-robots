import { Archive } from './archive.mjs';
import { PolicyManager } from './policy.mjs';
import { Collection, discoverLinks } from './collection.mjs';

// 采集上下文：来源白名单（授权上界，默认仅入口来源）、公告管理器与采集队列。
export function createCollection(base, directory, options = {}) {
  const origin = new URL(base).origin;
  const allow = (options.allow ?? [origin]).map(entry => new URL(entry).origin);
  const now = options.now ?? (() => Date.now());
  const userAgent = options.userAgent ?? 'CollectionBot';
  const policy = new PolicyManager({ userAgent, now, fetchImpl: options.fetchImpl, timeout: options.timeout });
  return new Collection({ directory, allow, policy, now, userAgent });
}

// 现有业务入口：领取入口公告页。领取本身也按当前有效政策判断。
export async function receiveCurrent(base, directory, options = {}) {
  const collection = options.collection ?? createCollection(base, directory, options);
  const outcome = await collection.claim(new URL('/index', base).href);
  if (outcome.action !== 'claimed') throw new Error(`入口资料按当前政策暂缓：${outcome.reason ?? '未知原因'}`);
  const bytes = outcome.bytes ?? await new Archive(directory).read(outcome.receipt);
  const data = JSON.parse(bytes);
  return { receipt: outcome.receipt.id, links: data.links, policy: data.policy };
}

// 批量采集入口：领取入口、发现链接入队，队列按派发时的当前有效政策逐个判断。
// 暂停的链接保留在队列中，馆方恢复开放后再次调用即继续，不会永久丢弃。
export async function collect(base, directory, options = {}) {
  const collection = options.collection ?? createCollection(base, directory, options);
  const index = new URL('/index', base).href;
  const outcome = await collection.claim(index);
  if (outcome.action === 'claimed' && !outcome.duplicate) {
    for (const link of discoverLinks(outcome.bytes, index)) await collection.enqueue(link);
  }
  return collection.drain();
}
