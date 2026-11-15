import { mkdir, open } from 'node:fs/promises';
import { join } from 'node:path';
import { capture } from './client.mjs';

// 已领取页面中声明的链接视为新发现，进入队列后同样按派发时的有效政策判断。
export function discoverLinks(bytes, pageUrl) {
  let data;
  try {
    data = JSON.parse(Buffer.isBuffer(bytes) ? bytes.toString('utf8') : bytes);
  } catch {
    return [];
  }
  if (!data || !Array.isArray(data.links)) return [];
  const links = [];
  for (const link of data.links) {
    if (typeof link !== 'string') continue;
    try {
      links.push(new URL(link, pageUrl).href);
    } catch {
      // 忽略无效地址
    }
  }
  return links;
}

export class Collection {
  constructor({ directory, allow, policy, now, userAgent }) {
    this.directory = directory;
    this.allow = new Set(allow);
    this.policy = policy;
    this.now = now ?? (() => Date.now());
    this.userAgent = userAgent ?? 'CollectionBot';
    this.items = new Map();
    this.decisions = [];
    this.logPath = join(directory, 'decisions.jsonl');
  }

  // 链接入队时只校验白名单（授权上界）；政策判断推迟到派发时，
  // 保证新发现和已经排队的链接都受当前有效政策约束。
  async enqueue(target) {
    let url;
    try {
      url = new URL(target);
    } catch {
      await this.record({ url: String(target), action: 'rejected', reason: '地址无效', policy: null, rule: null });
      return false;
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      await this.record({ url: url.href, action: 'rejected', reason: '协议不在采集范围', policy: null, rule: null });
      return false;
    }
    if (!this.allow.has(url.origin)) {
      await this.record({ url: url.href, action: 'rejected', reason: '来源不在白名单', policy: null, rule: null });
      return false;
    }
    if (this.items.has(url.href)) return false;
    this.items.set(url.href, { url: url.href, state: 'pending', attempts: 0, receipt: null });
    return true;
  }

  async claim(target) {
    let url;
    try {
      url = new URL(target).href;
    } catch {
      await this.enqueue(target);
      return { action: 'rejected', url: String(target) };
    }
    if (!this.items.has(url)) await this.enqueue(url);
    const item = this.items.get(url);
    if (!item) return { action: 'rejected', url };
    if (item.state === 'done') return { action: 'claimed', duplicate: true, url, receipt: item.receipt };
    const decision = await this.policy.evaluate(url);
    const policy = { version: decision.version, status: decision.status };
    if (!decision.allowed) {
      item.attempts += 1;
      await this.record({ url, action: 'paused', reason: decision.reason, policy, rule: decision.rule });
      return { action: 'paused', url, reason: decision.reason, policy };
    }
    try {
      const { bytes, receipt } = await capture(url, this.directory, {
        headers: { 'user-agent': this.userAgent },
        source: { policyVersion: decision.version, policyRule: decision.rule?.pattern ?? null },
      });
      item.state = 'done';
      item.receipt = receipt;
      await this.record({ url, action: 'claimed', reason: decision.reason, policy, rule: decision.rule, receipt: receipt.id });
      return { action: 'claimed', url, bytes, receipt, policy };
    } catch (error) {
      item.attempts += 1;
      await this.record({ url, action: 'failed', reason: error.message, policy, rule: decision.rule });
      return { action: 'failed', url, error: error.message, policy };
    }
  }

  // 逐轮派发待领取链接；本轮暂停或失败的链接留在队列中，
  // 下次 drain（例如馆方恢复开放后）按届时有效政策继续判断，不会永久丢弃。
  async drain({ discover = discoverLinks, maxPasses = 8 } = {}) {
    const settled = new Set();
    for (let pass = 0; pass < maxPasses; pass += 1) {
      const pending = [...this.items.values()].filter(item => item.state === 'pending' && !settled.has(item.url));
      if (pending.length === 0) break;
      let claimed = 0;
      for (const item of pending) {
        const outcome = await this.claim(item.url);
        if (outcome.action === 'claimed') {
          claimed += 1;
          for (const link of discover(outcome.bytes, item.url)) await this.enqueue(link);
        } else {
          settled.add(item.url);
        }
      }
      if (claimed === 0) break;
    }
    return this.report();
  }

  report() {
    const items = [...this.items.values()];
    return {
      claimed: items.filter(item => item.state === 'done').map(item => item.url),
      paused: items.filter(item => item.state === 'pending').map(item => item.url),
      rejected: this.decisions.filter(decision => decision.action === 'rejected').map(decision => decision.url),
      decisions: this.decisions,
    };
  }

  // 每次领取、暂停、拒绝或失败都记录所依据的公告版本，持久化到 decisions.jsonl。
  async record(decision) {
    const entry = { at: new Date(this.now()).toISOString(), ...decision };
    this.decisions.push(entry);
    await mkdir(this.directory, { recursive: true });
    const handle = await open(this.logPath, 'a', 0o600);
    try {
      await handle.writeFile(JSON.stringify(entry) + '\n');
      await handle.sync();
    } finally {
      await handle.close();
    }
    return entry;
  }
}
