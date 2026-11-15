import { createHash } from 'node:crypto';

const UNRESERVED = /^[A-Za-z0-9._~-]$/;
const REGEX_SPECIAL = /[.*+?^${}()|[\]\\]/;
const MAX_ROBOT_BYTES = 512 * 1024;
const MAX_REDIRECTS = 5;
const DEFAULT_MAX_AGE_SECONDS = 24 * 60 * 60;
const MAX_MAX_AGE_SECONDS = 24 * 60 * 60;

// RFC 9309 比较前的归一化：非保留字符的百分号编码解码，其余编码的十六进制统一大写。
// 保留字（如 %2F）保持编码形态，编码后的路径既不串用其他路径的判断，也不能借编码绕过规则。
export function canonicalizePath(path) {
  return path.replace(/%([0-9A-Fa-f]{2})/g, (sequence, hex) => {
    const character = String.fromCharCode(Number.parseInt(hex, 16));
    return UNRESERVED.test(character) ? character : '%' + hex.toUpperCase();
  });
}

// 解析 robots 公告分组。不支持的扩展字段（如 Crawl-delay、Sitemap）不作为授权依据，直接忽略。
export function parseRobots(text) {
  const groups = [];
  let current = null;
  let sawRule = false;
  for (const rawLine of text.replace(/^\uFEFF/, '').split(/\r\n|\r|\n/)) {
    const hash = rawLine.indexOf('#');
    const line = (hash >= 0 ? rawLine.slice(0, hash) : rawLine).trim();
    if (!line) continue;
    const colon = line.indexOf(':');
    if (colon < 0) continue;
    const field = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();
    if (field === 'user-agent') {
      if (!current || sawRule) {
        current = { agents: [], rules: [] };
        groups.push(current);
        sawRule = false;
      }
      if (value) current.agents.push(value);
    } else if (field === 'allow' || field === 'disallow') {
      if (!current || !value) continue;
      current.rules.push({ type: field, pattern: value });
      sawRule = true;
    }
  }
  return groups;
}

// 只取与采集身份最具体匹配的分组；其他分组（包括 *）的规则不串用。
function selectGroups(groups, userAgent) {
  const token = userAgent.toLowerCase();
  let best = -1;
  const selected = [];
  for (const group of groups) {
    for (const agent of group.agents) {
      const specificity = agent === '*' ? 0 : token.includes(agent.toLowerCase()) ? agent.length : -1;
      if (specificity < 0) continue;
      if (specificity > best) {
        best = specificity;
        selected.length = 0;
        selected.push(group);
      } else if (specificity === best && !selected.includes(group)) {
        selected.push(group);
      }
    }
  }
  return selected;
}

function matchPattern(pattern, path) {
  let body = pattern;
  let anchored = false;
  if (body.endsWith('$')) {
    anchored = true;
    body = body.slice(0, -1);
  }
  const source = [...body].map(character => {
    if (character === '*') return '.*';
    return REGEX_SPECIAL.test(character) ? '\\' + character : character;
  }).join('');
  return new RegExp('^' + source + (anchored ? '$' : '')).test(path);
}

// 按 RFC 9309 评估单个路径：最具体的 User-agent 分组、最长匹配、等长时 Allow 优先。
export function decidePath(groups, userAgent, rawPath) {
  const path = canonicalizePath(rawPath);
  let best = null;
  for (const group of selectGroups(groups, userAgent)) {
    for (const rule of group.rules) {
      const pattern = canonicalizePath(rule.pattern);
      if (!matchPattern(pattern, path)) continue;
      const length = pattern.endsWith('$') ? pattern.length - 1 : pattern.length;
      if (!best || length > best.length || (length === best.length && rule.type === 'allow')) {
        best = { length, type: rule.type, pattern: rule.pattern, group: group.agents.join(', ') };
      }
    }
  }
  if (!best) return { allowed: true, rule: null };
  return { allowed: best.type === 'allow', rule: { group: best.group, type: best.type, pattern: best.pattern } };
}

// 按来源获取、缓存并评估 robots 公告。判断不跨来源串用；获取失败不当作没有限制。
export class PolicyManager {
  constructor({ userAgent = 'CollectionBot', fetchImpl, now, timeout } = {}) {
    this.userAgent = userAgent;
    this.fetchImpl = fetchImpl ?? fetch;
    this.now = now ?? (() => Date.now());
    this.timeout = timeout ?? 5000;
    this.cache = new Map();
  }

  // 返回 { allowed, status, version, rule, reason }；status 为
  // current（有效公告）、absent（来源无公告）或 unconfirmed（公告不可达，等待确认）。
  async evaluate(target) {
    const url = new URL(target);
    const entry = await this.entryFor(url.origin);
    if (entry.kind === 'unconfirmed') {
      return { allowed: false, status: 'unconfirmed', version: entry.version, rule: null, reason: '政策不可达，等待确认' };
    }
    if (entry.kind === 'absent') {
      return { allowed: true, status: 'absent', version: 'absent', rule: null, reason: '来源未发布公告' };
    }
    const decision = decidePath(entry.groups, this.userAgent, url.pathname);
    return {
      allowed: decision.allowed,
      status: 'current',
      version: entry.version,
      rule: decision.rule,
      reason: decision.allowed ? '当前政策允许' : '当前政策禁止',
    };
  }

  async entryFor(origin) {
    const cached = this.cache.get(origin);
    if (cached && this.now() < cached.freshUntil) return cached;
    let fetched;
    try {
      fetched = await this.fetchRobots(origin);
    } catch {
      fetched = { kind: 'unavailable' };
    }
    const obtainedAt = this.now();
    if (fetched.kind === 'rules' || fetched.kind === 'absent') {
      const entry = {
        kind: fetched.kind,
        groups: fetched.kind === 'rules' ? parseRobots(fetched.body) : null,
        version: fetched.kind === 'rules' ? fetched.version : 'absent',
        obtainedAt,
        freshUntil: obtainedAt + fetched.maxAge * 1000,
      };
      this.cache.set(origin, entry);
      return entry;
    }
    // 获取失败（5xx、超时、网络错误）不当作没有限制：仍在有效期内的旧政策上面已沿用；
    // 超出有效期则等待确认，并保留最后已知版本作为暂停依据。
    return { kind: 'unconfirmed', version: cached?.version ?? 'unknown' };
  }

  async fetchRobots(origin) {
    let target = origin + '/robots.txt';
    for (let hop = 0; ; hop += 1) {
      const response = await this.fetchImpl(target, {
        redirect: 'manual',
        signal: AbortSignal.timeout(this.timeout),
        headers: { 'user-agent': this.userAgent },
      });
      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get('location');
        if (!location || hop >= MAX_REDIRECTS) return { kind: 'unavailable' };
        target = new URL(location, target).href;
        continue;
      }
      if (response.status >= 200 && response.status < 300) {
        const body = (await readLimited(response, MAX_ROBOT_BYTES)).toString('utf8');
        const version = response.headers.get('etag') ?? 'sha256:' + sha256hex(body).slice(0, 16);
        return { kind: 'rules', body, version, maxAge: maxAgeOf(response.headers.get('cache-control')) };
      }
      if (response.status >= 400 && response.status < 500) {
        return { kind: 'absent', maxAge: maxAgeOf(response.headers.get('cache-control')) };
      }
      return { kind: 'unavailable' };
    }
  }
}

async function readLimited(response, limit) {
  const chunks = [];
  let size = 0;
  for await (const chunk of response.body) {
    if (size + chunk.length > limit) {
      chunks.push(chunk.subarray(0, limit - size));
      break;
    }
    chunks.push(chunk);
    size += chunk.length;
  }
  return Buffer.concat(chunks);
}

function maxAgeOf(header) {
  if (!header) return DEFAULT_MAX_AGE_SECONDS;
  if (/(?:^|,)\s*no-store\s*(?:,|$)/i.test(header)) return 0;
  const match = /max-age\s*=\s*"?(\d+)"?/i.exec(header);
  if (match) return Math.min(Number(match[1]), MAX_MAX_AGE_SECONDS);
  return DEFAULT_MAX_AGE_SECONDS;
}

function sha256hex(text) {
  return createHash('sha256').update(text).digest('hex');
}
