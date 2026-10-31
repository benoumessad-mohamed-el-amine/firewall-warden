// Policy: allow/deny rules + egress allowlist + write roots. Loadable from a
// .warden.json file (Claude-Code-style rule syntax: `tool(glob)`).
import fs from 'node:fs';
import path from 'node:path';
import { safeStringify, asStr, canonicalHost } from './scan.mjs';

export const DEFAULT_POLICY = { allow: [], deny: [], egressAllow: [], writeRoots: null, provenance: null };

export const DEFAULT_UNTRUSTED_SOURCES = [
  { match: 'fetch(*)', trust: 'untrusted' },
  { match: 'http(*)', trust: 'untrusted' },
  { match: 'browser(*)', trust: 'untrusted' },
  { match: 'puppeteer(*)', trust: 'untrusted' },
  { match: 'playwright(*)', trust: 'untrusted' },
  { match: 'web_search(*)', trust: 'untrusted' },
  { match: 'search_web(*)', trust: 'untrusted' },
  { match: 'read_url_content(*)', trust: 'untrusted' },
  { match: '*issue*(*)', trust: 'untrusted' },
  { match: '*pull_request*(*)', trust: 'untrusted' },
  { match: '*comment*(*)', trust: 'untrusted' },
  { match: '*mail*(*)', trust: 'untrusted' },
  { match: '*email*(*)', trust: 'untrusted' },
];

export const DEFAULT_TAINTED_POLICY = {
  deny: [
    'fetch(*"POST"*)',
    'fetch(*"PUT"*)',
    'fetch(*"PATCH"*)',
    'http(*"POST"*)',
    'http(*"PUT"*)',
    'http(*"PATCH"*)',
    'shell(*git push*)',
    'shell(*mail *)',
    'shell(*sendmail*)',
    'shell(*gist*)',
    '*gist*(*)',
    '*paste*(*)',
    '*send*mail*(*)',
    '*upload*(*)',
  ],
  gate: [
    'shell(*)',
    'read_file(*.env*)',
    'read_file(*id_rsa*)',
    'read_file(*credentials*)',
  ],
};

export function normalizeProvenance(prov) {
  if (!prov) return null;
  const p = typeof prov === 'object' ? prov : {};
  return {
    enabled: true,
    sources: Array.isArray(p.sources) && p.sources.length ? p.sources : [...DEFAULT_UNTRUSTED_SOURCES],
    taintedPolicy: {
      deny: Array.isArray(p.taintedPolicy?.deny) ? p.taintedPolicy.deny : [...DEFAULT_TAINTED_POLICY.deny],
      gate: Array.isArray(p.taintedPolicy?.gate) ? p.taintedPolicy.gate : [...DEFAULT_TAINTED_POLICY.gate],
    },
    taintDecayCalls: typeof p.taintDecayCalls === 'number' && p.taintDecayCalls >= 0 ? p.taintDecayCalls : null,
  };
}

// The project policy file was `warden.config.json` before the rename. A fresh
// `warden init` now writes `warden.config.json`, but an existing
// `warden.config.json` is still read transparently (see resolveConfig) so a
// project set up before the rename keeps working. (The GLOBAL config at
// `~/.warden/config.json` and the `WARDEN_*` env vars are kept as-is for
// compatibility — only the project filename gets the branded default.)
export const DEFAULT_CONFIG = 'warden.config.json';
export const LEGACY_CONFIG = 'warden.config.json';

/** Pick the project config file when no explicit `--policy` is given: prefer
 *  `warden.config.json`, fall back to an existing `warden.config.json`, and
 *  default to `warden.config.json` when neither exists. */
export function resolveConfig(explicit, dir = process.cwd()) {
  if (typeof explicit === 'string' && explicit) return explicit;
  for (const name of [DEFAULT_CONFIG, LEGACY_CONFIG]) {
    const p = path.join(dir, name);
    try { if (fs.existsSync(p)) return p; } catch {}
  }
  return path.join(dir, DEFAULT_CONFIG);
}

// Linear, anchored glob match where only `*` is special (matches any run of
// chars, INCLUDING newlines). Replaces the old `pat.replace(/\*/g,'.*')` + anchored
// RegExp, which had two faults: (1) `.` does not match `\n`, so a rule silently
// FAILED to match a multi-line command — a deny rule was bypassable by adding a
// newline (fail-open); (2) every `*`→`.*` against a non-matching subject caused
// catastrophic backtracking (ReDoS: a multi-star rule could pin a CPU for minutes
// in the firewall's hot path). This greedy left-to-right scan is O(n·segments)
// with no backtracking, and `*` spanning newlines fixes the bypass. (`*`-only
// globs admit a correct greedy match — no `?`/`[]` were ever supported.)
function globMatch(pattern, text) {
  const parts = pattern.split('*');
  if (parts.length === 1) return text === pattern;          // no wildcard → exact
  if (!text.startsWith(parts[0])) return false;             // anchored prefix
  let idx = parts[0].length;
  for (let k = 1; k < parts.length - 1; k++) {              // middle segments, in order
    const seg = parts[k];
    if (!seg) continue;
    const at = text.indexOf(seg, idx);
    if (at < 0) return false;
    idx = at + seg.length;
  }
  const last = parts[parts.length - 1];
  return text.length - last.length >= idx && text.endsWith(last); // anchored suffix
}

/** Does an action match a rule like `shell(npm run test:*)` / `write(src/**)` / `fetch(api.github.com)`? */
export function matchRule(rule, action) {
  const m = /^([^()]+)\((.*)\)$/.exec(rule);
  if (!m) return false;
  const [, t, pat] = m;
  const toolName = asStr((action && action.tool) || '').toLowerCase();
  const ruleTool = t.toLowerCase();
  if (ruleTool.includes('*')) {
    if (!globMatch(ruleTool, toolName)) return false;
  } else if (ruleTool !== toolName) {
    return false;
  }
  if (pat === '*') return true;
  const i = (action && action.input) || {};
  const subject = i.command || i.path || i.url || i;
  // Coerce safely: a string is itself; an array (split command) joins via
  // map(String) — so a Symbol element can't throw; anything else goes through
  // safeStringify (circular/BigInt/Symbol-safe). A bare String() would throw on
  // a Symbol or a Symbol-bearing array.
  const text = typeof subject === 'string' ? subject
    : Array.isArray(subject) ? subject.map(String).join(' ')
    : safeStringify(subject);
  if (globMatch(pat, text)) return true;
  if (typeof subject === 'string') {
    const fullText = safeStringify(i);
    if (globMatch(pat, fullText)) return true;
  }
  return false;
}

// Coerce a rule list to an array: a scalar/object (e.g. a `.warden.json` with
// `"allow": "shell(*)"` instead of `["shell(*)"]`) must NOT survive as a non-array,
// or the decision engine's `.find()`/`.some()` throws and the hook fails OPEN on a
// black action. A bad value drops to [] (fail closed: nothing pre-allowed).
const asRules = (v) => (Array.isArray(v) ? v : []);

/** Merge a .warden.json file over the defaults. Never throws — bad/missing file → defaults. */
export function loadPolicy(path) {
  try {
    const parsed = JSON.parse(fs.readFileSync(path, 'utf8'));
    return normalizePolicy({ ...DEFAULT_POLICY, ...parsed });
  } catch {
    return { ...DEFAULT_POLICY };
  }
}

/** Force the rule/egress lists to arrays and writeRoots to array|null. Idempotent. */
export function normalizePolicy(policy) {
  const p = policy || {};
  return {
    ...p,
    allow: asRules(p.allow),
    deny: asRules(p.deny),
    egressAllow: asRules(p.egressAllow),
    writeRoots: Array.isArray(p.writeRoots) ? p.writeRoots : null,
    provenance: normalizeProvenance(p.provenance),
  };
}

/**
 * Parse an egressAllow rule entry.
 * May be host-only ("api.github.com") or path-scoped ("api.github.com/repos/ORG/*").
 */
export function parseEgressRule(rule) {
  if (typeof rule !== 'string') return null;
  const trimmed = rule.trim();
  const slash = trimmed.indexOf('/');
  if (slash < 0) {
    return {
      host: canonicalHost(trimmed.toLowerCase()),
      pathGlob: null,
      isPathScoped: false,
      raw: trimmed,
    };
  }
  const hostPart = trimmed.slice(0, slash).toLowerCase();
  let pathPart = trimmed.slice(slash);
  if (!pathPart.startsWith('/')) pathPart = '/' + pathPart;
  return {
    host: canonicalHost(hostPart),
    pathGlob: pathPart,
    isPathScoped: true,
    raw: trimmed,
  };
}

/**
 * Normalize a destination URL or string for path-level egress matching.
 *  - lowercase host
 *  - strip trailing dot
 *  - reject userinfo ("host@evil")
 *  - handle ports: default 80/443 stripped; non-default preserved on host
 *  - decode percent-encoded path segments once
 *  - resolve "." and ".." segments
 *  - collapse "//"
 *  - handle scheme-relative URLs ("//api.github.com/path")
 * Returns { valid: true, host, path, raw } or { valid: false, reason, host, raw }
 */
export function normalizeDestination(dest) {
  if (typeof dest !== 'string' || !dest.trim()) {
    return { valid: false, reason: 'empty or non-string destination', host: '', path: '', raw: dest };
  }
  let s = dest.trim();

  // Check for git SCP-style destination: [user@]host:path
  const scp = /^(?:([a-z0-9_.-]+)@)?([a-z0-9_.-]+):(?!\/\/)(.*)$/i.exec(s);
  if (scp && !/^[a-z]$/i.test(scp[2])) {
    const user = scp[1];
    const rawHost = scp[2];
    const rawPath = scp[3];
    if (user && user !== 'git') {
      return { valid: false, reason: 'SCP destination contains non-git userinfo', host: rawHost, path: '', raw: dest, userinfo: user };
    }
    const host = canonicalHost(rawHost.toLowerCase());
    const rawSegments = (rawPath.startsWith('/') ? rawPath : '/' + rawPath).split('/');
    const stack = [];
    for (const seg of rawSegments) {
      let decoded;
      try {
        decoded = decodeURIComponent(seg);
      } catch {
        return { valid: false, reason: 'malformed percent encoding in path', host, path: '', raw: dest };
      }
      if (!decoded || decoded === '.') continue;
      if (decoded === '..') {
        if (stack.length > 0) stack.pop();
      } else {
        stack.push(decoded);
      }
    }
    const normPath = '/' + stack.join('/');
    return { valid: true, host, path: normPath, raw: dest };
  }

  if (s.startsWith('//')) s = 'http:' + s;
  else if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = 'http://' + s;

  let u;
  try {
    u = new URL(s);
  } catch {
    return { valid: false, reason: 'unparseable URL', host: '', path: '', raw: dest };
  }

  // Reject userinfo
  if (u.username || u.password) {
    return { valid: false, reason: 'URL contains userinfo', host: u.hostname || '', path: u.pathname || '', raw: dest, userinfo: u.username || u.password };
  }

  let host = (u.hostname || '').toLowerCase().replace(/\.$/, '');
  host = canonicalHost(host);

  // Port handling: if non-default port is specified, include it in host
  const port = u.port;
  if (port && port !== '80' && port !== '443') {
    host = host + ':' + port;
  }

  // Normalize path
  const rawPath = u.pathname || '/';
  const rawSegments = rawPath.split('/');
  const stack = [];
  for (const seg of rawSegments) {
    let decoded;
    try {
      decoded = decodeURIComponent(seg);
    } catch {
      return { valid: false, reason: 'malformed percent encoding in path', host, path: '', raw: dest };
    }
    if (!decoded || decoded === '.') continue;
    if (decoded === '..') {
      if (stack.length > 0) stack.pop();
    } else {
      stack.push(decoded);
    }
  }
  const normPath = '/' + stack.join('/');
  return { valid: true, host, path: normPath, raw: dest };
}

/**
 * Linear-time path glob matcher:
 * "*" = one path segment
 * "**" = zero or more segments
 * Everything else literal and case-sensitive.
 * Zero regex, no backtracking.
 */
export function matchPathGlob(pattern, normPath) {
  const pSegs = pattern.replace(/^\//, '').split('/').filter(Boolean);
  const sSegs = normPath.replace(/^\//, '').split('/').filter(Boolean);

  if (!pSegs.includes('**')) {
    if (pSegs.length !== sSegs.length) return false;
    for (let i = 0; i < pSegs.length; i++) {
      if (pSegs[i] !== '*' && pSegs[i] !== sSegs[i]) return false;
    }
    return true;
  }

  const chunks = [];
  let cur = [];
  for (const seg of pSegs) {
    if (seg === '**') {
      chunks.push(cur);
      cur = [];
    } else {
      cur.push(seg);
    }
  }
  chunks.push(cur);

  const prefix = chunks[0];
  const suffix = chunks[chunks.length - 1];

  if (sSegs.length < prefix.length + suffix.length) return false;

  for (let i = 0; i < prefix.length; i++) {
    if (prefix[i] !== '*' && prefix[i] !== sSegs[i]) return false;
  }

  for (let i = 0; i < suffix.length; i++) {
    const pVal = suffix[suffix.length - 1 - i];
    const sVal = sSegs[sSegs.length - 1 - i];
    if (pVal !== '*' && pVal !== sVal) return false;
  }

  let sIdx = prefix.length;
  const sEnd = sSegs.length - suffix.length;

  for (let c = 1; c < chunks.length - 1; c++) {
    const chunk = chunks[c];
    if (chunk.length === 0) continue;
    let found = false;
    for (let i = sIdx; i <= sEnd - chunk.length; i++) {
      let match = true;
      for (let j = 0; j < chunk.length; j++) {
        if (chunk[j] !== '*' && chunk[j] !== sSegs[i + j]) {
          match = false;
          break;
        }
      }
      if (match) {
        sIdx = i + chunk.length;
        found = true;
        break;
      }
    }
    if (!found) return false;
  }

  return true;
}

/**
 * Check whether a destination (URL or host) satisfies egressAllow rules.
 * When ANY path-scoped rule exists for a host, requests to that host that match
 * no path rule are denied (fail closed for that host only).
 */
export function checkEgressAllowed(dest, egressAllow = []) {
  if (!egressAllow || !egressAllow.length) {
    return { allowed: true, host: '', path: '', reason: 'no egress rules' };
  }
  const norm = normalizeDestination(dest);
  const parsedRules = egressAllow.map(parseEgressRule).filter(Boolean);

  if (!norm.valid) {
    // Check if any path rule applies to this destination (hostname, userinfo, or raw text)
    const raw = String(dest || '').toLowerCase();
    const pathRules = parsedRules.filter((r) => r.isPathScoped);
    const matchedPathRule = pathRules.find((r) => {
      if (norm.host && (norm.host === r.host || norm.host.endsWith('.' + r.host))) return true;
      if (norm.userinfo && (norm.userinfo === r.host || r.host.endsWith('.' + norm.userinfo) || norm.userinfo.endsWith('.' + r.host))) return true;
      if (raw.includes(r.host)) return true;
      const bareDomain = r.host.replace(/^[^.]+\./, '');
      if (bareDomain && raw.includes(bareDomain)) return true;
      return false;
    });

    if (matchedPathRule) {
      return {
        allowed: false,
        pathViolation: true,
        host: norm.host || raw,
        path: norm.path || '',
        failedRules: [matchedPathRule.raw],
        reason: `${norm.reason} for host ${norm.host || raw}, path rule ${matchedPathRule.raw} cannot be evaluated`,
      };
    }
    return { allowed: false, pathViolation: false, host: norm.host || raw, path: '', reason: norm.reason };
  }

  const baseHost = norm.host.replace(/:\d+$/, '');
  const matchingHostRules = parsedRules.filter((r) => {
    const rBase = r.host.replace(/:\d+$/, '');
    return baseHost === rBase || baseHost.endsWith('.' + rBase);
  });

  if (!matchingHostRules.length) {
    return { allowed: false, pathViolation: false, host: norm.host, path: norm.path, reason: 'host not in egress allowlist' };
  }

  const pathRules = matchingHostRules.filter((r) => r.isPathScoped);
  if (!pathRules.length) {
    // Host-only matching: all paths allowed if host matches
    const hostMatched = matchingHostRules.some((r) => norm.host === r.host || norm.host.endsWith('.' + r.host));
    if (hostMatched) {
      return { allowed: true, pathViolation: false, host: norm.host, path: norm.path, matchedRule: matchingHostRules[0].raw };
    }
    return { allowed: false, pathViolation: false, host: norm.host, path: norm.path, reason: 'host/port not in egress allowlist' };
  }

  // Path-scoped matching: at least one path rule must match both host/port and path glob
  for (const pr of pathRules) {
    const hostMatch = norm.host === pr.host || norm.host.endsWith('.' + pr.host);
    if (hostMatch && matchPathGlob(pr.pathGlob, norm.path)) {
      return { allowed: true, pathViolation: false, host: norm.host, path: norm.path, matchedRule: pr.raw };
    }
  }

  return {
    allowed: false,
    pathViolation: true,
    host: norm.host,
    path: norm.path,
    failedRules: pathRules.map((r) => r.raw),
    reason: `host ${norm.host}, path ${norm.path} does not match rule ${pathRules.map((r) => r.raw).join(', ')}`,
  };
}

