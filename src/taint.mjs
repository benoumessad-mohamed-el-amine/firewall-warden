// Cross-call taint tracking — the stateful layer over the stateless core.
//
// decide() classifies ONE call in isolation, which an attacker evades by
// splitting an exfil across calls: read a secret into a temp file (call 1 —
// looks like a sensitive read), then ship that temp file to an external host
// (call 2 — looks benign, because THIS call carries no visible secret). Only a
// session that remembers call 1 can catch call 2.
//
// TaintSession is opt-in and additive: decide() is untouched and every verdict
// here starts from it. The session can only RAISE risk (like the judge tier),
// never lower a block — so wrapping a stream of calls is always at least as safe
// as calling decide() on each. Deterministic and offline: no model, no network.
import crypto from 'node:crypto';
import { decide, TIER } from './index.mjs';
import { scanSecrets, isExternal, safeStringify, SENSITIVE_PATH_RE } from './scan.mjs';
import { normalizePolicy, matchRule, DEFAULT_UNTRUSTED_SOURCES } from './policy.mjs';
import { SHELL } from './classify.mjs';

const ORDER = { green: 0, yellow: 1, red: 2, black: 3 };
const worst = (a, b) => (ORDER[a] >= ORDER[b] ? a : b);

// The command text of an action, symbol/array/circular-safe (never throws).
function cmdText(action) {
  const i = (action && action.input) || {};
  const c = i.command ?? i.cmd;
  if (typeof c === 'string') return c;
  if (Array.isArray(c)) return c.map((x) => (typeof x === 'string' ? x : '')).join(' ');
  return safeStringify(i);
}

// Destinations a command writes secret-bearing output INTO — so the taint flows
// to that file. `cat ~/.ssh/id_rsa > /tmp/x`, `cp .env /tmp/x`, `tar czf /tmp/x`.
function writeDests(cmd) {
  const out = [];
  // redirection: `> file` / `>> file` (not a fd dup like `2>&1`)
  for (const m of cmd.matchAll(/(?<![0-9&])>>?\s*([^\s|;&<>()]{1,200})/g)) out.push(m[1]);
  // cp/mv/install SRC ... DEST  (last non-flag token is the destination)
  for (const m of cmd.matchAll(/\b(?:cp|mv|install)\b((?:\s+-\S+|\s+[^\s|;&]+){2,})/gi)) {
    const toks = m[1].trim().split(/\s+/).filter((t) => !t.startsWith('-'));
    if (toks.length >= 2) out.push(toks[toks.length - 1]);
  }
  // tar/zip archive target: `tar czf DEST ...`, `zip DEST ...`
  for (const m of cmd.matchAll(/\b(?:tar\s+[a-z]*f|zip(?:\s+-\S+)*)\s+([^\s|;&]{1,200})/gi)) out.push(m[1]);
  return out;
}

// Does the command actually SEND data out (vs. a plain GET)? Used to keep the
// weaker in-memory-secret signal precise: reading a secret then GETting an
// external URL is usually benign; POSTing/uploading data after is the concern.
const SEND_SHAPE = /-d\b|--data(?:-binary|-raw)?\b|-F\b|--form\b|-T\b|--upload-file\b|-X\s*(?:POST|PUT|PATCH)\b|--request\s+(?:POST|PUT|PATCH)\b|\bnc\b|\bncat\b|\bscp\b|\brsync\b|\bsocat\b/i;
function looksLikeSend(cmd, action) {
  if (SEND_SHAPE.test(cmd)) return true;
  const m = ((action && action.input && (action.input.method)) || '');
  return typeof m === 'string' && /^(post|put|patch)$/i.test(m);
}

export function isOutboundWrite(action) {
  if (!action) return false;
  const tool = String((action && action.tool) || '').toLowerCase();
  const input = action.input || {};
  const method = String(input.method || '').toUpperCase();
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) return true;
  const cmd = String(input.command || input.cmd || '');
  if (looksLikeSend(cmd, action)) return true;
  if (/\b(?:git\s+push|sendmail|mail\s+-s|gh\s+gist\b|gist\b)\b/i.test(cmd)) return true;
  if (/gist|paste|upload|send.*mail/i.test(tool)) return true;
  return false;
}

export function isSecretRead(action) {
  if (!action) return false;
  const input = action.input || {};
  const p = String(input.path || input.filepath || input.file || input.target || '');
  if (p && SENSITIVE_PATH_RE.test(p)) return true;
  const cmd = String(input.command || input.cmd || '');
  if (cmd && SENSITIVE_PATH_RE.test(cmd)) return true;
  return false;
}

export function isShell(action) {
  if (!action) return false;
  const tool = String((action && action.tool) || '').toLowerCase();
  return SHELL.includes(tool);
}

// (src, dst) pairs so taint propagates through a copy/move of a tainted file.
function copyPairs(cmd) {
  const pairs = [];
  for (const m of cmd.matchAll(/\b(?:cp|mv|install)\b((?:\s+-\S+|\s+[^\s|;&]+){2,})/gi)) {
    const toks = m[1].trim().split(/\s+/).filter((t) => !t.startsWith('-'));
    if (toks.length >= 2) for (let k = 0; k < toks.length - 1; k++) pairs.push([toks[k], toks[toks.length - 1]]);
  }
  return pairs;
}

function escalate(v, tier, why) {
  const t = worst(v.tier, tier);
  const decision = t === TIER.BLACK ? 'block' : t === TIER.RED ? (v.decision === 'block' ? 'block' : 'approve') : v.decision;
  return { ...v, tier: t, decision, why: [...v.why, why], crossCall: true };
}

export class TaintSession {
  constructor(policy = undefined) {
    this.policy = policy;
    const norm = normalizePolicy(policy);
    this._egress = norm.egressAllow || [];
    this.taintDecayCalls = norm.provenance?.taintDecayCalls ?? null;
    this.taintedPaths = new Set(); // files that hold secret-derived bytes
    this.holdsSecret = false;      // a secret was read to stdout/memory this session
    this.calls = 0;
    this.tainted = false;
    this.sources = [];
    this.taintedAtCall = null;
  }

  isTainted() {
    this._checkDecay();
    return this.tainted;
  }

  getTaintState() {
    return {
      tainted: this.isTainted(),
      sources: [...this.sources],
    };
  }

  markTainted({ tool, seq, hash }) {
    this.tainted = true;
    this.sources.push({ tool, seq, hash });
    this.taintedAtCall = this.calls;
  }

  _checkDecay() {
    if (this.tainted && this.taintDecayCalls != null) {
      if (this.taintedAtCall != null && this.calls - this.taintedAtCall > this.taintDecayCalls) {
        this.clearProvenanceTaint();
      }
    }
  }

  clearProvenanceTaint() {
    this.tainted = false;
    this.sources = [];
    this.taintedAtCall = null;
  }

  resetProvenance() {
    this.clearProvenanceTaint();
  }

  applyTaintedPolicy(action, v) {
    const norm = normalizePolicy(this.policy);
    const prov = norm.provenance;
    if (!prov || !prov.enabled) {
      return { ...v, taint: this.getTaintState() };
    }

    const { deny = [], gate = [] } = prov.taintedPolicy || {};
    let denied = false;
    let denyRule = '';

    for (const rule of deny) {
      if (matchRule(rule, action)) {
        denied = true;
        denyRule = rule;
        break;
      }
    }
    if (!denied && isOutboundWrite(action)) {
      denied = true;
      denyRule = 'outbound write';
    }

    if (denied) {
      return {
        ...v,
        tier: TIER.BLACK,
        decision: 'block',
        why: [...v.why, `☠ tainted session: outbound write denied (${denyRule})`],
        taint: this.getTaintState(),
      };
    }

    let gated = false;
    let gateRule = '';
    for (const rule of gate) {
      if (matchRule(rule, action)) {
        gated = true;
        gateRule = rule;
        break;
      }
    }
    if (!gated && (isSecretRead(action) || isShell(action))) {
      gated = true;
      gateRule = isSecretRead(action) ? 'secret-file read' : 'shell command';
    }

    if (gated) {
      const newTier = worst(v.tier, TIER.RED);
      const newDecision = newTier === TIER.BLACK ? 'block' : 'approve';
      return {
        ...v,
        tier: newTier,
        decision: newDecision,
        why: [...v.why, `⚠ tainted session: gated by tainted policy (${gateRule})`],
        taint: this.getTaintState(),
      };
    }

    return { ...v, taint: this.getTaintState() };
  }

  // Classify one call in the CONTEXT of the session so far. Returns decide()'s
  // verdict, possibly RAISED for a cross-call flow. Never throws, never lowers.
  // `skillText` is forwarded to decide() unchanged so callers that vet skill
  // text (the daemon's action-shape requests) keep that classification when they
  // route through a session.
  check(action, skillText = '') {
    this.calls++;
    this._checkDecay();
    let v;
    try { v = decide(action, this.policy, skillText); } catch { return { tool: action && action.tool, tier: TIER.RED, decision: 'approve', why: ['⚠ taint: guard error — fail-safe gate'], crossCall: true, taint: this.getTaintState() }; }
    let out = v;
    if (this.isTainted()) {
      out = this.applyTaintedPolicy(action, out);
    } else {
      out.taint = this.getTaintState();
    }

    try {
      const cmd = cmdText(action);
      const sec = scanSecrets(action);
      const extern = (sec.hosts || []).filter((h) => isExternal(h, this._egress));

      // ── SINK: is this call shipping tainted data OUT? (evaluate before we
      //    re-taint on this same call) ──
      if (out.decision !== 'block' && extern.length) {
        const sentPath = [...this.taintedPaths].find((p) => p && cmd.includes(p));
        if (sentPath) {
          out = escalate(out, TIER.BLACK, `☠ CROSS-CALL EXFIL: ${sentPath} (derived from a secret read earlier this session) → external ${extern.join(',')}`);
        } else if (out.decision === 'allow' && this.holdsSecret && looksLikeSend(cmd, action)) {
          // weaker signal: a DATA-SEND (not a plain GET) to an external host
          // after a secret was read this session, with no tainted file named —
          // gate for review rather than block.
          out = escalate(out, TIER.RED, `⚠ cross-call: external data-send to ${extern.join(',')} after a secret was read this session`);
        }
      }

      // ── SOURCE + PROPAGATION: update taint AFTER classifying this call ──
      if (sec.hasSecret) {
        const dests = writeDests(cmd);
        if (dests.length) for (const d of dests) this.taintedPaths.add(d);
        else this.holdsSecret = true; // read to stdout/memory, no file target
      }
      for (const [src, dst] of copyPairs(cmd)) {
        if (this.taintedPaths.has(src) || SENSITIVE_PATH_RE.test(src)) this.taintedPaths.add(dst);
      }
    } catch { /* taint analysis is best-effort; the stateless verdict always stands */ }
    return out;
  }

  // Inspect / reset session state (for a new agent task).
  state() {
    return {
      calls: this.calls,
      holdsSecret: this.holdsSecret,
      taintedPaths: [...this.taintedPaths],
      tainted: this.isTainted(),
      sources: [...this.sources],
    };
  }

  reset() {
    this.taintedPaths.clear();
    this.holdsSecret = false;
    this.calls = 0;
    this.clearProvenanceTaint();
  }
}

/**
 * Observe a tool result in the context of an agent session.
 * If the call matches an untrusted source, marks the session tainted.
 * Stores ONLY metadata and a content hash: { tainted, sources: [{tool, seq, hash}] }.
 * NEVER stores result content.
 */
export function observeResult(call, result, session) {
  if (!session || !call) return null;
  const norm = normalizePolicy(session.policy);
  const prov = norm.provenance;
  if (!prov || !prov.enabled) return session.getTaintState();

  const sources = prov.sources || DEFAULT_UNTRUSTED_SOURCES;
  let isUntrusted = false;
  for (const src of sources) {
    if (matchRule(src.match, call)) {
      if (src.trust === 'untrusted') {
        isUntrusted = true;
        break;
      }
      if (src.trust === 'trusted') {
        return session.getTaintState();
      }
    }
  }

  // Also default heuristics if rule list wasn't matched explicitly
  if (!isUntrusted && sources === DEFAULT_UNTRUSTED_SOURCES) {
    const t = String(call.tool || '').toLowerCase();
    if (['fetch', 'http', 'browser', 'puppeteer', 'playwright', 'web_search', 'search_web', 'read_url_content'].includes(t) ||
        t.includes('issue') || t.includes('pull_request') || t.includes('comment') || t.includes('mail')) {
      isUntrusted = true;
    }
  }

  if (isUntrusted) {
    const contentStr = typeof result === 'string' ? result : safeStringify(result);
    const hash = crypto.createHash('sha256').update(contentStr).digest('hex');
    session.markTainted({
      tool: call.tool || '',
      seq: session.calls,
      hash,
    });
  }

  return session.getTaintState();
}

// Convenience: wrap a stream of actions, returning the per-call verdicts.
export function checkSequence(actions, policy) {
  const s = new TaintSession(policy);
  return (Array.isArray(actions) ? actions : []).map((a) => s.check(a));
}
