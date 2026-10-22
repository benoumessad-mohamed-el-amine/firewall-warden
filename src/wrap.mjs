import { check, checkAsync } from './index.mjs';
import { mapMcpToAction } from './mcp.mjs';
import { observeResult } from './taint.mjs';

export class WardenBlocked extends Error {
  constructor(action, verdict, held = false) {
    super(`warden ${held ? 'held for approval' : 'blocked'} ${action.tool} (${verdict.tier}): ${verdict.why.join('; ')}`);
    this.name = 'WardenBlocked';
    this.action = action;
    this.verdict = verdict;
    this.tier = verdict.tier;
    this.heldForApproval = held;
  }
}

/**
 * Wrap a native async executor so every call is firewalled first.
 *
 *   const safeRun = guardExecutor(runShell, {
 *     toAction: (cmd) => ({ tool: 'shell', input: { command: cmd } }),
 *     policy, audit, onApprove,
 *   });
 *   await safeRun('rm -rf /');   // throws WardenBlocked
 *
 * block   -> throws WardenBlocked (or returns onBlock(action, verdict) if given)
 * approve -> onApprove(action, verdict) must resolve truthy, else throws (fail-closed)
 * allow   -> calls execFn(...args)
 */
export function guardExecutor(execFn, { toAction, policy = {}, audit = null, judge = null, onApprove = null, onBlock = null, session = null } = {}) {
  const map = toAction || ((a) => a);
  return async function guarded(...args) {
    const action = map(...args);
    const v = judge ? await checkAsync(action, policy, { audit, judge, session }) : check(action, policy, { audit, session });
    if (v.decision === 'block') { if (onBlock) return onBlock(action, v); throw new WardenBlocked(action, v); }
    if (v.decision === 'approve') {
      const ok = onApprove ? await onApprove(action, v) : false; // fail-closed
      if (!ok) { if (onBlock) return onBlock(action, v); throw new WardenBlocked(action, v, true); }
      if (session && typeof session.resetProvenance === 'function') session.resetProvenance();
    }
    const res = await execFn(...args);
    if (session) observeResult(action, res, session);
    return res;
  };
}

/** Firewall an Anthropic-SDK tool_use block ({ name, input }). Returns the verdict. */
export function guardToolUse(toolUse, policy = {}, opts = {}) {
  const action = mapMcpToAction(toolUse.name, toolUse.input || {}, opts.nameMap || {});
  return check(action, policy, { audit: opts.audit, session: opts.session });
}
