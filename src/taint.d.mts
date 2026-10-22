import type { Action, Policy, Verdict, ProvenanceTaint } from './types.mjs';

export interface TaintState {
  calls: number;
  holdsSecret: boolean;
  taintedPaths: string[];
  tainted: boolean;
  sources: Array<{ tool: string; seq: number; hash: string }>;
}

export declare function isOutboundWrite(action: Action): boolean;
export declare function isSecretRead(action: Action): boolean;
export declare function isShell(action: Action): boolean;

/** Stateful checker that catches secrets staged across calls and tracks context provenance taint. */
export declare class TaintSession {
  constructor(policy?: Policy);
  policy: Policy | undefined;
  calls: number;
  holdsSecret: boolean;
  taintedPaths: Set<string>;
  tainted: boolean;
  sources: Array<{ tool: string; seq: number; hash: string }>;
  isTainted(): boolean;
  getTaintState(): ProvenanceTaint;
  markTainted(source: { tool: string; seq: number; hash: string }): void;
  clearProvenanceTaint(): void;
  resetProvenance(): void;
  applyTaintedPolicy(action: Action, v: Verdict): Verdict;
  /** Check one call in the context of the session so far. Never throws, never lowers a verdict. */
  check(action: Action, skillText?: string): Verdict;
  state(): TaintState;
  /** Clear session state, e.g. at the start of a new agent task. */
  reset(): void;
}

/** Observe a tool result in an agent session, marking the session tainted if from an untrusted source. */
export declare function observeResult(call: Action, result: unknown, session: TaintSession): ProvenanceTaint | null;

/** Check a sequence of actions through one fresh TaintSession. */
export declare function checkSequence(actions: Action[], policy?: Policy): Verdict[];
