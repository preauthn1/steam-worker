// Shared contract between the Worker core (src/*.ts) and the Steam layer (src/steam/**).
// Keep this file small and stable: both halves are built against it in parallel.

export type Scope = 'read' | 'write' | 'admin';

export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

/** Thrown for any expected failure. `code` is snake_case and safe to return to clients. */
export class OpError extends Error {
  constructor(public readonly status: number, public readonly code: string) {
    super(code);
    this.name = 'OpError';
  }
}

/**
 * Persisted per-account Steam state. Encrypted at rest by the core; the Steam layer owns its shape.
 * Never place a password here. Tokens, cookies and Guard secrets live here and nowhere else.
 */
export type AccountState = { [key: string]: Json };

export interface SteamTransportLike {
  /** Number of upstream HTTP requests this operation has issued so far. */
  readonly requestCount: number;
}

export interface OpContext {
  /** Mutable. The core persists it after `run`, including when `run` throws. */
  state: AccountState;
  transport: SteamTransportLike;
  /** The caller's EFFECTIVE privilege, not the operation's nominal scope. */
  scope: Scope;
}

export interface JsonSchema {
  type: 'object';
  additionalProperties: false;
  properties: Record<string, Record<string, Json>>;
  required: string[];
}

export interface OperationSpec {
  name: string;
  scope: Scope;
  mutating: boolean;
  description: string;
  schema: JsonSchema;
  /** `args` has already been validated against `schema`. */
  run(ctx: OpContext, args: Record<string, Json>): Promise<Json>;
}

export interface OperationDescription {
  name: string;
  scope: Scope;
  mutating: boolean;
  description: string;
  schema: JsonSchema;
}
