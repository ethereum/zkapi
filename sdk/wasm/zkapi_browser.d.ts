/* tslint:disable */
/* eslint-disable */

/**
 * The note tree rebuilt from vault logs (§6.6): `apply` one event, in log
 * order, and compare the returned root with the event's.
 */
export class BrowserNoteTree {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Apply one `TreeEvent` (JSON) and return the new root (JSON felt).
     */
    apply(event_json: string): string;
    constructor();
    next_note_id(): number;
    path(note_id: number): string;
    root(): string;
}

export class BrowserRequestProver {
    free(): void;
    [Symbol.dispose](): void;
    constructor(proving_key: Uint8Array);
    prepare_request(config_json: string, state_json: string, args_json: string): string;
}

/**
 * S1, S2, S4 and S6 of a response whose journal is lost; returns
 * `{charge_applied, next_anchor}` (JSON).
 */
export function browser_check_unrecoverable_response(config_json: string, state_json: string, response_json: string): string;

export function browser_circuit_id(): string;

export function browser_complete_response(config_json: string, args_json: string): string;

export function browser_confirm_deposit(config_json: string, args_json: string): string;

export function browser_generate_deposit(): string;

/**
 * Whether `{active_root, siblings}` (JSON) is a path of the state's note.
 */
export function browser_note_path_matches(state_json: string, path_json: string): boolean;

export function browser_prepare_request(config_json: string, state_json: string, args_json: string, proving_key: Uint8Array): string;

export function browser_prepare_withdrawal(config_json: string, state_json: string, args_json: string, proving_key: Uint8Array): string;

/**
 * The setup this bundle loads keys of: "dev" or "mpc-1".
 */
export function browser_setup_id(): string;

export function browser_successor_nullifier(state_json: string): string;

export function browser_tree_path(snapshot_json: string, note_id: number, require_existing: boolean): string;

export function browser_tree_path_from_leaves(leaves_json: string, note_id: number): string;

/**
 * `true` iff the proof verifies for the statement under the request
 * verifying key file `verifying_key`; an error for malformed input.
 */
export function browser_verify_request(public_json: string, proof_base64: string, verifying_key: Uint8Array): boolean;

export function browser_wallet_status(state_json?: string | null, journal_json?: string | null): string;

export function browser_withdrawal_nullifier(state_json: string): string;

export function start(): void;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_browsernotetree_free: (a: number, b: number) => void;
    readonly __wbg_browserrequestprover_free: (a: number, b: number) => void;
    readonly browser_check_unrecoverable_response: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly browser_circuit_id: () => [number, number];
    readonly browser_complete_response: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly browser_confirm_deposit: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly browser_generate_deposit: () => [number, number, number, number];
    readonly browser_note_path_matches: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly browser_prepare_request: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number, number];
    readonly browser_prepare_withdrawal: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number, number];
    readonly browser_setup_id: () => [number, number];
    readonly browser_successor_nullifier: (a: number, b: number) => [number, number, number, number];
    readonly browser_tree_path: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly browser_tree_path_from_leaves: (a: number, b: number, c: number) => [number, number, number, number];
    readonly browser_verify_request: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly browser_wallet_status: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly browser_withdrawal_nullifier: (a: number, b: number) => [number, number, number, number];
    readonly browsernotetree_apply: (a: number, b: number, c: number) => [number, number, number, number];
    readonly browsernotetree_new: () => number;
    readonly browsernotetree_next_note_id: (a: number) => number;
    readonly browsernotetree_path: (a: number, b: number) => [number, number, number, number];
    readonly browsernotetree_root: (a: number) => [number, number, number, number];
    readonly browserrequestprover_new: (a: number, b: number) => [number, number, number];
    readonly browserrequestprover_prepare_request: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number, number];
    readonly start: () => void;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
