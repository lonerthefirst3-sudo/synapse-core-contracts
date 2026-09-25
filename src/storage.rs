//! # Storage
//!
//! All ledger read/write operations are centralised here, keeping handler and
//! service logic free of raw `env.storage()` calls.
//!
//! ## Storage tiers used
//!
//! | Data                  | Tier       | Rationale                                  |
//! |-----------------------|------------|--------------------------------------------|
//! | Admin, relay signer   | `persistent` | Must survive archive/restore cycles      |
//! | Transactions          | `persistent` | Long-lived; needed for audit trail       |
//! | Idempotency keys      | `temporary`  | 24-hour TTL; evicted by the ledger       |
//! | Initialised flag      | `instance`   | Lives with the contract instance         |

use soroban_sdk::{Address, Env, String};

use crate::types::{ContractError, StorageKey, Transaction};

/// TTL extension in ledgers applied to idempotency keys (~24 hours at ~5s/ledger).
///
/// 24 * 3600 / 5 = 17_280 ledgers.  We round up to 18_000 for safety.
const IDEMPOTENCY_TTL_LEDGERS: u32 = 18_000;

/// Minimum TTL we require on transaction records before extending.
const TRANSACTION_MIN_TTL_LEDGERS: u32 = 100_000; // ~1 week

pub struct StorageClient;

impl StorageClient {
    // ── Initialisation flag ───────────────────────────────────────────────────

    /// Returns `true` if [`crate::SynapseCoreContract::initialize`] has been called.
    pub fn is_initialised(env: &Env) -> bool {
        env.storage().instance().has(&StorageKey::Initialised)
    }

    /// Persist the initialised flag.  Called exactly once during `initialize()`.
    pub fn set_initialised(env: &Env) {
        env.storage()
            .instance()
            .set(&StorageKey::Initialised, &true);
    }

    // ── Pause / circuit breaker ───────────────────────────────────────────────

    /// Returns `true` when the emergency-pause flag is engaged.
    ///
    /// Defaults to `false` when the flag has never been written, so a freshly
    /// initialised contract is always unpaused.
    pub fn is_paused(env: &Env) -> bool {
        env.storage()
            .instance()
            .get(&StorageKey::Paused)
            .unwrap_or(false)
    }

    /// Persist the emergency-pause flag.
    pub fn set_paused(env: &Env, paused: bool) {
        env.storage().instance().set(&StorageKey::Paused, &paused);
    }

    // ── Admin ─────────────────────────────────────────────────────────────────

    /// Read the current admin address from persistent storage.
    pub fn get_admin(env: &Env) -> Result<Address, ContractError> {
        env.storage()
            .persistent()
            .get(&StorageKey::Admin)
            .ok_or(if Self::is_admin_vacant(env) {
                ContractError::AdminVacant
            } else {
                ContractError::NotInitialised
            })
    }

    /// Persist an admin address.
    pub fn set_admin(env: &Env, admin: &Address) {
        env.storage().persistent().set(&StorageKey::Admin, admin);
    }

    // ── Relay signer ──────────────────────────────────────────────────────────

    /// Read the trusted relay signer address.
    pub fn get_relay_signer(env: &Env) -> Result<Address, ContractError> {
        env.storage()
            .persistent()
            .get(&StorageKey::RelaySigner)
            .ok_or(ContractError::NotInitialised)
    }

    /// Persist the relay signer address.
    pub fn set_relay_signer(env: &Env, signer: &Address) {
        env.storage()
            .persistent()
            .set(&StorageKey::RelaySigner, signer);
    }

    // ── Admin transfer (two-step) ─────────────────────────────────────────────

    /// Read the pending admin nominee, if a transfer is in progress.
    pub fn get_pending_admin(env: &Env) -> Option<Address> {
        env.storage().persistent().get(&StorageKey::PendingAdmin)
    }

    /// Persist the pending admin nominee, overwriting any existing proposal.
    pub fn set_pending_admin(env: &Env, nominee: &Address) {
        env.storage()
            .persistent()
            .set(&StorageKey::PendingAdmin, nominee);
    }

    /// Clear the pending admin nominee after a transfer is accepted.
    pub fn clear_pending_admin(env: &Env) {
        env.storage().persistent().remove(&StorageKey::PendingAdmin);
    }

    // ── Schema version ────────────────────────────────────────────────────────

    /// Read the on-chain storage schema version.
    pub fn get_schema_version(env: &Env) -> Result<u32, ContractError> {
        env.storage()
            .persistent()
            .get(&StorageKey::SchemaVersion)
            .ok_or(ContractError::NotInitialised)
    }

    /// Persist the storage schema version. Called once during `initialize()`.
    pub fn set_schema_version(env: &Env, version: u32) {
        env.storage()
            .persistent()
            .set(&StorageKey::SchemaVersion, &version);
    }

    // ── Transactions ──────────────────────────────────────────────────────────

    /// Returns `true` if a transaction record already exists for `tx_id`.
    ///
    /// Existence-only check — unlike [`Self::get_transaction`] it does not
    /// extend TTL, since it is used purely as a pre-write guard against
    /// `transaction_id` reuse (see `register_callback`'s duplicate-tx-id
    /// check, THREAT_MODEL.md finding F-07).
    pub fn transaction_exists(env: &Env, tx_id: &String) -> bool {
        env.storage()
            .persistent()
            .has(&StorageKey::Transaction(tx_id.clone()))
    }

    /// Read a [`Transaction`] by its ID.
    ///
    /// Extends the ledger TTL on each access so active records are never evicted.
    pub fn get_transaction(env: &Env, tx_id: &String) -> Result<Transaction, ContractError> {
        let key = StorageKey::Transaction(tx_id.clone());
        let tx = env
            .storage()
            .persistent()
            .get::<StorageKey, Transaction>(&key)
            .ok_or(ContractError::TransactionNotFound)?;
        env.storage().persistent().extend_ttl(
            &key,
            TRANSACTION_MIN_TTL_LEDGERS,
            TRANSACTION_MIN_TTL_LEDGERS,
        );
        Ok(tx)
    }

    /// Persist (insert or update) a [`Transaction`].
    pub fn save_transaction(env: &Env, tx: &Transaction) {
        let key = StorageKey::Transaction(tx.id.clone());
        env.storage().persistent().set(&key, tx);
        env.storage().persistent().extend_ttl(
            &key,
            TRANSACTION_MIN_TTL_LEDGERS,
            TRANSACTION_MIN_TTL_LEDGERS,
        );
    }

    // ── Idempotency keys ──────────────────────────────────────────────────────

    /// Return the ledger sequence at which an idempotency key was first stored,
    /// or `None` if the key is unknown / expired.
    pub fn get_idempotency_key(env: &Env, key: &String) -> Option<u32> {
        env.storage()
            .temporary()
            .get::<StorageKey, u32>(&StorageKey::IdempotencyKey(key.clone()))
    }

    /// Record an idempotency key with a ~24-hour TTL.
    pub fn set_idempotency_key(env: &Env, key: &String) {
        let storage_key = StorageKey::IdempotencyKey(key.clone());
        env.storage()
            .temporary()
            .set(&storage_key, &env.ledger().sequence());
        env.storage().temporary().extend_ttl(
            &storage_key,
            IDEMPOTENCY_TTL_LEDGERS,
            IDEMPOTENCY_TTL_LEDGERS,
        );
    }

    // ── Relay-signer liveness ─────────────────────────────────────────────────

    /// Last heartbeat ledger timestamp recorded for `signer`, if any.
    pub fn get_last_heartbeat(env: &Env, signer: &Address) -> Option<u64> {
        env.storage()
            .persistent()
            .get(&StorageKey::LastHeartbeat(signer.clone()))
    }

    /// Record `ts` as `signer`'s last heartbeat.
    pub fn set_last_heartbeat(env: &Env, signer: &Address, ts: u64) {
        env.storage()
            .persistent()
            .set(&StorageKey::LastHeartbeat(signer.clone()), &ts);
    }

    /// Staleness window in seconds; `0` (default) disables quarantine.
    pub fn get_heartbeat_window(env: &Env) -> u64 {
        env.storage()
            .persistent()
            .get(&StorageKey::HeartbeatWindow)
            .unwrap_or(0)
    }

    /// Persist the staleness window in seconds.
    pub fn set_heartbeat_window(env: &Env, secs: u64) {
        env.storage()
            .persistent()
            .set(&StorageKey::HeartbeatWindow, &secs);
    }

    // ── Role scopes ───────────────────────────────────────────────────────────

    /// Scopes granted to `who` (empty when none).
    pub fn get_scopes(env: &Env, who: &Address) -> soroban_sdk::Vec<crate::types::RoleScope> {
        env.storage()
            .persistent()
            .get(&StorageKey::Scopes(who.clone()))
            .unwrap_or(soroban_sdk::Vec::new(env))
    }

    /// Persist the scope set for `who`.
    pub fn set_scopes(env: &Env, who: &Address, scopes: &soroban_sdk::Vec<crate::types::RoleScope>) {
        env.storage()
            .persistent()
            .set(&StorageKey::Scopes(who.clone()), scopes);
    }

    // ── Guardians ─────────────────────────────────────────────────────────────

    /// Current guardian set (empty when none configured).
    pub fn get_guardians(env: &Env) -> soroban_sdk::Vec<Address> {
        env.storage()
            .persistent()
            .get(&StorageKey::Guardians)
            .unwrap_or(soroban_sdk::Vec::new(env))
    }

    /// Persist the guardian set.
    pub fn set_guardians(env: &Env, guardians: &soroban_sdk::Vec<Address>) {
        env.storage()
            .persistent()
            .set(&StorageKey::Guardians, guardians);
    }

    // ── Emergency admin revocation ────────────────────────────────────────────

    /// Guardian quorum M (0 = unset).
    pub fn get_guardian_threshold(env: &Env) -> u32 {
        env.storage()
            .persistent()
            .get(&StorageKey::GuardianThreshold)
            .unwrap_or(0)
    }

    /// Persist the guardian quorum M.
    pub fn set_guardian_threshold(env: &Env, m: u32) {
        env.storage()
            .persistent()
            .set(&StorageKey::GuardianThreshold, &m);
    }

    /// Whether the admin was revoked via break-glass.
    pub fn is_admin_vacant(env: &Env) -> bool {
        env.storage().persistent().has(&StorageKey::AdminVacant)
    }

    /// Remove the admin and mark the role vacant.
    pub fn vacate_admin(env: &Env) {
        env.storage().persistent().remove(&StorageKey::Admin);
        env.storage().persistent().remove(&StorageKey::PendingAdmin);
        env.storage().persistent().set(&StorageKey::AdminVacant, &true);
    }
}
