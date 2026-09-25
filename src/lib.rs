#![no_std]

//! # Synapse Core — On-Chain Contract
//!
//! Phase 1 of the Synapse Bridge ecosystem.
//!
//! This contract mirrors the off-chain `synapse-core` Rust service, providing an
//! **on-chain transaction registry** that:
//!
//! 1. Accepts callback registrations from the Stellar Anchor Platform (via the
//!    off-chain relay), storing each deposit event with status `Pending`.
//! 2. Guards against duplicate delivery with an idempotency key ledger.
//! 3. Drives the transaction through its lifecycle:
//!    `Pending → Processing → Completed | Failed`
//! 4. Emits structured events at every state transition so Phase 2 (Swap Engine)
//!    and Phase 3 (Cross-Chain Bridge) can subscribe and act.
//!
//! ## Module layout
//!
//! ```text
//! lib.rs          ← you are here (contract entry-point)
//! types.rs        ← Transaction, TransactionStatus, CallbackPayload, errors
//! storage.rs      ← all ledger read/write helpers
//! events.rs       ← typed event emission
//! validation.rs   ← input guards (account format, asset code, amount bounds)
//! admin.rs        ← admin / owner management
//! ```

mod admin;
mod events;
mod storage;
mod types;
mod validation;

#[cfg(test)]
mod test_pause;
#[cfg(test)]
mod tests;

use soroban_sdk::{contract, contractimpl, Address, BytesN, Env, String};

use crate::admin::AdminClient;
use crate::events::EventEmitter;
use crate::storage::StorageClient;
use crate::types::{
    CallbackPayload, ContractError, RoleScope, Transaction, TransactionStatus, SCHEMA_VERSION,
};
use crate::validation::Validator;

// ─── Public contract interface ───────────────────────────────────────────────

#[contract]
pub struct SynapseCoreContract;

#[contractimpl]
impl SynapseCoreContract {
    // ── Initialisation ────────────────────────────────────────────────────────

    /// Initialise the contract; can only be called once.
    ///
    /// * `admin`        — Address that may call privileged methods.
    /// * `relay_signer` — Address of the trusted off-chain relay that forwards
    ///                    Anchor Platform callbacks on-chain.
    pub fn initialize(
        env: Env,
        admin: Address,
        relay_signer: Address,
    ) -> Result<(), ContractError> {
        if StorageClient::is_initialised(&env) {
            return Err(ContractError::AlreadyInitialised);
        }
        StorageClient::set_admin(&env, &admin);
        StorageClient::set_relay_signer(&env, &relay_signer);
        // Start unpaused so a freshly deployed contract accepts callbacks.
        StorageClient::set_paused(&env, false);
        StorageClient::set_schema_version(&env, SCHEMA_VERSION);
        StorageClient::set_initialised(&env);
        EventEmitter::initialised(&env, &admin, &relay_signer);
        Ok(())
    }

    // ── Callback ingestion (Phase 1 core) ─────────────────────────────────────

    /// Register a new anchor callback, persisting a [`Transaction`] with status
    /// [`TransactionStatus::Pending`].
    ///
    /// Called by the trusted `relay_signer` after the off-chain `synapse-core`
    /// service validates and deduplicates the raw Anchor Platform webhook.
    ///
    /// # Idempotency
    /// If `payload.idempotency_key` has been seen before within the retention
    /// window the call returns `Ok(existing_tx_id)` without writing — matching
    /// the Redis idempotency behaviour of the off-chain service.
    ///
    /// The idempotency key alone is not a durable enough guard: it lives in
    /// *temporary* storage with a ~24h TTL, so a late replay with a fresh
    /// `idempotency_key` but the same `transaction_id` would otherwise pass
    /// the check above and reach the write below. To prevent that write from
    /// silently overwriting an existing (possibly `Completed`/`Failed`)
    /// record, `transaction_id` reuse is also rejected independently of
    /// idempotency-key state (THREAT_MODEL.md finding F-07).
    ///
    /// # Events
    /// Emits [`events::TransactionRegistered`] on first write.
    pub fn register_callback(env: Env, payload: CallbackPayload) -> Result<String, ContractError> {
        // Circuit breaker: while the emergency pause is engaged we fail closed
        // and reject all new callback ingestion outright. This check is first so
        // ingestion is blocked regardless of caller. Read-only queries and
        // draining of already-registered work are intentionally left unguarded
        // (see the module docs on `pause`).
        if StorageClient::is_paused(&env) {
            return Err(ContractError::ContractPaused);
        }

        // Only the trusted relay signer may forward Anchor Platform callbacks.
        let relay = StorageClient::get_relay_signer(&env)?;
        relay.require_auth();

        // Quarantine: a signer with a stale heartbeat cannot take new intake.
        // Existing Pending/Processing work stays processable.
        AdminClient::assert_not_quarantined(&env, &relay)?;

        Validator::validate_payload(&env, &payload)?;

        // Idempotency: a replayed key returns the original tx id without a
        // second write, mirroring the off-chain Redis idempotency behaviour.
        if StorageClient::get_idempotency_key(&env, &payload.idempotency_key).is_some() {
            return Ok(payload.transaction_id.clone());
        }

        // Second-line guard (F-07): the idempotency key's TTL is much shorter
        // than a transaction record's, so a late replay past that window must
        // still not be allowed to overwrite an existing record under the same
        // transaction_id.
        if StorageClient::transaction_exists(&env, &payload.transaction_id) {
            return Err(ContractError::DuplicateRequest);
        }

        let ledger = env.ledger().sequence();
        let tx = Transaction {
            id: payload.transaction_id.clone(),
            stellar_account: payload.stellar_account.clone(),
            amount: payload.amount,
            asset_code: payload.asset_code.clone(),
            asset_issuer: payload.asset_issuer.clone(),
            status: TransactionStatus::Pending,
            created_at_ledger: ledger,
            updated_at_ledger: ledger,
            anchor_transaction_id: payload.anchor_transaction_id.clone(),
            callback_type: payload.callback_type.clone(),
            callback_status: payload.callback_status.clone(),
            stellar_tx_hash: String::from_str(&env, ""),
            failure_reason: String::from_str(&env, ""),
        };

        StorageClient::save_transaction(&env, &tx);
        StorageClient::set_idempotency_key(&env, &payload.idempotency_key);
        EventEmitter::transaction_registered(&env, &tx);

        Ok(tx.id)
    }

    // ── Status transitions ────────────────────────────────────────────────────

    /// Mark a `Pending` transaction as `Processing`.
    ///
    /// Called by the relay when the off-chain processor picks up the job.
    /// Enforces the state machine: only `Pending → Processing` is valid here.
    pub fn start_processing(env: Env, tx_id: String, caller: Address) -> Result<(), ContractError> {
        AdminClient::require_scope(&env, &caller, RoleScope::StartProcessing)?;

        let mut tx = StorageClient::get_transaction(&env, &tx_id)?;
        if tx.status != TransactionStatus::Pending {
            return Err(ContractError::InvalidStatusTransition);
        }
        let old_status = tx.status.clone();
        tx.status = TransactionStatus::Processing;
        tx.updated_at_ledger = env.ledger().sequence();

        StorageClient::save_transaction(&env, &tx);
        EventEmitter::status_changed(&env, &tx_id, old_status, TransactionStatus::Processing);

        Ok(())
    }

    /// Mark a `Processing` transaction as `Completed` after on-chain verification.
    ///
    /// `stellar_tx_hash` — the Stellar transaction hash confirming the deposit
    ///                     was settled on Horizon. Stored for auditability.
    pub fn complete_transaction(
        env: Env,
        tx_id: String,
        stellar_tx_hash: String,
        caller: Address,
    ) -> Result<(), ContractError> {
        AdminClient::require_scope(&env, &caller, RoleScope::CompleteTransaction)?;
        Validator::validate_stellar_tx_hash(&stellar_tx_hash)?;

        let mut tx = StorageClient::get_transaction(&env, &tx_id)?;
        if tx.status != TransactionStatus::Processing {
            return Err(ContractError::InvalidStatusTransition);
        }
        let old_status = tx.status.clone();
        tx.status = TransactionStatus::Completed;
        tx.stellar_tx_hash = stellar_tx_hash.clone();
        tx.updated_at_ledger = env.ledger().sequence();

        StorageClient::save_transaction(&env, &tx);
        EventEmitter::status_changed(&env, &tx_id, old_status, TransactionStatus::Completed);
        EventEmitter::transaction_completed(&env, &tx_id, &stellar_tx_hash);

        Ok(())
    }

    /// Mark a `Pending` or `Processing` transaction as `Failed`.
    ///
    /// `reason` — short human-readable failure code (e.g. "horizon_timeout",
    ///            "invalid_account", "circuit_open").
    pub fn fail_transaction(
        env: Env,
        tx_id: String,
        reason: String,
        caller: Address,
    ) -> Result<(), ContractError> {
        AdminClient::require_scope(&env, &caller, RoleScope::FailTransaction)?;
        Validator::validate_failure_reason(&reason)?;

        let mut tx = StorageClient::get_transaction(&env, &tx_id)?;
        if tx.status != TransactionStatus::Pending && tx.status != TransactionStatus::Processing {
            return Err(ContractError::InvalidStatusTransition);
        }
        let old_status = tx.status.clone();
        tx.status = TransactionStatus::Failed;
        tx.failure_reason = reason.clone();
        tx.updated_at_ledger = env.ledger().sequence();

        StorageClient::save_transaction(&env, &tx);
        EventEmitter::status_changed(&env, &tx_id, old_status, TransactionStatus::Failed);
        EventEmitter::transaction_failed(&env, &tx_id, &reason);

        Ok(())
    }

    // ── Read-only queries ─────────────────────────────────────────────────────

    /// Return the [`Transaction`] for the given `tx_id`, or
    /// [`ContractError::TransactionNotFound`].
    pub fn get_transaction(env: Env, tx_id: String) -> Result<Transaction, ContractError> {
        // Read-only: intentionally NOT gated by the pause flag — pausing must
        // never brick reads.
        StorageClient::get_transaction(&env, &tx_id)
    }

    /// Return the current [`TransactionStatus`] without fetching the full record.
    pub fn get_status(env: Env, tx_id: String) -> Result<TransactionStatus, ContractError> {
        StorageClient::get_transaction(&env, &tx_id).map(|tx| tx.status)
    }

    /// Check whether an idempotency key has already been processed.
    pub fn is_duplicate(env: Env, idempotency_key: String) -> bool {
        StorageClient::get_idempotency_key(&env, &idempotency_key).is_some()
    }

    /// Return the current admin address, or [`ContractError::NotInitialised`].
    ///
    /// Read-only: lets off-chain monitoring and deployment tooling verify the
    /// on-chain admin against the value recorded in `contract-ids.json`
    /// without needing to trust that record alone.
    pub fn admin(env: Env) -> Result<Address, ContractError> {
        StorageClient::get_admin(&env)
    }

    /// Return the current trusted relay signer address, or
    /// [`ContractError::NotInitialised`].
    pub fn relay_signer(env: Env) -> Result<Address, ContractError> {
        StorageClient::get_relay_signer(&env)
    }

    /// Return the current on-chain storage schema version, or
    /// [`ContractError::NotInitialised`]. The value `upgrade()` requires
    /// callers to pass as `expected_schema_version`.
    pub fn schema_version(env: Env) -> Result<u32, ContractError> {
        StorageClient::get_schema_version(&env)
    }

    /// Return the pending admin nominee, if an admin transfer is in
    /// progress. `None` once accepted or if none was ever proposed.
    pub fn pending_admin(env: Env) -> Option<Address> {
        StorageClient::get_pending_admin(&env)
    }

    // ── Admin (two-step transfer) ────────────────────────────────────────────

    /// Nominate `new_admin` as the next admin.  Requires existing admin auth.
    ///
    /// The transfer does not take effect here — it only completes once
    /// `new_admin` itself calls [`Self::accept_admin`], proving it controls
    /// the corresponding key. A single call from the current admin can no
    /// longer finalise a transfer on its own (THREAT_MODEL.md finding F-03),
    /// which also rules out the classic mis-typed-address failure mode: a
    /// wrong address can never accept, so the current admin simply stays in
    /// control and can propose again.
    ///
    /// Rejects nominating the contract's own address (F-02) — see
    /// [`Validator::validate_admin_nominee`] for why that is the only
    /// "invalid address" Soroban lets this check for on-chain.
    ///
    /// # Events
    /// Emits [`events::EventAdminTransferProposed`].
    pub fn propose_admin(env: Env, new_admin: Address) -> Result<(), ContractError> {
        let current_admin = AdminClient::require_admin(&env)?;
        Validator::validate_admin_nominee(&env, &new_admin)?;
        StorageClient::set_pending_admin(&env, &new_admin);
        EventEmitter::admin_transfer_proposed(&env, &current_admin, &new_admin);
        Ok(())
    }

    /// Complete a pending admin transfer nominated via [`Self::propose_admin`].
    ///
    /// `caller` must be the pending nominee; the call requires `caller`'s own
    /// auth, which is what proves key control and finalises the transfer.
    ///
    /// # Errors
    /// - [`ContractError::NoPendingAdminTransfer`] if no transfer is pending.
    /// - [`ContractError::Unauthorised`] if `caller` is not the pending nominee.
    ///
    /// # Events
    /// Emits [`events::EventAdminTransferred`].
    pub fn accept_admin(env: Env, caller: Address) -> Result<(), ContractError> {
        let pending =
            StorageClient::get_pending_admin(&env).ok_or(ContractError::NoPendingAdminTransfer)?;
        if caller != pending {
            return Err(ContractError::Unauthorised);
        }
        caller.require_auth();

        let old_admin = StorageClient::get_admin(&env)?;
        StorageClient::set_admin(&env, &caller);
        StorageClient::clear_pending_admin(&env);
        EventEmitter::admin_transferred(&env, &old_admin, &caller);
        Ok(())
    }

    /// Rotate the trusted relay signer address.
    ///
    /// # Events
    /// Emits [`events::EventRelaySignerRotated`] so off-chain monitoring can
    /// observe the rotation the same way it does [`Self::accept_admin`].
    pub fn set_relay_signer(env: Env, new_signer: Address) -> Result<(), ContractError> {
        AdminClient::require_admin(&env)?;
        let old_signer = StorageClient::get_relay_signer(&env)?;
        StorageClient::set_relay_signer(&env, &new_signer);
        EventEmitter::relay_signer_rotated(&env, &old_signer, &new_signer);
        Ok(())
    }

    // ── Relay-signer liveness ─────────────────────────────────────────────────

    /// Record a liveness heartbeat for the relay signer `caller`.
    ///
    /// Only the registered relay signer may call this.
    ///
    /// # Events
    /// Emits [`events::EventHeartbeat`].
    pub fn heartbeat(env: Env, caller: Address) -> Result<(), ContractError> {
        AdminClient::require_relay_signer(&env, &caller)?;
        StorageClient::set_last_heartbeat(&env, &caller, env.ledger().timestamp());
        EventEmitter::heartbeat(&env, &caller);
        Ok(())
    }

    /// Set the heartbeat staleness window in seconds (`0` disables
    /// quarantine). Admin-gated.
    pub fn set_heartbeat_window(env: Env, secs: u64) -> Result<(), ContractError> {
        AdminClient::require_admin(&env)?;
        StorageClient::set_heartbeat_window(&env, secs);
        Ok(())
    }

    /// Manually lift a quarantine by resetting `signer`'s heartbeat to now.
    /// Admin-gated.
    ///
    /// # Events
    /// Emits [`events::EventQuarantineCleared`].
    pub fn clear_quarantine(env: Env, signer: Address) -> Result<(), ContractError> {
        let admin = AdminClient::require_admin(&env)?;
        StorageClient::set_last_heartbeat(&env, &signer, env.ledger().timestamp());
        EventEmitter::quarantine_cleared(&env, &signer, &admin);
        Ok(())
    }

    /// Return whether `signer` is currently quarantined.
    pub fn is_quarantined(env: Env, signer: Address) -> bool {
        AdminClient::assert_not_quarantined(&env, &signer).is_err()
    }

    // ── Role scopes ─────────────────────────────────────────────────────────────

    /// Grant `scope` to `who` (idempotent). Admin-gated.
    pub fn grant_scope(env: Env, who: Address, scope: RoleScope) -> Result<(), ContractError> {
        AdminClient::require_admin(&env)?;
        let mut scopes = StorageClient::get_scopes(&env, &who);
        if !scopes.contains(scope) {
            scopes.push_back(scope);
            StorageClient::set_scopes(&env, &who, &scopes);
        }
        Ok(())
    }

    /// Revoke `scope` from `who` (idempotent). Admin-gated.
    pub fn revoke_scope(env: Env, who: Address, scope: RoleScope) -> Result<(), ContractError> {
        AdminClient::require_admin(&env)?;
        let mut scopes = StorageClient::get_scopes(&env, &who);
        if let Some(i) = scopes.first_index_of(scope) {
            scopes.remove(i);
            StorageClient::set_scopes(&env, &who, &scopes);
        }
        Ok(())
    }

    /// Return whether `who` has been explicitly granted `scope`.
    pub fn has_scope(env: Env, who: Address, scope: RoleScope) -> bool {
        StorageClient::get_scopes(&env, &who).contains(scope)
    }

    // ── Contract upgrade ───────────────────────────────────────────────────────

    /// Replace the contract WASM in-place.
    ///
    /// Only the current admin may call this.  The new WASM **must** be compatible
    /// with the existing storage schema (`StorageKey` variants, `Transaction`
    /// struct layout).  Persistent storage (admin, relay_signer, transactions)
    /// and instance storage (init flag, pause flag) survive intact; temporary
    /// storage (idempotency keys) is evicted.
    ///
    /// `expected_schema_version` must match the on-chain `SchemaVersion`
    /// (THREAT_MODEL.md finding F-04). This cannot validate that the *new*
    /// WASM is actually compatible — Soroban gives the running code no way to
    /// introspect an uploaded-but-not-yet-installed WASM blob — but it does
    /// guard against invoking `upgrade()` against a contract instance whose
    /// on-chain state isn't what the caller believes it is.
    ///
    /// # Events
    /// Emits [`events::EventContractUpgraded`] on success.
    ///
    /// # Trust
    /// Because this entry point allows the admin to deploy arbitrary WASM, the
    /// admin key **MUST** be held by a multisig or DAO.  See `DECISIONS.md` for
    /// the full rationale and `README.md` for operational requirements.
    pub fn upgrade(
        env: Env,
        new_wasm_hash: BytesN<32>,
        expected_schema_version: u32,
    ) -> Result<(), ContractError> {
        let admin = AdminClient::require_admin(&env)?;
        let schema_version = StorageClient::get_schema_version(&env)?;
        if schema_version != expected_schema_version {
            return Err(ContractError::SchemaVersionMismatch);
        }
        env.deployer()
            .update_current_contract_wasm(new_wasm_hash.clone());
        EventEmitter::contract_upgraded(&env, &admin, &new_wasm_hash, schema_version);
        Ok(())
    }

    // ── Emergency pause / circuit breaker ──────────────────────────────────────

    /// Engage the emergency circuit breaker.  Admin-gated.
    ///
    /// While paused, [`Self::register_callback`] rejects all new ingestion with
    /// [`ContractError::ContractPaused`]. Status transitions
    /// (`start_processing` / `complete_transaction` / `fail_transaction`) are
    /// **deliberately left running** so already-registered work can drain during
    /// an incident, and all read-only queries stay available. Idempotent: pausing
    /// an already-paused contract is a no-op success.
    pub fn pause(env: Env) -> Result<(), ContractError> {
        let admin = AdminClient::require_admin(&env)?;
        StorageClient::set_paused(&env, true);
        EventEmitter::pause_toggled(&env, true, &admin);
        Ok(())
    }

    /// Set the guardian set. Admin-gated; simple (non-timelocked) rotation,
    /// flagged as a fast-follow. Replaces any previous set.
    pub fn set_guardians(env: Env, guardians: soroban_sdk::Vec<Address>) -> Result<(), ContractError> {
        AdminClient::require_admin(&env)?;
        StorageClient::set_guardians(&env, &guardians);
        Ok(())
    }

    /// Set the guardian quorum M for [`Self::revoke_admin_emergency`].
    /// Admin-gated; must satisfy `1 <= m <= guardians.len()`.
    pub fn set_guardian_threshold(env: Env, m: u32) -> Result<(), ContractError> {
        AdminClient::require_admin(&env)?;
        if m == 0 || m > StorageClient::get_guardians(&env).len() {
            return Err(ContractError::QuorumNotMet);
        }
        StorageClient::set_guardian_threshold(&env, m);
        Ok(())
    }

    /// Break-glass: revoke the admin entirely with an M-of-N guardian quorum.
    ///
    /// `approvers` must contain at least M distinct guardians, each of which
    /// must authorise the call; one short of M is rejected. On success the
    /// contract is paused and enters the documented "admin vacant" state: every
    /// admin-gated entry point fails with [`ContractError::AdminVacant`], while
    /// `guardian_pause`, reads and (via the stored relay signer) nothing that
    /// needs admin remain. Bootstrapping a new admin is a tracked follow-up
    /// (see `docs/adr/0004-guardian-emergency-admin-revocation.md`).
    ///
    /// # Events
    /// Emits [`events::EventAdminRevokedEmergency`].
    pub fn revoke_admin_emergency(
        env: Env,
        approvers: soroban_sdk::Vec<Address>,
    ) -> Result<(), ContractError> {
        let threshold = StorageClient::get_guardian_threshold(&env);
        if threshold == 0 {
            return Err(ContractError::QuorumNotMet);
        }
        let guardians = StorageClient::get_guardians(&env);
        let mut seen: soroban_sdk::Vec<Address> = soroban_sdk::Vec::new(&env);
        for a in approvers.iter() {
            if !guardians.contains(&a) {
                return Err(ContractError::NotGuardian);
            }
            if !seen.contains(&a) {
                a.require_auth();
                seen.push_back(a);
            }
        }
        if seen.len() < threshold {
            return Err(ContractError::QuorumNotMet);
        }
        let admin = StorageClient::get_admin(&env)?;
        StorageClient::vacate_admin(&env);
        StorageClient::set_paused(&env, true);
        EventEmitter::admin_revoked_emergency(&env, &admin, seen.len());
        Ok(())
    }

    /// Return the configured guardian set.
    pub fn guardians(env: Env) -> soroban_sdk::Vec<Address> {
        StorageClient::get_guardians(&env)
    }

    /// Engage the circuit breaker on guardian authority alone, without admin
    /// rights, so an incident responder can halt the contract when the admin
    /// key is suspected compromised. Idempotent.
    ///
    /// Design choice: **unpause remains admin-only**. A guardian that is also
    /// the admin is harmless: it simply passes either check.
    ///
    /// # Events
    /// Emits [`events::EventGuardianPaused`] (not `EventPauseToggled`).
    pub fn guardian_pause(env: Env, caller: Address) -> Result<(), ContractError> {
        if !StorageClient::get_guardians(&env).contains(&caller) {
            return Err(ContractError::NotGuardian);
        }
        caller.require_auth();
        StorageClient::set_paused(&env, true);
        EventEmitter::guardian_paused(&env, &caller);
        Ok(())
    }

    /// Release the emergency circuit breaker, resuming normal callback
    /// ingestion.  Admin-gated. Idempotent.
    pub fn unpause(env: Env) -> Result<(), ContractError> {
        let admin = AdminClient::require_admin(&env)?;
        StorageClient::set_paused(&env, false);
        EventEmitter::pause_toggled(&env, false, &admin);
        Ok(())
    }

    /// Return whether the emergency pause is currently engaged.
    pub fn is_paused(env: Env) -> bool {
        StorageClient::is_paused(&env)
    }

    /// Liveness probe — returns `true` when the contract is initialised.
    pub fn health(env: Env) -> bool {
        StorageClient::is_initialised(&env)
    }

    /// Return the contract version string (semver).
    pub fn version(env: Env) -> String {
        // NOTE: `&'static str` is not a Soroban-representable return type, so the
        // package version is returned as a host `String`.
        String::from_str(&env, env!("CARGO_PKG_VERSION"))
    }
}
