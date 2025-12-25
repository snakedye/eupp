use blake2::{Blake2s256, Digest};
use rand::{TryRngCore, rngs::OsRng};

use ed25519_dalek::{Signer, SigningKey};

use crate::core::transaction::{Input, Output, OutputId, Transaction};

use super::{hash_pubkey, matches_mask, transaction::sighash};

/// Deterministic mining: derive signing keys from a master seed + nonce.
///
/// For nonce in [0, max_attempts), derive seed = Blake2s256(master_seed || nonce_be)
/// and construct an Ed25519 `SigningKey` from `seed` (32 bytes). This allows cheap
/// iteration and easy parallelization (split nonce ranges).
///
/// The function searches for a public key whose Blake2s256(pubkey) satisfies the
/// mask condition stored in the previous minting output's `public_key_hash`.
pub fn build_mining_tx_deterministic(
    prev_block: &crate::core::block::Block,
    miner_pk_hash: [u8; 32],
    max_attempts: u64,
    master_seed: [u8; 32],
) -> Option<Transaction> {
    // Get previous minting tx/out
    let prev_mint_tx = prev_block.transactions.get(0)?;
    let prev_mint_output = prev_mint_tx.outputs.get(0)?;

    // Mask is stored in previous minting output's public_key_hash
    let mask = prev_mint_output.public_key_hash;

    // Initialize hasher
    let mut h = Blake2s256::new();

    // Compute previous txid
    let prev_txid = prev_mint_tx.hash(&mut h)?;

    // Convert mask to array ref
    let mask_arr: [u8; 32] = mask;

    for attempt in 0..max_attempts {
        // Derive seed = Blake2s256(master_seed || nonce_be)
        h.update(&master_seed);
        h.update(&attempt.to_be_bytes());
        let digest = h.finalize_reset();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(digest.as_ref());

        // Build signing key from seed deterministically
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let pk_bytes = verifying_key.to_bytes();

        // Hash pubkey and test mask
        let hpk = hash_pubkey::<Blake2s256>(&pk_bytes);
        if matches_mask(&mask_arr, &hpk) {
            // Build outputs: new mint and miner reward
            let new_mint_output = Output {
                data: prev_mint_output.data,
                public_key_hash: mask,
            };
            let miner_reward_output = Output {
                data: 1u64,
                public_key_hash: miner_pk_hash,
            };
            let outputs = vec![new_mint_output, miner_reward_output];

            // Compute sighash
            let sighash = sighash(
                h,
                &OutputId {
                    transaction_id: prev_txid,
                    output_index: 0,
                },
                outputs.iter(),
            );

            // Sign
            let signature = signing_key.sign(sighash.as_ref());

            // Build input revealing pk and signature
            let input = Input {
                version: 0,
                output_id: OutputId {
                    transaction_id: prev_txid,
                    output_index: 0,
                },
                signature: String::from_utf8_lossy(signature.to_bytes().as_ref()).to_string(),
                public_key: pk_bytes,
            };

            let tx = Transaction {
                version: 0,
                inputs: vec![input],
                outputs,
            };

            return Some(tx);
        }
    }

    None
}

/// Backwards-compatible wrapper: generate a random master seed and call deterministic miner.
pub fn build_mining_tx(
    prev_block: &crate::core::block::Block,
    miner_pk_hash: [u8; 32],
    max_attempts: u64,
) -> Option<Transaction> {
    let mut csprng = OsRng;
    let mut seed_bytes = [0u8; 32];
    csprng.try_fill_bytes(&mut seed_bytes).ok()?;
    build_mining_tx_deterministic(prev_block, miner_pk_hash, max_attempts, seed_bytes)
}
