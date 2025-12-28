use blake2::{Blake2s256, Digest};
use rand::{TryRngCore, rngs::OsRng};

use ed25519_dalek::{Signer, SigningKey};

use crate::core::transaction::{Input, Output, OutputId, Transaction};

use super::{
    calculate_reward,
    ledger::Ledger,
    matches_mask,
    transaction::{TransactionHash, sighash},
};

/// Deterministic mining: derive signing keys from a master seed + nonce.
///
/// For nonce in [0, max_attempts), derive seed = Blake2s256(master_seed || nonce_be)
/// and construct an Ed25519 `SigningKey` from `seed` (32 bytes). This allows cheap
/// iteration and easy parallelization (split nonce ranges).
///
/// The mining condition is checked directly against the raw public key bytes
/// according to the README semantics:
///
///     (mask & pubkey) == 0
///
/// i.e. for every byte, (mask_byte & pubkey_byte) must equal zero.
pub fn build_mining_tx_deterministic(
    prev_tx_hash: &TransactionHash,
    lead_utxo: &Output,
    max_attempts: usize,
    master_seed: [u8; 32],
) -> Option<(SigningKey, Transaction)> {
    // Mask is stored in previous minting output's commitment
    let mask = lead_utxo.commitment;

    // Convert mask to array ref
    let mask_arr: [u8; 32] = mask;

    // If no attempts allowed, return immediately
    if max_attempts == 0 {
        return None;
    }

    for attempt in 0..max_attempts {
        // Derive seed = Blake2s256(master_seed || nonce_be)
        let mut h = Blake2s256::new();
        h.update(&master_seed);
        h.update(&attempt.to_be_bytes());
        let digest = h.finalize();
        let seed = digest.as_slice().try_into().unwrap();

        // Build signing key from seed deterministically
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let pk_bytes = verifying_key.to_bytes();

        // We'll use a nonce as the data hash for outputs (kept zero for now)
        let data_hash = [0u8; 32];

        // Check mask against the raw public key bytes (README semantics)
        if matches_mask(&mask_arr, &pk_bytes) {
            // Calculate block reward
            let reward = calculate_reward(&mask);

            // Build outputs: new mint (carry forward mask) and miner reward
            let new_mint_output = Output {
                version: super::Version::V1,
                amount: lead_utxo.amount.saturating_sub(reward),
                data: data_hash,
                commitment: mask,
            };
            let miner_reward_output = Output::new_v1(reward, &pk_bytes, &data_hash);
            let outputs = vec![new_mint_output, miner_reward_output];

            // Compute sighash
            let sighash = sighash(
                Blake2s256::new(),
                &OutputId {
                    tx_hash: *prev_tx_hash,
                    index: 0,
                },
                outputs.iter().copied(),
            );

            // Sign
            let signature = signing_key.sign(sighash.as_ref());

            // Build input revealing pk and signature
            let input = Input {
                output_id: OutputId {
                    tx_hash: *prev_tx_hash,
                    index: 0,
                },
                signature: signature.to_bytes(),
                public_key: pk_bytes,
            };

            let tx = Transaction {
                inputs: vec![input],
                outputs,
            };

            return Some((signing_key, tx));
        }
    }

    None
}

/// Generate a random master seed and call deterministic miner.
pub fn build_mining_tx(
    prev_tx_hash: &TransactionHash,
    lead_utxo: &Output,
    max_attempts: usize,
) -> Option<(SigningKey, Transaction)> {
    let mut csprng = OsRng;
    let mut seed_bytes = [0u8; 32];
    csprng.try_fill_bytes(&mut seed_bytes).ok()?;
    build_mining_tx_deterministic(prev_tx_hash, lead_utxo, max_attempts, seed_bytes)
}

/// Build the next block by mining a valid mining transaction and assembling the block.
pub fn build_next_block<L: Ledger>(
    ledger: &L,
    prev_tx_hash: &TransactionHash,
    max_attempts: usize,
) -> Option<(SigningKey, crate::core::block::Block)> {
    let lead_utxo = ledger.get_utxo(&OutputId {
        tx_hash: *prev_tx_hash,
        index: 0,
    })?;
    // Attempt to create a mining transaction that spends the prev block's minting UTXO
    let (signing_key, mining_tx) = build_mining_tx(prev_tx_hash, &lead_utxo, max_attempts)?;

    // Create a new block.
    let mut block =
        crate::core::block::Block::new(super::Version::V1, ledger.get_last_block_metadata()?.hash);

    // Include the mining transaction as the first transaction in the block
    block.transactions.push(mining_tx);

    Some((signing_key, block))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{
        create_commitment,
        transaction::{Output, Transaction},
    };
    use blake2::Blake2s256;
    use ed25519_dalek::{Signature, VerifyingKey};
    use std::time::{Duration, Instant};

    #[test]
    fn test_build_mining_tx_deterministic_finds_solution_with_permissive_mask() {
        // With the updated matches_mask semantics, a zero mask permits any candidate
        // because (attempted & mask) == 0 for all attempted when mask == 0.
        let mask = [0x00u8; 32];
        let prev_mint_output = Output {
            version: crate::core::Version::V1,
            amount: 100,
            data: [0u8; 32],
            commitment: mask,
        };
        let funding_tx = Transaction {
            inputs: vec![],
            outputs: vec![prev_mint_output],
        };
        let prev_tx_hash = funding_tx.hash::<Blake2s256>();
        // let mut prev_block = Block::new(crate::core::Version::V1, [0u8; 32]);
        // prev_block.transactions.push(funding_tx);

        // We only need a single attempt because the mask accepts any pubkey.
        let result = build_mining_tx_deterministic(&prev_tx_hash, &prev_mint_output, 1, [0u8; 32]);
        assert!(
            result.is_some(),
            "Expected mining to find a solution with permissive mask"
        );
        let (_signing_key, tx) = result.unwrap();

        // Basic structural checks
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 2);

        // Miner reward commitment should be the commitment of the revealed public key
        let input = &tx.inputs[0];
        let expected_commitment =
            create_commitment::<Blake2s256>(&input.public_key, &tx.outputs[1].data);
        assert_eq!(tx.outputs[1].commitment, expected_commitment);

        // Verify the signature over the sighash using the revealed public key
        let sighash = sighash(
            Blake2s256::new(),
            &input.output_id,
            tx.outputs.iter().copied(),
        );
        let vk = VerifyingKey::from_bytes(&input.public_key).expect("valid vk");
        let sig = Signature::from_slice(&input.signature).expect("valid signature");
        assert!(vk.verify_strict(&sighash, &sig).is_ok());
    }

    #[test]
    fn test_build_mining_tx_deterministic_zero_attempts_returns_none() {
        let mask = [0x00u8; 32];
        let prev_mint_output = Output {
            version: crate::core::Version::V1,
            amount: 100,
            data: [0u8; 32],
            commitment: mask,
        };
        let funding_tx = Transaction {
            inputs: vec![],
            outputs: vec![prev_mint_output],
        };
        let prev_tx_hash = funding_tx.hash::<Blake2s256>();

        // let mut prev_block = Block::new(crate::core::Version::V1, [0u8; 32]);
        // prev_block.transactions.push(funding_tx);

        // max_attempts = 0 should immediately return None
        let tx_opt = build_mining_tx_deterministic(&prev_tx_hash, &prev_mint_output, 0, [0u8; 32]);
        assert!(tx_opt.is_none(), "Expected None when max_attempts is zero");
    }

    #[test]
    fn test_build_mining_tx_difficult_mask_under_5s() {
        // This test uses a mask that enforces zeroes on the first 12 bits of the
        // pubkey (i.e. first byte == 0, high 4 bits of second byte == 0).
        // That yields a difficulty of about 1/4096; it should find a solution
        // within a few thousand attempts, well under 5 seconds on typical CI.
        // Construct a mask that requires the first 12 bits of the candidate to be zero.
        // To require the entire first byte be zero, set mask[0] = 0xFF.
        // To require the high 4 bits of byte 1 be zero, set mask[1] = 0xF0.
        let mut mask = [0x00u8; 32];
        mask[0] = 0xFF;
        mask[1] = 0xF0;
        for i in 2..32 {
            mask[i] = 0x00;
        }

        let prev_mint_output = Output {
            version: crate::core::Version::V1,
            amount: 100,
            data: [0u8; 32],
            commitment: mask,
        };
        let funding_tx = Transaction {
            inputs: vec![],
            outputs: vec![prev_mint_output],
        };
        let prev_tx_hash = funding_tx.hash::<Blake2s256>();
        // let mut prev_block = Block::new(crate::core::Version::V1, [0u8; 32]);
        // prev_block.transactions.push(funding_tx);

        // Allow a generous number of attempts but we expect to find a solution far fewer.
        let max_attempts = 200_000;
        let master_seed = [0u8; 32];

        let start = Instant::now();
        let result = build_mining_tx_deterministic(
            &prev_tx_hash,
            &prev_mint_output,
            max_attempts,
            master_seed,
        );
        let elapsed = start.elapsed();

        assert!(
            result.is_some(),
            "Expected mining to find a solution for the difficult mask within the allotted attempts"
        );

        // Ensure it completed within 5 seconds
        assert!(
            elapsed < Duration::from_secs(5),
            "Mining took too long: {:?} (expected < 5s)",
            elapsed
        );

        // Sanity check the found transaction
        let (_signing_key, tx) = result.unwrap();
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 2);

        // Miner reward commitment should match revealed public key
        let input = &tx.inputs[0];
        let expected_commitment =
            create_commitment::<Blake2s256>(&input.public_key, &tx.outputs[1].data);
        assert_eq!(tx.outputs[1].commitment, expected_commitment);

        // Verify the signature over the sighash using the revealed public key
        let sighash = sighash(
            Blake2s256::new(),
            &input.output_id,
            tx.outputs.iter().copied(),
        );
        let vk = VerifyingKey::from_bytes(&input.public_key).expect("valid vk");
        let sig = Signature::from_slice(&input.signature).expect("valid signature");
        assert!(vk.verify_strict(&sighash, &sig).is_ok());
    }
}
