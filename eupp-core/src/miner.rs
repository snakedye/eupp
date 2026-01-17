/*! Mining logic for minting new coins and building blocks.

This module provides functions for mining new transactions and assembling blocks
in a proof-of-work style system. It includes:
- Mining solution computation based on a previous block hash, public key, and nonce.
- Mining transaction construction that spends the previous minting output and rewards the miner.
- Block assembly by including a valid mining transaction.
- Utilities for mask-based mining difficulty and reward calculation.

The mining process attempts to find a nonce such that the hash of the previous block,
the miner's public key, and the nonce matches a difficulty mask. Upon success, a new
minting output and a miner reward output are created and included in a new block.
*/

use blake2::{Blake2s256, Digest};

use ed25519_dalek::{Signer, SigningKey};

use crate::{
    PublicKey,
    transaction::{Input, Output, OutputId, Transaction},
};

use super::{
    Hash, calculate_reward,
    ledger::Indexer,
    matches_mask,
    transaction::{TransactionHash, sighash},
};

/// Computes the mining solution for a given public key, previous block hash, and nonce.
pub fn mining_solution(prev_block_hash: &Hash, pubkey: &PublicKey, nonce: &[u8]) -> Hash {
    let mut h = Blake2s256::new();
    h.update(prev_block_hash);
    h.update(pubkey);
    h.update(nonce);
    h.finalize().into()
}

/// Mines a new transaction to a specified public key.
pub fn build_mining_tx<R>(
    secret_key: &[u8; 32],
    prev_block_hash: &Hash,
    prev_tx_hash: &TransactionHash,
    lead_utxo: &Output,
    range: R,
) -> Option<(SigningKey, Transaction)>
where
    R: IntoIterator<Item = usize>,
{
    // Mask is stored in previous minting output's data
    let mask = lead_utxo.data;

    let signing_key = SigningKey::from_bytes(secret_key);
    let verifying_key = signing_key.verifying_key();
    let pk_bytes = verifying_key.to_bytes();

    for attempt in range {
        let mut nonce = [0u8; 32];
        nonce[..8].copy_from_slice(&attempt.to_be_bytes());
        let solution = mining_solution(prev_block_hash, &pk_bytes, &nonce);

        // Check mask against the raw public key bytes (README semantics)
        if matches_mask(&mask, &solution) {
            let lead_utxo_id = OutputId {
                tx_hash: *prev_tx_hash,
                index: 0,
            };
            // Calculate block reward
            let reward = calculate_reward(&mask);
            let new_supply = lead_utxo.amount.saturating_sub(reward);

            // Build outputs: new mint (carry forward mask) and miner reward
            let new_mint_output = Output::new_v0(new_supply, &mask, &nonce);
            let miner_reward_output = Output::new_v1(reward.min(new_supply), &pk_bytes, &[0; 32]);
            let outputs = vec![new_mint_output, miner_reward_output];

            // Compute sighash
            let sighash = sighash(&[lead_utxo_id], &outputs);

            // Sign
            let signature = signing_key.sign(sighash.as_ref());

            // Build input revealing pk and signature
            let input = Input::new(lead_utxo_id, pk_bytes, signature.to_bytes());

            let tx = Transaction {
                inputs: vec![input],
                outputs,
            };

            return Some((signing_key, tx));
        }
    }

    None
}

/// Build the next block by mining a valid mining transaction and assembling the block.
pub fn build_next_block<L: Indexer>(
    secret_key: &[u8; 32],
    indexer: &L,
    max_attempts: usize,
) -> Option<(SigningKey, crate::block::Block)> {
    let prev_block = indexer.get_last_block_metadata()?;
    let prev_block_hash = prev_block.hash;
    let lead_utxo_id = prev_block.lead_utxo;
    let lead_utxo = indexer.get_utxo(&lead_utxo_id)?;

    // Attempt to create a mining transaction that spends the prev block's minting UTXO
    let (signing_key, mining_tx) = build_mining_tx(
        secret_key,
        &prev_block_hash,
        &lead_utxo_id.tx_hash,
        &lead_utxo,
        0..max_attempts,
    )?;

    // Create a new block.
    let mut block = crate::block::Block::new(0, indexer.get_last_block_metadata()?.hash);

    // Include the mining transaction as the first transaction in the block
    block.transactions.push(mining_tx);

    Some((signing_key, block))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{Output, Transaction, Version};
    use ed25519_dalek::{Signature, VerifyingKey};
    use std::time::{Duration, Instant};

    #[test]
    fn test_build_mining_tx_deterministic_finds_solution_with_permissive_mask() {
        // With the updated matches_mask semantics, a zero mask permits any candidate
        // because (attempted & mask) == 0 for all attempted when mask == 0.
        let mask = [0; 32];
        let prev_mint_output = Output::new_v0(100, &mask, &[0; 32]);
        let funding_tx = Transaction {
            inputs: vec![],
            outputs: vec![prev_mint_output],
        };
        let prev_tx_hash = funding_tx.hash();
        let prev_block_hash = [0u8; 32];

        // We only need a single attempt because the mask accepts any pubkey.
        let result = build_mining_tx(
            &[0u8; 32],
            &prev_block_hash,
            &prev_tx_hash,
            &prev_mint_output,
            0..1,
        );
        assert!(
            result.is_some(),
            "Expected mining to find a solution with permissive mask"
        );
        let (_signing_key, tx) = result.unwrap();

        // Basic structural checks
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 2);

        let input = &tx.inputs[0];
        let output = &tx.outputs[0];
        let solution = mining_solution(&prev_block_hash, &input.public_key, &output.commitment);
        assert!(matches_mask(&mask, &solution));

        // Verify the signature over the sighash using the revealed public key
        let sighash = sighash(&[input.output_id], &tx.outputs);
        let vk = VerifyingKey::from_bytes(&input.public_key).expect("valid vk");
        let sig = Signature::from_slice(&input.signature).expect("valid signature");
        assert!(vk.verify_strict(&sighash, &sig).is_ok());
    }

    #[test]
    fn test_build_mining_tx_deterministic_zero_attempts_returns_none() {
        let mask = [0x00u8; 32];
        let prev_mint_output = Output {
            version: Version::V1,
            amount: 100,
            data: [0u8; 32],
            commitment: mask,
        };
        let funding_tx = Transaction {
            inputs: vec![],
            outputs: vec![prev_mint_output],
        };
        let prev_tx_hash = funding_tx.hash();
        let prev_block_hash = [0u8; 32];

        let tx_opt = build_mining_tx(
            &[0u8; 32],
            &prev_block_hash,
            &prev_tx_hash,
            &prev_mint_output,
            0..0,
        );
        assert_eq!(tx_opt, None, "Expected None when max_attempts is zero");
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

        let prev_mint_output = Output::new_v0(100, &mask, &[0; 32]);
        let funding_tx = Transaction {
            inputs: vec![],
            outputs: vec![prev_mint_output],
        };
        let prev_tx_hash = funding_tx.hash();
        let prev_block_hash = [0u8; 32];

        // Allow a generous number of attempts but we expect to find a solution far fewer.
        let max_attempts = 100_000;
        let master_seed = [0u8; 32];

        let start = Instant::now();
        let result = build_mining_tx(
            &master_seed,
            &prev_block_hash,
            &prev_tx_hash,
            &prev_mint_output,
            0..max_attempts,
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

        let input = &tx.inputs[0];
        let output = &tx.outputs[0];
        let solution = mining_solution(&prev_block_hash, &input.public_key, &output.commitment);
        assert!(matches_mask(&mask, &solution));

        // Verify the signature over the sighash using the revealed public key
        let sighash = sighash(&[input.output_id], &tx.outputs);
        let vk = VerifyingKey::from_bytes(&input.public_key).expect("valid vk");
        let sig = Signature::from_slice(&input.signature).expect("valid signature");
        assert!(vk.verify_strict(&sighash, &sig).is_ok());
    }
}
