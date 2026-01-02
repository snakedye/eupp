use blake2::Digest;

pub mod block;
pub mod ledger;
pub mod miner;
pub mod transaction;
pub mod vm;

pub type PublicKey = [u8; 32];
pub type Hash = [u8; 32];
pub type Signature = [u8; 64];

/// Trait for calculating the virtual size of a type.
pub trait VirtualSize {
    /// Returns the virtual size of the type in bytes.
    fn vsize(&self) -> usize;
}

// Helpers
/// Create a 32-byte commitment from a public key.
pub fn pubkey_hash(pk: &PublicKey, data: Option<&[u8]>) -> Hash {
    let mut hasher = blake2::Blake2s256::new();
    hasher.update(pk);
    if let Some(data) = data {
        hasher.update(data);
    }
    hasher.finalize().into()
}

/// Check whether an attempted public key satisfies the provided mask.
///
/// Convention:
/// - a 1-bit in `mask` indicates that the corresponding bit in `attempted` MUST be zero.
/// - The attempt matches if all masked bits in `attempted` are zero.
pub fn matches_mask(mask: &[u8; 32], attempted: &Hash) -> bool {
    attempted
        .iter()
        .zip(mask.iter())
        .all(|(&a, &m)| (a & m) == 0)
}

/// Counts how many bits the miner had to "solve".
/// This is the population count of set bits in the mask (i.e. number of constrained zero-bits).
pub fn mask_difficulty(mask: &[u8; 32]) -> u32 {
    mask.iter().map(|byte| byte.count_ones()).sum()
}

/// Calculate block reward using a Capped Exponential Growth curve.
///
/// Reward policy (as requested):
/// - Base reward = 1 (pure powers of two)
/// - exponent = floor(difficulty / SCALE_FACTOR)
/// - reward = min(HARD_CAP, 2^exponent)
pub fn calculate_reward(mask: &[u8; 32]) -> u32 {
    const HARD_CAP: u32 = 1_000_000;
    const MIN_REWARD: u32 = 1;
    const SCALE_FACTOR: u32 = 4;
    const MAX_SAFE_EXPONENT: u32 = 127; // safe for shifting u128

    // difficulty = number of 1-bits in the mask
    let difficulty: u32 = mask_difficulty(mask);

    let exponent: u32 = difficulty / SCALE_FACTOR;

    if exponent > MAX_SAFE_EXPONENT {
        return HARD_CAP;
    }

    // compute 2^exponent safely
    let pow2: u128 = match 1u128.checked_shl(exponent) {
        Some(v) => v,
        None => return HARD_CAP,
    };

    let reward128 = pow2; // base = 1 => reward = 2^exponent

    if reward128 == 0 {
        return MIN_REWARD;
    }

    if reward128 >= u128::from(HARD_CAP) {
        HARD_CAP
    } else {
        let r = reward128 as u32;
        if r < MIN_REWARD { MIN_REWARD } else { r }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a mask with exactly `ones` bits set.
    /// Bits are filled starting from byte index 0, LSB-first within each byte.
    fn mask_with_ones(mut ones: usize) -> [u8; 32] {
        let mut mask = [0u8; 32];
        mask.iter_mut().for_each(|byte| {
            if ones > 0 {
                *byte = if ones >= 8 {
                    0xFF
                } else {
                    ((1u16 << ones) - 1) as u8
                };
                ones = ones.saturating_sub(8);
            }
        });
        mask
    }

    #[test]
    fn reward_all_zeros() {
        // mask all zeros => difficulty = 0
        let mask = [0u8; 32];
        let reward = calculate_reward(&mask);
        // expectation: 2^0 = 1 (spam protection)
        assert_eq!(reward, 1);
    }

    #[test]
    fn reward_all_ones() {
        // mask all ones => difficulty = 256
        let mask = [0xFFu8; 32];
        let reward = calculate_reward(&mask);
        // exponent = 256/4 = 64 -> huge -> capped
        assert_eq!(reward, 1_000_000);
    }

    #[test]
    fn reward_60_zeros() {
        // difficulty = 60
        let mask = mask_with_ones(60);
        let reward = calculate_reward(&mask);
        // exponent = floor(60/4) = 15 -> 2^15 = 32768
        assert_eq!(reward, 32_768);
    }

    #[test]
    fn reward_68_zeros() {
        // difficulty = 68
        let mask = mask_with_ones(68);
        let reward = calculate_reward(&mask);
        // exponent = floor(68/4) = 17 -> 2^17 = 131072
        assert_eq!(reward, 131072);
    }

    #[test]
    fn reward_80_zeros() {
        // difficulty = 80
        let mask = mask_with_ones(80);
        let reward = calculate_reward(&mask);
        // exponent = 20 -> 2^20 = 1_048_576 -> capped
        assert_eq!(reward, 1_000_000);
    }

    // Additional checks matching the requested table
    #[test]
    fn reward_difficulty_16() {
        let mask = mask_with_ones(16);
        let reward = calculate_reward(&mask);
        // floor(16/4)=4 -> 2^4 = 16
        assert_eq!(reward, 16);
    }

    #[test]
    fn reward_difficulty_32() {
        let mask = mask_with_ones(32);
        let reward = calculate_reward(&mask);
        // floor(32/4)=8 -> 2^8 = 256
        assert_eq!(reward, 256);
    }

    #[test]
    fn reward_difficulty_48() {
        let mask = mask_with_ones(48);
        let reward = calculate_reward(&mask);
        // floor(48/4)=12 -> 2^12 = 4096
        assert_eq!(reward, 4_096);
    }

    #[test]
    fn reward_difficulty_64() {
        let mask = mask_with_ones(64);
        let reward = calculate_reward(&mask);
        // floor(64/4)=16 -> 2^16 = 65536
        assert_eq!(reward, 65_536);
    }
}
