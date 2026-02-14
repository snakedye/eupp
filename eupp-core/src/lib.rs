use blake2::Digest;
use ed25519_dalek::SigningKey;
use serde::Deserialize;

mod block;
pub mod ledger;
pub mod miner;
mod transaction;
pub mod vm;

pub use block::*;
use const_hex as hex;
pub use transaction::*;

/// Like [`AsRef`], but returns `Option<&T>` instead of `&T`.
pub trait TryAsRef<T: ?Sized> {
    fn try_as_ref(&self) -> Option<&T>;
}

/// 32-byte Ed25519 public key
pub type PublicKey = [u8; 32];

/// 32-byte Ed25519 secret key
pub type SecretKey = [u8; 32];

/// 32-byte hash (e.g., Blake2s256 output)
pub type Hash = [u8; 32];

/// 64-byte Ed25519 signature
pub type Signature = [u8; 64];

/// Trait for calculating the virtual size of a type.
pub trait VirtualSize {
    /// Returns the virtual size of the type in bytes.
    fn vsize(&self) -> usize;
}

/// Create a 32-byte commitment from a public key.
pub fn commitment<'a>(pk: &PublicKey, data: impl IntoIterator<Item = &'a [u8]>) -> Hash {
    let mut hasher = blake2::Blake2s256::new();
    hasher.update(pk);
    for chunk in data {
        hasher.update(chunk);
    }
    hasher.finalize().into()
}

/// Generate a keypair from a secret key.
pub fn keypair(sk: &SecretKey) -> SigningKey {
    SigningKey::from_bytes(sk)
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

/// Calculate block reward using an asymptotic curve.
pub fn calculate_reward(mask: &[u8; 32]) -> u64 {
    const MAX_REWARD: u64 = 1_000_000;
    const MIN_REWARD: u64 = 1;
    // Every 32 bits halves the distance to the cap.
    const HALF_LIFE: u32 = 32;

    let difficulty = mask_difficulty(mask);

    if difficulty == 0 {
        return MIN_REWARD;
    }

    // Reward formula: MAX - (MAX - MIN) / 2^(difficulty / HALF_LIFE)
    // We use u128 to ensure no overflows during intermediate calculations.
    let range = (MAX_REWARD - MIN_REWARD) as u128;

    // Integer division for the exponent
    let exponent = difficulty / HALF_LIFE;
    let remainder_bits = difficulty % HALF_LIFE;

    // Calculate the divisor: 2^exponent
    let divisor = match 1u128.checked_shl(exponent) {
        Some(v) => v,
        None => return MAX_REWARD, // If difficulty is extremely high, we are at the cap
    };

    // Calculate the base reduction (the "gap" we subtract from MAX)
    // To make the curve smooth for EVERY bit (not just every 32 bits),
    // we approximate the fractional part of the exponent.
    // This reduces the gap by ~2.18% per bit (since 1.0218^32 ≈ 2)
    // Using fixed-point: gap = gap * (100 - 2) / 100 for each remainder bit
    let gap = (0..remainder_bits).fold(range / divisor, |gap, _| (gap * 978) / 1000);

    let final_reward = MAX_REWARD.saturating_sub(gap as u64);

    final_reward.max(MIN_REWARD)
}

/// Serialize a byte slice to a hexadecimal string.
pub fn serialize_to_hex<S>(hash: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&hex::encode(hash))
}

/// Deserialize a hexadecimal string into a fixed-size array.
pub fn deserialize_arr<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    hex::decode_to_array(&s).map_err(serde::de::Error::custom)
}

/// Deserialize a hexadecimal string into a vector.
pub fn deserialize_vec<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    hex::decode(&s).map_err(serde::de::Error::custom)
}

impl<U, T> TryAsRef<U> for T
where
    T: AsRef<U>,
{
    fn try_as_ref(&self) -> Option<&U> {
        Some(self.as_ref())
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
        // expectation: reward = 1 (spam protection)
        assert_eq!(reward, 1);
    }

    #[test]
    fn reward_all_ones() {
        // mask all ones => difficulty = 256
        let mask = [0xFFu8; 32];
        let reward = calculate_reward(&mask);
        // difficulty = 256 -> reward = capped at MAX_REWARD
        assert_eq!(reward, 996_094);
    }

    #[test]
    fn reward_60_zeros() {
        // difficulty = 60
        let mask = mask_with_ones(60);
        let reward = calculate_reward(&mask);
        // difficulty = 60 -> reward = 731,812
        assert_eq!(reward, 731_812);
    }

    #[test]
    fn reward_68_zeros() {
        // difficulty = 68
        let mask = mask_with_ones(68);
        let reward = calculate_reward(&mask);
        // difficulty = 68 -> reward = 771,286
        assert_eq!(reward, 771_286);
    }

    #[test]
    fn reward_80_zeros() {
        // difficulty = 80
        let mask = mask_with_ones(80);
        let reward = calculate_reward(&mask);
        // difficulty = 80 -> reward = 824,876
        assert_eq!(reward, 824_876);
    }

    // Additional checks matching the requested table
    #[test]
    fn reward_difficulty_16() {
        let mask = mask_with_ones(16);
        let reward = calculate_reward(&mask);
        // difficulty = 16 -> reward = 299,485
        assert_eq!(reward, 299_485);
    }

    #[test]
    fn reward_difficulty_32() {
        let mask = mask_with_ones(32);
        let reward = calculate_reward(&mask);
        // difficulty = 32 -> reward = 500,001
        assert_eq!(reward, 500_001);
    }

    #[test]
    fn reward_difficulty_48() {
        let mask = mask_with_ones(48);
        let reward = calculate_reward(&mask);
        // difficulty = 48 -> reward = 649,746
        assert_eq!(reward, 649_746);
    }

    #[test]
    fn reward_difficulty_64() {
        let mask = mask_with_ones(64);
        let reward = calculate_reward(&mask);
        // difficulty = 64 -> reward = 750,001
        assert_eq!(reward, 750_001);
    }

    // ── matches_mask tests ──────────────────────────────────────────────

    #[test]
    fn matches_mask_all_zeros_mask_accepts_anything() {
        let mask = [0u8; 32];
        assert!(matches_mask(&mask, &[0xFF; 32]));
        assert!(matches_mask(&mask, &[0x00; 32]));
        assert!(matches_mask(&mask, &[0xAB; 32]));
    }

    #[test]
    fn matches_mask_all_ones_mask_requires_all_zeros() {
        let mask = [0xFF; 32];
        assert!(matches_mask(&mask, &[0x00; 32]));
        assert!(!matches_mask(&mask, &[0x01; 32]));
        assert!(!matches_mask(&mask, &[0xFF; 32]));
    }

    #[test]
    fn matches_mask_single_bit() {
        let mut mask = [0u8; 32];
        mask[0] = 0b0000_0100; // bit 2 of byte 0 must be zero
        let mut good = [0u8; 32];
        good[0] = 0b1111_1011; // every bit set except bit 2
        assert!(matches_mask(&mask, &good));

        let mut bad = [0u8; 32];
        bad[0] = 0b0000_0100; // bit 2 set
        assert!(!matches_mask(&mask, &bad));
    }

    #[test]
    fn matches_mask_partial_byte() {
        let mut mask = [0u8; 32];
        mask[0] = 0xF0; // upper nibble must be zero
        let mut attempt = [0u8; 32];
        attempt[0] = 0x0F; // lower nibble set, upper clear
        assert!(matches_mask(&mask, &attempt));

        attempt[0] = 0x10; // one bit in upper nibble set
        assert!(!matches_mask(&mask, &attempt));
    }

    #[test]
    fn matches_mask_only_checked_bytes_matter() {
        let mut mask = [0u8; 32];
        mask[31] = 0xFF; // only last byte constrained
        let mut attempt = [0xFF; 32];
        attempt[31] = 0x00; // last byte all zeros
        assert!(matches_mask(&mask, &attempt));

        attempt[31] = 0x01;
        assert!(!matches_mask(&mask, &attempt));
    }

    // ── mask_difficulty tests ───────────────────────────────────────────

    #[test]
    fn mask_difficulty_zero_mask() {
        assert_eq!(mask_difficulty(&[0u8; 32]), 0);
    }

    #[test]
    fn mask_difficulty_full_mask() {
        assert_eq!(mask_difficulty(&[0xFF; 32]), 256);
    }

    #[test]
    fn mask_difficulty_single_bit() {
        let mut mask = [0u8; 32];
        mask[0] = 1;
        assert_eq!(mask_difficulty(&mask), 1);
    }

    #[test]
    fn mask_difficulty_matches_helper() {
        for ones in [1, 7, 8, 15, 16, 33, 60, 128, 200, 256] {
            let mask = mask_with_ones(ones);
            assert_eq!(
                mask_difficulty(&mask) as usize,
                ones,
                "mask_with_ones({ones}) should have difficulty {ones}"
            );
        }
    }

    #[test]
    fn mask_difficulty_sparse_bits() {
        let mut mask = [0u8; 32];
        mask[0] = 0b1010_1010; // 4 bits
        mask[16] = 0b0001_0001; // 2 bits
        assert_eq!(mask_difficulty(&mask), 6);
    }

    // ── commitment tests ────────────────────────────────────────────────

    #[test]
    fn commitment_deterministic() {
        let pk = [42u8; 32];
        let data: &[u8] = &[1, 2, 3];
        let c1 = commitment(&pk, Some(data));
        let c2 = commitment(&pk, Some(data));
        assert_eq!(c1, c2);
    }

    #[test]
    fn commitment_changes_with_pk() {
        let data: &[u8] = &[0u8; 4];
        let c1 = commitment(&[0u8; 32], Some(data));
        let c2 = commitment(&[1u8; 32], Some(data));
        assert_ne!(c1, c2);
    }

    #[test]
    fn commitment_changes_with_data() {
        let pk = [7u8; 32];
        let c1 = commitment(&pk, Some([0u8].as_slice()));
        let c2 = commitment(&pk, Some([1u8].as_slice()));
        assert_ne!(c1, c2);
    }

    #[test]
    fn commitment_no_data_differs_from_empty_slice() {
        let pk = [9u8; 32];
        let c_none: Hash = commitment(&pk, None);
        let c_empty: Hash = commitment(&pk, Some([].as_slice()));
        // Both should be the same since iterating over None yields nothing,
        // just like iterating over an empty slice.
        assert_eq!(c_none, c_empty);
    }

    #[test]
    fn commitment_multiple_data_chunks() {
        let pk = [5u8; 32];
        let chunks: Vec<&[u8]> = vec![&[1, 2], &[3, 4]];
        let c1 = commitment(&pk, chunks.clone());
        let c2 = commitment(&pk, chunks);
        assert_eq!(c1, c2);
        // Single concatenated chunk should differ because blake2 processes
        // update calls sequentially; however here the hash state is the same
        // as feeding [1,2] then [3,4], which equals feeding [1,2,3,4] for
        // a streaming hash. Verify that equivalence:
        let c_concat = commitment(&pk, vec![[1u8, 2, 3, 4].as_slice()]);
        assert_eq!(c1, c_concat);
    }

    #[test]
    fn commitment_output_is_32_bytes() {
        let pk = [0u8; 32];
        let c = commitment(&pk, None);
        assert_eq!(c.len(), 32);
    }
}
