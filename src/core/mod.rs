use sha2::Digest;

mod block;
mod ledger;
mod miner;
mod transaction;

type PublicKey = [u8; 32];
type Hash = [u8; 32];

// Helpers
fn hash_pubkey<D: Digest>(pubkey_bytes: &PublicKey) -> Hash {
    let hash = D::digest(pubkey_bytes);
    let mut buf = [0u8; 32];
    buf.copy_from_slice(hash.as_ref());
    buf
}

fn matches_mask(mask: &[u8; 32], attempted: &Hash) -> bool {
    for i in 0..32 {
        if (mask[i] & attempted[i]) != attempted[i] {
            return false;
        }
    }
    true
}
