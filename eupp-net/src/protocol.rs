use eupp_core::block::Block;
use eupp_core::transaction::Transaction;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum NetworkMessage {
    Transaction(Transaction),
    Block(Block),
    GetMaxSupply,
    MaxSupply(u32),
    GetBlocks(u32), // from height
    SyncComplete,
}
