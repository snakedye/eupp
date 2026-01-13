use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;

use async_trait::async_trait;
use eupp_core::{
    ledger::{Ledger, Query},
    transaction::{Transaction, TransactionHash},
};
use eupp_rpc::{EuppRpcServer, NetworkInfo, OutputEntry};
use jsonrpsee::types::ErrorObjectOwned;

/// The server-side implementation of the `EuppRpc`.
pub struct EuppRpcImpl<L> {
    ledger: Arc<RwLock<L>>,
    tx_sender: mpsc::Sender<Transaction>,
}

impl<L> EuppRpcImpl<L> {
    pub fn new(ledger: Arc<RwLock<L>>, tx_sender: mpsc::Sender<Transaction>) -> Self {
        Self { ledger, tx_sender }
    }
}

#[async_trait]
impl<L> EuppRpcServer for EuppRpcImpl<L>
where
    L: Ledger + Send + Sync + 'static,
{
    async fn get_network_info(&self) -> Result<NetworkInfo, ErrorObjectOwned> {
        let lg = self.ledger.read().unwrap();
        let metadata = lg.get_last_block_metadata();

        match metadata {
            Some(meta) => Ok(NetworkInfo {
                tip_hash: meta.hash,
                tip_height: meta.height as u64,
                available_supply: meta.available_supply,
            }),
            None => Ok(NetworkInfo {
                tip_hash: Default::default(),
                tip_height: 0,
                available_supply: 0,
            }),
        }
    }

    async fn get_confirmations(&self, tx_hash: TransactionHash) -> Result<u64, ErrorObjectOwned> {
        let lg = self.ledger.read().unwrap();
        let tip_metadata = lg.get_last_block_metadata();
        let tx_block_hash = lg.get_transaction_block_hash(&tx_hash);

        match (tip_metadata, tx_block_hash) {
            (Some(tip), Some(block_hash)) => {
                let block_metadata = lg.get_block_metadata(&block_hash).unwrap();
                let confirmations = tip.height.saturating_sub(block_metadata.height);
                Ok(confirmations as u64)
            }
            _ => Ok(0),
        }
    }

    async fn send_raw_transaction(
        &self,
        tx: Transaction,
    ) -> Result<TransactionHash, ErrorObjectOwned> {
        let tx_hash = tx.hash();
        {
            let lg = self.ledger.read().unwrap();
            tx.verify(&*lg).map_err(|e| {
                ErrorObjectOwned::owned(-32600, "Transaction verification failed", Some(e))
            })?;
        }

        // Send to the network loop to be gossiped
        let _ = self.tx_sender.send(tx).await;

        Ok(tx_hash)
    }

    async fn get_utxos(&self, query: Query) -> Result<Vec<OutputEntry>, ErrorObjectOwned> {
        let lg = self.ledger.read().unwrap();
        Ok(lg.query_utxos(&query).collect())
    }
}
