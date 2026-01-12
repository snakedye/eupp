use eupp_core::{
    Hash,
    ledger::Query,
    transaction::{Output, OutputId, Transaction, TransactionHash},
};
use jsonrpsee::{proc_macros::rpc, types::ErrorObjectOwned};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub tip_hash: Hash,
    pub tip_height: u64,
    pub available_supply: u64,
}

pub type OutputEntry = (OutputId, Output);

#[rpc(server, client, namespace = "eupp")]
pub trait EuppRpc {
    /// Returns basic information about the network.
    #[method(name = "getNetworkInfo")]
    async fn get_network_info(&self) -> Result<NetworkInfo, ErrorObjectOwned>;

    /// Returns the number of confirmations for a given transaction.
    /// Confirmations are calculated as `tip_height - transaction_block_height`.
    /// A transaction in the tip block has 0 confirmations.
    /// An unconfirmed (mempool) or non-existent transaction has 0 confirmations.
    #[method(name = "getConfirmations")]
    async fn get_confirmations(&self, tx_hash: TransactionHash) -> Result<u64, ErrorObjectOwned>;

    /// Broadcasts a raw transaction to the network.
    #[method(name = "sendRawTransaction")]
    async fn send_raw_transaction(
        &self,
        tx: Transaction,
    ) -> Result<TransactionHash, ErrorObjectOwned>;

    /// Returns the UTXOs matching the query.
    #[method(name = "getUtxosForAddresses")]
    async fn get_utxos(&self, query: Query) -> Result<Vec<OutputEntry>, ErrorObjectOwned>;
}
