use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use eupp_core::ledger::Query;
use eupp_core::transaction::{Output, OutputId, Transaction, TransactionHash};
use eupp_net::RpcClient;
use eupp_net::protocol::{self as protocol, RpcError, RpcRequest, RpcResponse};

/// Newtype wrapper around [`RpcError`] so we can implement [`IntoResponse`]
/// in this crate (orphan-rule workaround).
struct ApiError(RpcError);

impl From<RpcError> for ApiError {
    fn from(err: RpcError) -> Self {
        ApiError(err)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match &self.0 {
            RpcError::ChannelClosed => StatusCode::INTERNAL_SERVER_ERROR,
            RpcError::LockError => StatusCode::INTERNAL_SERVER_ERROR,
            RpcError::Handler(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, self.0.to_string()).into_response()
    }
}

/// Build and return an Axum `Router` wired to the provided `RpcClient`.
pub fn router(state: RpcClient) -> Router {
    Router::new()
        .route("/network", get(get_network_info))
        .route(
            "/transactions/:tx_hash/confirmations",
            get(get_confirmations),
        )
        .route("/transactions/outputs", post(query_outputs))
        .route("/transactions", post(send_raw_tx))
        .with_state(state)
}

async fn get_network_info(
    State(client): State<RpcClient>,
) -> Result<Json<protocol::NetworkInfo>, ApiError> {
    match client.request(RpcRequest::GetNetworkInfo).await? {
        RpcResponse::NetworkInfo(info) => Ok(Json(info)),
        _ => Err(RpcError::Handler("unexpected response".to_string()).into()),
    }
}

async fn get_confirmations(
    State(client): State<RpcClient>,
    axum::extract::Path(tx_hash_hex): axum::extract::Path<String>,
) -> Result<Json<u64>, ApiError> {
    let bytes = hex::decode(&tx_hash_hex)
        .map_err(|e| RpcError::Handler(format!("invalid tx hash: {e}")))?;
    if bytes.len() != 32 {
        return Err(RpcError::Handler("tx hash must be 32 bytes".to_string()).into());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    match client
        .request(RpcRequest::GetConfirmations { tx_hash: arr })
        .await?
    {
        RpcResponse::Confirmations(n) => Ok(Json(n)),
        _ => Err(RpcError::Handler("unexpected response".to_string()).into()),
    }
}

async fn query_outputs(
    State(client): State<RpcClient>,
    Json(query): Json<Query>,
) -> Result<Json<Vec<(OutputId, Output)>>, ApiError> {
    match client.request(RpcRequest::GetUtxos { query }).await? {
        RpcResponse::Utxos(list) => Ok(Json(list)),
        _ => Err(RpcError::Handler("unexpected response".to_string()).into()),
    }
}

async fn send_raw_tx(
    State(client): State<RpcClient>,
    Json(tx): Json<Transaction>,
) -> Result<Json<TransactionHash>, ApiError> {
    match client
        .request(RpcRequest::SendRawTransaction { tx })
        .await?
    {
        RpcResponse::TransactionHash(h) => Ok(Json(h)),
        _ => Err(RpcError::Handler("unexpected response".to_string()).into()),
    }
}
