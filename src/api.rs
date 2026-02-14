use std::collections::HashMap;

use axum::{
    Json, Router,
    extract::Query as HttpQuery,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use eupp_core::{BlockHeader, Output, OutputId, Transaction, TransactionHash, ledger::Query};
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
            RpcError::UnexpectedResponse(_) => StatusCode::INTERNAL_SERVER_ERROR,
            RpcError::BadRequest(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, self.0.to_string()).into_response()
    }
}

/// Build and return an Axum `Router` wired to the provided `RpcClient`.
pub fn router(state: RpcClient) -> Router {
    Router::new()
        .route("/", get(root_handler))
        .route("/network", get(get_network_info))
        .route(
            "/transactions/:tx_hash/confirmations",
            get(get_confirmations),
        )
        .route("/transactions/outputs", post(query_outputs))
        .route("/blocks", get(get_block))
        .route("/transactions", post(send_raw_tx))
        .with_state(state)
}

async fn root_handler() -> &'static str {
    "Welcome to the Eupp API!"
}

async fn get_network_info(
    State(client): State<RpcClient>,
) -> Result<Json<protocol::NetworkInfo>, ApiError> {
    match client.request(RpcRequest::GetNetworkInfo).await? {
        RpcResponse::NetworkInfo(info) => Ok(Json(info)),
        resp => Err(RpcError::UnexpectedResponse(resp).into()),
    }
}

async fn get_confirmations(
    State(client): State<RpcClient>,
    axum::extract::Path(tx_hash_hex): axum::extract::Path<String>,
) -> Result<Json<u64>, ApiError> {
    let hash = const_hex::decode_to_array(tx_hash_hex)
        .map_err(|e| RpcError::BadRequest(format!("invalid tx hash: {e}")))?;
    match client
        .request(RpcRequest::GetConfirmations { tx_hash: hash })
        .await?
    {
        RpcResponse::Confirmations(n) => Ok(Json(n)),
        resp => Err(RpcError::UnexpectedResponse(resp).into()),
    }
}

async fn query_outputs(
    State(client): State<RpcClient>,
    Json(query): Json<Query>,
) -> Result<Json<Vec<(OutputId, Output)>>, ApiError> {
    match client.request(RpcRequest::GetUtxos { query }).await? {
        RpcResponse::Utxos(list) => Ok(Json(list)),
        resp => Err(RpcError::UnexpectedResponse(resp).into()),
    }
}

async fn get_block(
    State(client): State<RpcClient>,
    HttpQuery(params): HttpQuery<HashMap<String, String>>,
) -> Result<Json<BlockHeader>, ApiError> {
    // Prefer explicit block_hash if provided, otherwise fall back to tx_hash.
    if let Some(block_hash_hex) = params.get("hash") {
        let hash = const_hex::decode_to_array(block_hash_hex)
            .map_err(|e| RpcError::BadRequest(format!("invalid block hash: {e}")))?;
        match client
            .request(RpcRequest::GetBlockByHash { block_hash: hash })
            .await?
        {
            RpcResponse::BlockHeader(header) => Ok(Json(header)),
            resp => Err(RpcError::UnexpectedResponse(resp).into()),
        }
    } else if let Some(tx_hash_hex) = params.get("tx_id") {
        let hash = const_hex::decode_to_array(tx_hash_hex)
            .map_err(|e| RpcError::BadRequest(format!("invalid tx hash: {e}")))?;
        match client
            .request(RpcRequest::GetBlockByTxHash { tx_hash: hash })
            .await?
        {
            RpcResponse::BlockHeader(header) => Ok(Json(header)),
            resp => Err(RpcError::UnexpectedResponse(resp).into()),
        }
    } else {
        Err(RpcError::BadRequest("missing hash or tx_id parameter".to_string()).into())
    }
}

async fn send_raw_tx(
    State(client): State<RpcClient>,
    Json(tx): Json<Transaction>,
) -> Result<Json<TransactionHash>, ApiError> {
    match client
        .request(RpcRequest::BroadcastTransaction { tx })
        .await?
    {
        RpcResponse::TransactionHash(h) => Ok(Json(h)),
        resp => Err(RpcError::UnexpectedResponse(resp).into()),
    }
}
