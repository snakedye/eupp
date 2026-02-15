use axum::{
    Json, Router,
    extract::State,
    http::{StatusCode, header::LOCATION},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use eupp_core::{Output, OutputId, Transaction, ledger::Query};
use eupp_net::protocol::{self as protocol, RpcError};
use eupp_net::{RpcClient, protocol::BlockSummary};
use serde::Serialize;

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
            RpcError::BadRequest(_) => StatusCode::BAD_REQUEST,
        };
        (status, self.0.to_string()).into_response()
    }
}

#[derive(Serialize)]
struct Confirmations {
    confirmations: u64,
}

/// Build and return an Axum `Router` wired to the provided `RpcClient`.
pub fn router(state: RpcClient) -> Router {
    Router::new()
        .route("/", get(root_handler))
        .route("/network", get(get_network_info))
        .route(
            "/transactions/{tx_hash}/confirmations",
            get(get_confirmations),
        )
        .route("/transactions/{tx_hash}/block", get(get_block_from_tx_id))
        .route("/outputs/search", post(search_outputs))
        .route("/blocks/{hash}", get(get_block))
        .route("/transactions", post(send_raw_tx))
        .with_state(state)
}

async fn root_handler() -> &'static str {
    "Welcome to the Eupp API!"
}

async fn get_network_info(
    State(client): State<RpcClient>,
) -> Result<Json<protocol::NetworkInfo>, ApiError> {
    Ok(Json(client.get_network_info().await?))
}

/// Helper to parse hex strings from path parameters.
/// Accepts optional leading "0x".
fn parse_hex_hash<const N: usize>(s: &str) -> Result<[u8; N], RpcError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    const_hex::decode_to_array(s).map_err(|e| RpcError::BadRequest(format!("invalid hash: {e}")))
}

async fn get_confirmations(
    State(client): State<RpcClient>,
    axum::extract::Path(tx_hash_hex): axum::extract::Path<String>,
) -> Result<Json<Confirmations>, ApiError> {
    let hash = parse_hex_hash(&tx_hash_hex)?;
    let n = client.get_confirmations(hash).await?;
    Ok(Json(Confirmations { confirmations: n }))
}

async fn get_block_from_tx_id(
    State(client): State<RpcClient>,
    axum::extract::Path(tx_hash_hex): axum::extract::Path<String>,
) -> Result<Json<BlockSummary>, ApiError> {
    let tx_hash = parse_hex_hash(&tx_hash_hex)?;
    Ok(Json(client.get_block_by_tx_hash(tx_hash).await?))
}

async fn search_outputs(
    State(client): State<RpcClient>,
    Json(query): Json<Query>,
) -> Result<Json<Vec<(OutputId, Output)>>, ApiError> {
    Ok(Json(client.get_outputs(query).await?))
}

async fn get_block(
    State(client): State<RpcClient>,
    axum::extract::Path(block_hash_hex): axum::extract::Path<String>,
) -> Result<Json<BlockSummary>, ApiError> {
    let hash = parse_hex_hash(&block_hash_hex)?;
    Ok(Json(client.get_block_by_hash(hash).await?))
}

/// Broadcast a transaction (create a new transaction resource).
/// Returns 201 Created with a Location header pointing to `/transactions/{tx_hash}`.
async fn send_raw_tx(
    State(client): State<RpcClient>,
    Json(tx): Json<Transaction>,
) -> Result<Response, ApiError> {
    let h = client.broadcast_transaction(tx).await?;
    let hex = const_hex::encode(h);
    let location = format!("/transactions/0x{hex}");
    let body = Json(h);
    let resp = (StatusCode::CREATED, [(LOCATION, location.as_str())], body).into_response();
    Ok(resp)
}
