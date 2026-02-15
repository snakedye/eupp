use axum::{
    Json, Router,
    extract::State,
    http::{StatusCode, header::LOCATION},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use eupp_core::{Output, OutputId, Transaction, ledger::Query};
use eupp_net::protocol::{self as protocol, RpcError, RpcRequest, RpcResponse};
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
///
/// Endpoints:
/// - GET  /                 -> root_handler
/// - GET  /network          -> get_network_info
/// - GET  /transactions/:tx_hash/confirmations -> get_confirmations (returns { confirmations: n })
/// - GET  /transactions/:tx_hash/block         -> get_block_from_tx_id
/// - POST /outputs/search  -> search_outputs  (complex query in JSON body)
/// - GET  /blocks/:hash    -> get_block
/// - POST /transactions    -> send_raw_tx (broadcast; returns 201 + Location)
pub fn router(state: RpcClient) -> Router {
    Router::new()
        .route("/", get(root_handler))
        .route("/network", get(get_network_info))
        .route(
            "/transactions/:tx_hash/confirmations",
            get(get_confirmations),
        )
        .route("/transactions/:tx_hash/block", get(get_block_from_tx_id))
        .route("/outputs/search", post(search_outputs))
        .route("/blocks/:hash", get(get_block))
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
    match client
        .request(RpcRequest::GetConfirmations { tx_hash: hash })
        .await?
    {
        RpcResponse::Confirmations(n) => Ok(Json(Confirmations { confirmations: n })),
        resp => Err(RpcError::UnexpectedResponse(resp).into()),
    }
}

async fn get_block_from_tx_id(
    State(client): State<RpcClient>,
    axum::extract::Path(tx_hash_hex): axum::extract::Path<String>,
) -> Result<Json<BlockSummary>, ApiError> {
    let tx_hash = parse_hex_hash(&tx_hash_hex)?;
    match client
        .request(RpcRequest::GetBlockByTxHash { tx_hash })
        .await?
    {
        RpcResponse::BlockSummary(summary) => Ok(Json(summary)),
        resp => Err(RpcError::UnexpectedResponse(resp).into()),
    }
}

async fn search_outputs(
    State(client): State<RpcClient>,
    Json(query): Json<Query>,
) -> Result<Json<Vec<(OutputId, Output)>>, ApiError> {
    match client.request(RpcRequest::GetOutputs { query }).await? {
        RpcResponse::Outputs(list) => Ok(Json(list)),
        resp => Err(RpcError::UnexpectedResponse(resp).into()),
    }
}

async fn get_block(
    State(client): State<RpcClient>,
    axum::extract::Path(block_hash_hex): axum::extract::Path<String>,
) -> Result<Json<BlockSummary>, ApiError> {
    let hash = parse_hex_hash(&block_hash_hex)?;
    match client.request(RpcRequest::GetBlockByHash { hash }).await? {
        RpcResponse::BlockSummary(summary) => Ok(Json(summary)),
        resp => Err(RpcError::UnexpectedResponse(resp).into()),
    }
}

/// Broadcast a transaction (create a new transaction resource).
/// Returns 201 Created with a Location header pointing to `/transactions/{tx_hash}`.
async fn send_raw_tx(
    State(client): State<RpcClient>,
    Json(tx): Json<Transaction>,
) -> Result<Response, ApiError> {
    match client
        .request(RpcRequest::BroadcastTransaction { tx })
        .await?
    {
        RpcResponse::TransactionHash(h) => {
            let hex = const_hex::encode(h);
            let location = format!("/transactions/0x{hex}");
            let body = Json(h);
            let resp = (StatusCode::CREATED, [(LOCATION, location.as_str())], body).into_response();
            Ok(resp)
        }
        resp => Err(RpcError::UnexpectedResponse(resp).into()),
    }
}
