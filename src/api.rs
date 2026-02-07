use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    routing::{get, post},
};
use eupp_core::ledger::Query;
use eupp_core::transaction::{Output, OutputId, Transaction, TransactionHash};
use eupp_net::RpcClient;
use eupp_net::protocol::{self as protocol, RpcRequest, RpcResponse};

/// Build and return an Axum `Router` wired to the provided `RpcClient`.
pub fn router(state: RpcClient) -> Router {
    Router::new()
        .route("/network", get(get_network_info))
        .route(
            "/transactions/:tx_hash/confirmations",
            get(get_confirmations),
        )
        .route("/transactions/outputs", post(query_outputs))
        .route("/transactions/outputs", get(get_outputs))
        .route("/transactions", post(send_raw_tx))
        .with_state(state)
}

async fn get_network_info(
    State(client): State<RpcClient>,
) -> Result<Json<protocol::NetworkInfo>, StatusCode> {
    match client.request(RpcRequest::GetNetworkInfo).await {
        Some(RpcResponse::NetworkInfo(info)) => Ok(Json(info)),
        _ => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn get_confirmations(
    State(client): State<RpcClient>,
    axum::extract::Path(tx_hash_hex): axum::extract::Path<String>,
) -> Result<Json<u64>, StatusCode> {
    match hex::decode(&tx_hash_hex) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            match client
                .request(RpcRequest::GetConfirmations { tx_hash: arr })
                .await
            {
                Some(RpcResponse::Confirmations(n)) => Ok(Json(n)),
                _ => Err(StatusCode::INTERNAL_SERVER_ERROR),
            }
        }
        _ => Err(StatusCode::BAD_REQUEST),
    }
}

async fn query_outputs(
    State(client): State<RpcClient>,
    Json(query): Json<Query>,
) -> Result<Json<Vec<(OutputId, Output)>>, StatusCode> {
    match client.request(RpcRequest::GetUtxos { query }).await {
        Some(RpcResponse::Utxos(list)) => Ok(Json(list)),
        _ => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn get_outputs(
    State(client): State<RpcClient>,
) -> Result<Json<Vec<(OutputId, Output)>>, StatusCode> {
    match client
        .request(RpcRequest::GetUtxos {
            query: Query::new(),
        })
        .await
    {
        Some(RpcResponse::Utxos(list)) => Ok(Json(list)),
        _ => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn send_raw_tx(
    State(client): State<RpcClient>,
    Json(tx): Json<Transaction>,
) -> Result<Json<TransactionHash>, StatusCode> {
    match client.request(RpcRequest::SendRawTransaction { tx }).await {
        Some(RpcResponse::TransactionHash(h)) => Ok(Json(h)),
        _ => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}
