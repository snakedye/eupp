/*!
Configuration loader for the network node.

Use `Config::from_env()` to construct a configuration from environment variables or a `.env` file.
*/

use std::env;
use std::error::Error;
use std::fmt;

use const_hex as hex;
use eupp_core::PublicKey;
use libp2p::identity::ed25519::{Keypair, SecretKey};

/// Default number of blocks to fetch in a single synchronization chunk when not provided.
const DEFAULT_BLOCK_CHUNK_SIZE: usize = 16;

/// Error type for config parsing issues.
#[derive(Debug)]
pub struct ConfigError {
    /// The environment variable that caused the error.
    pub var: &'static str,
    /// A description of what went wrong.
    pub message: String,
}

impl ConfigError {
    fn new(var: &'static str, message: impl Into<String>) -> Self {
        Self {
            var,
            message: message.into(),
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "var ({}) {}", self.var, self.message)
    }
}

impl Error for ConfigError {}

/// Read an environment variable, returning `None` when unset or empty.
/// The returned value is always trimmed.
fn env_var(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// The configuration of an [`crate::EuppNode`].
#[derive(Clone, Debug)]
pub struct Config {
    /// Optional TCP port for the HTTP API.
    ///
    /// Environment variable: `EUPP_API_PORT`
    pub api_port: Option<u16>,

    /// Optional TCP port for libp2p peer-to-peer communication.
    /// When not set, the OS assigns a random available port.
    ///
    /// Environment variable: `EUPP_P2P_PORT`
    pub p2p_port: Option<u16>,

    /// Raw 32 bytes of the ed25519 secret key.
    ///
    /// The environment value should be a hex-encoded 32-byte secret (64 hex chars).
    pub secret_key: [u8; 32],

    /// Optional mining difficulty in bits. When set, mining is enabled
    /// with this many leading zero-bytes required in the solution hash.
    ///
    /// Environment variable: `EUPP_MINING_DIFFICULTY`
    pub difficulty: Option<usize>,

    /// The number of blocks to fetch in a single synchronization chunk.
    pub block_chunk_size: usize,

    /// Optional path to the indexing database (used by `eupp-db`).
    ///
    /// Environment variable: `EUPP_INDEX_DB_PATH`
    pub index_db_path: Option<String>,

    /// Optional path to the block file where all blocks are stored on disk.
    ///
    /// Environment variable: `EUPP_BLOCK_FILE`
    pub block_file_path: Option<String>,

    /// The gossipsub topic / network name used for peer communication (required).
    ///
    /// Environment variable: `EUPP_NETWORK_NAME`
    pub network_name: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            api_port: None,
            p2p_port: None,
            secret_key: Default::default(),
            difficulty: None,
            block_chunk_size: DEFAULT_BLOCK_CHUNK_SIZE,
            index_db_path: None,
            block_file_path: None,
            network_name: String::new(),
        }
    }
}

impl Config {
    /// Load configuration from environment variables or a `.env` file.
    ///
    /// Recognized environment variables:
    /// - `EUPP_API_PORT` - optional HTTP API port (u16)
    /// - `EUPP_P2P_PORT` - optional libp2p port (u16), OS-assigned if omitted
    /// - `EUPP_SECRET_KEY` - required hex-encoded 32-byte ed25519 secret key
    /// - `EUPP_MINING_DIFFICULTY` - optional mining difficulty in bits (0–256); enables mining when set
    /// - `EUPP_BLOCK_CHUNK_SIZE` - optional usize, defaults to 16
    /// - `EUPP_INDEX_DB_PATH` - optional path to the indexing database used by `eupp-db`
    /// - `EUPP_BLOCK_FILE` - optional path to the block file where blocks are stored
    /// - `EUPP_NETWORK_NAME` - required network name / gossipsub topic
    pub fn from_env() -> Result<Self, ConfigError> {
        // Load .env if present, ignore errors
        let _ = dotenv::dotenv();

        let api_port = env_var("EUPP_API_PORT")
            .map(|s| {
                s.parse::<u16>()
                    .map_err(|e| ConfigError::new("EUPP_API_PORT", format!("invalid u16: {e}")))
            })
            .transpose()?;

        let p2p_port = env_var("EUPP_P2P_PORT")
            .map(|s| {
                s.parse::<u16>()
                    .map_err(|e| ConfigError::new("EUPP_P2P_PORT", format!("invalid u16: {e}")))
            })
            .transpose()?;

        let mining_difficulty = env_var("EUPP_MINING_DIFFICULTY")
            .map(|s| {
                s.parse::<usize>().map_err(|e| {
                    ConfigError::new("EUPP_MINING_DIFFICULTY", format!("invalid usize: {e}"))
                })
            })
            .transpose()?;

        let block_chunk_size = env_var("EUPP_BLOCK_CHUNK_SIZE")
            .map(|s| {
                s.parse::<usize>().map_err(|e| {
                    ConfigError::new("EUPP_BLOCK_CHUNK_SIZE", format!("invalid usize: {e}"))
                })
            })
            .transpose()?
            .unwrap_or(DEFAULT_BLOCK_CHUNK_SIZE);

        let index_db_path = env_var("EUPP_INDEX_DB_PATH");
        let block_file_path = env_var("EUPP_BLOCK_FILE");

        let network_name = env_var("EUPP_NETWORK_NAME")
            .ok_or_else(|| ConfigError::new("EUPP_NETWORK_NAME", "not set"))?;

        let sk_hex = env_var("EUPP_SECRET_KEY")
            .or_else(|| env_var("SECRET_KEY"))
            .ok_or_else(|| {
                ConfigError::new("EUPP_SECRET_KEY", "hex-encoded 32-byte key not set")
            })?;

        let sk_hex_trimmed = sk_hex.trim_start_matches("0x");

        let secret_key = hex::decode_to_array(sk_hex_trimmed).map_err(|e| {
            ConfigError::new(
                "EUPP_SECRET_KEY",
                format!("invalid hex (expected 64 hex chars): {e}"),
            )
        })?;

        Ok(Config {
            api_port,
            p2p_port,
            secret_key,
            difficulty: mining_difficulty,
            block_chunk_size,
            index_db_path,
            block_file_path,
            network_name,
        })
    }

    /// Retrieve the secret key.
    pub fn secret_key(&self) -> [u8; 32] {
        self.secret_key
    }

    /// Retrieve the public key.
    pub fn public_key(&self) -> PublicKey {
        let sk = SecretKey::try_from_bytes(self.secret_key.clone().as_mut()).unwrap();
        let kp = Keypair::from(sk);
        kp.public().to_bytes()
    }

    /// Convenience: return the effective block chunk size (already present on the struct,
    /// but this method exists for symmetry/clarity).
    pub fn block_chunk_size(&self) -> usize {
        self.block_chunk_size
    }

    /// Optional path to the indexing database (if configured).
    pub fn index_db_path(&self) -> Option<&str> {
        self.index_db_path.as_deref()
    }

    /// Optional path to the block file where blocks are stored (if configured).
    pub fn block_file_path(&self) -> Option<&str> {
        self.block_file_path.as_deref()
    }

    /// The gossipsub topic / network name.
    pub fn network_name(&self) -> &str {
        &self.network_name
    }
}
