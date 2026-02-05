/*!
Configuration loader for the network node.

Use `Config::from_env()` to construct a configuration from environment variables or a `.env` file.
*/

use std::env;
use std::error::Error;
use std::fmt;

use hex;

/// Default number of blocks to fetch in a single synchronization chunk when not provided.
const DEFAULT_BLOCK_CHUNK_SIZE: usize = 16;

/// Error type for config parsing issues.
#[derive(Debug)]
pub struct ConfigError(String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ConfigError: {}", self.0)
    }
}

impl Error for ConfigError {}

/// Node configuration.
#[derive(Clone, Debug)]
pub struct Config {
    /// Optional TCP port to listen on.
    pub port: Option<u16>,

    /// Raw 32 bytes of the ed25519 secret key.
    ///
    /// The environment value should be a hex-encoded 32-byte secret (64 hex chars).
    pub secret_key_bytes: [u8; 32],

    /// Whether mining should be enabled.
    pub mining: bool,

    /// The number of blocks to fetch in a single synchronization chunk.
    pub block_chunk_size: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            port: None,
            secret_key_bytes: Default::default(),
            mining: false,
            block_chunk_size: DEFAULT_BLOCK_CHUNK_SIZE,
        }
    }
}

impl Config {
    /// Load configuration from environment variables or a `.env` file.
    ///
    /// Recognized environment variables:
    /// - `EUPP_PORT` - optional port (u16)
    /// - `EUPP_SECRET_KEY` - required hex-encoded 32-byte ed25519 secret key
    /// - `EUPP_MINING` - optional boolean (true/false). Accepts `1`, `true`, `yes`, `on`.
    /// - `EUPP_BLOCK_CHUNK_SIZE` - optional usize, defaults to 16
    pub fn from_env() -> Result<Self, ConfigError> {
        // Load .env if present, ignore errors
        let _ = dotenv::dotenv();

        // PORT (optional)
        let port = match env::var("EUPP_PORT").ok() {
            Some(s) if !s.trim().is_empty() => {
                let p = s.trim().parse::<u16>().map_err(|e| {
                    ConfigError(format!("failed to parse EUPP_PORT='{}' as u16: {}", s, e))
                })?;
                Some(p)
            }
            _ => None,
        };

        // MINING (optional, default false)
        let mining = match env::var("EUPP_MINING").ok() {
            Some(s) if !s.trim().is_empty() => parse_bool(&s).map_err(|_| {
                ConfigError(format!("failed to parse EUPP_MINING='{}' as boolean", s))
            })?,
            _ => false,
        };

        // BLOCK_CHUNK_SIZE (optional, default DEFAULT_BLOCK_CHUNK_SIZE)
        let block_chunk_size = match env::var("EUPP_BLOCK_CHUNK_SIZE").ok() {
            Some(s) if !s.trim().is_empty() => {
                let n = s.trim().parse::<usize>().map_err(|e| {
                    ConfigError(format!(
                        "failed to parse EUPP_BLOCK_CHUNK_SIZE='{}' as usize: {}",
                        s, e
                    ))
                })?;
                n
            }
            _ => DEFAULT_BLOCK_CHUNK_SIZE,
        };

        // SECRET KEY (required) - expect hex encoded 32 bytes
        let sk_hex = env::var("EUPP_SECRET_KEY")
            .or_else(|_| env::var("SECRET_KEY"))
            .map_err(|_| ConfigError("EUPP_SECRET_KEY (hex-encoded 32 bytes) not set".into()))?;

        let sk_hex_trimmed = sk_hex.trim().trim_start_matches("0x");

        let sk_vec = hex::decode(sk_hex_trimmed).map_err(|e| {
            ConfigError(format!(
                "failed to decode EUPP_SECRET_KEY as hex (expected 64 hex chars): {}",
                e
            ))
        })?;

        if sk_vec.len() != 32 {
            return Err(ConfigError(format!(
                "EUPP_SECRET_KEY must decode to 32 bytes (got {} bytes)",
                sk_vec.len()
            )));
        }

        let mut secret_key_bytes = [0u8; 32];
        secret_key_bytes.copy_from_slice(&sk_vec);

        Ok(Config {
            port,
            secret_key_bytes,
            mining,
            block_chunk_size,
        })
    }

    /// Retrieve the secret key.
    pub fn secret_key(&self) -> &[u8; 32] {
        &self.secret_key_bytes
    }

    /// Convenience: return the effective block chunk size (already present on the struct,
    /// but this method exists for symmetry/clarity).
    pub fn block_chunk_size(&self) -> usize {
        self.block_chunk_size
    }
}

/// Parse a boolean-like string. Accepts `1`, `true`, `yes`, `on` as true; `0`, `false`, `no`, `off` as false.
fn parse_bool(s: &str) -> Result<bool, ()> {
    match s.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bool_accepts_variants() {
        for t in &["1", "true", "True", "YES", "on"] {
            assert_eq!(parse_bool(t).unwrap(), true);
        }
        for f in &["0", "false", "False", "no", "OFF"] {
            assert_eq!(parse_bool(f).unwrap(), false);
        }
        assert!(parse_bool("maybe").is_err());
    }
}
