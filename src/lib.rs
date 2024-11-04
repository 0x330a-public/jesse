mod warpcast;
mod contracts;

use alloy::network::EthereumWallet;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::transports::http::Http;
use eyre::Result;
use op_alloy_network::Optimism;
use reqwest::Client;

// Expose the basic onchain registration / add key / hash generation functions
pub use crate::contracts::{get_nonce,
                           key_add_sign_hash,
                           one_hour_deadline,
                           sign_key_metadata,
                           sign_key_request_metadata,
                           sign_key_request_sign_hash,
                           register_fid,
                           register_fid_for,
                           add_key,
                           add_key_for,
};
// Need this as a return
pub use crate::contracts::SignedKeyRequestMetadata;

pub fn default_provider(wallet: EthereumWallet) -> Result<impl Provider<Http<Client>, Optimism>> {
    Ok(
        ProviderBuilder::new()
            .with_recommended_fillers()
            .network::<Optimism>()
            .wallet(wallet)
            .on_http("https://mainnet.optimism.io".parse()?)
    )
}