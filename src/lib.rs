mod warpcast;
mod contracts;

use alloy::network::EthereumWallet;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::transports::http::Http;
use eyre::Result;
use op_alloy_network::Optimism;
use reqwest::Client;

// Need this as a return
pub use crate::contracts::SignedKeyRequestMetadata;
// Expose the basic onchain registration / add key / hash generation functions
pub use crate::contracts::{add_key,
                           add_key_for,
                           get_nonce,
                           key_add_sign_hash,
                           one_hour_deadline,
                           register_fid,
                           register_fid_for,
                           register_sign_hash,
                           sign_key_metadata,
                           sign_key_request_metadata,
                           sign_key_request_sign_hash,
                           build_register_fid_for,
                           build_add_key_for
};

// Expose the Warpcast fname specific methods
pub use crate::warpcast::{register_with_warpcast,
                          fname_sign_hash,
                          get_transfers_for_username,
                          get_transfers_for_fid,
                          Transfer
};

pub use crate::contracts::{ID_GATEWAY_ADDRESS, KEY_GATEWAY_ADDRESS};

pub fn default_provider(wallet: EthereumWallet) -> Result<impl Provider<Http<Client>, Optimism>> {
    Ok(
        ProviderBuilder::new()
            .with_recommended_fillers()
            .network::<Optimism>()
            .wallet(wallet)
            .on_http("https://mainnet.optimism.io".parse()?)
    )
}