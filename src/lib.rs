mod warpcast;
mod contracts;

use alloy::network::EthereumWallet;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::transports::http::Http;
pub use contracts::{register_fid, fid_of, sign_key_metadata};
use eyre::Result;
use op_alloy::network::Optimism;
use reqwest::Client;

pub fn default_provider(wallet: EthereumWallet) -> Result<impl Provider<Http<Client>,Optimism>> {
    Ok(
        ProviderBuilder::new()
            .with_recommended_fillers()
            .network::<Optimism>()
            .wallet(wallet)
            .on_http("https://mainnet.optimism.io".parse()?)
    )
}