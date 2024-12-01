#![deny(clippy::all)]

#[macro_use]
extern crate napi_derive;

use alloy::hex;
use alloy::network::EthereumWallet;
use alloy::primitives::Address;
use alloy::signers::local::coins_bip39::English;
use alloy::signers::local::{MnemonicBuilder, PrivateKeySigner};
use napi::Error;
use napi::Status::{GenericFailure, InvalidArg};
use std::str::FromStr;
use std::time::SystemTime;
use alloy::signers::Signer;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum JesseError {
    #[error("Invalid mnemonic supplied")]
    InvalidMnemonic,
    #[error("Error serializing a hex value")]
    HexSerialization,
    #[error("Generic error pls implement a specific one here")]
    Generic,
    #[error("Already registered")]
    AlreadyRegistered,
}

impl From<JesseError> for Error {
    fn from(value: JesseError) -> Self {
        match value {
            JesseError::HexSerialization => Error::new(InvalidArg, value),
            JesseError::Generic => Error::new(GenericFailure, value),
            JesseError::AlreadyRegistered => Error::new(GenericFailure, value),
            JesseError::InvalidMnemonic => Error::new(InvalidArg, value)
        }
    }
}

fn parse_address(address: String) -> Result<Address, Error> {
    hex::decode(address.replace("0x", ""))
        .map(|vec| Address::from_slice(&vec[..]))
        .map_err(|_| Error::from(JesseError::HexSerialization))
}

fn parse_hex(hex_string: String) -> Result<Vec<u8>, Error> {
    hex::decode(hex_string.replace("0x", ""))
        .map_err(|_| Error::from(JesseError::HexSerialization))
}

#[napi]
pub async fn register_fid(
    account: &Account,
    recovery_address: Option<String>,
) -> Result<u32, Error> {

    let wallet = EthereumWallet::new(account.private_key.clone());

    let provider = jesse::default_provider(wallet)
        .map_err(|_| Error::from(JesseError::Generic))?;

    let recovery_address = if let Some(address) = recovery_address {
        Some(parse_address(address)?)
    } else {
        None
    };

    let fid = jesse::register_fid(recovery_address, &provider).await
        .map_err(|_| Error::from(JesseError::Generic))?;

    Ok(fid as u32)
}

#[napi]
pub async fn add_key(
    account: &Account,
    key_hex: String
) -> Result<bool, Error> {
    let key: [u8;32] = {
        let decoded_key = parse_hex(key_hex)?;
        let mut key_bytes = [0u8;32];
        key_bytes.copy_from_slice(&decoded_key[..]);
        key_bytes
    };

    let owner_address = account.private_key.address();

    let provider = jesse::default_provider(EthereumWallet::new(account.private_key.clone()))
        .map_err(|_| Error::from(JesseError::Generic))?;

    jesse::add_key(owner_address, key, &account.private_key, &provider).await
        .map_err(|_| Error::from(JesseError::Generic))?;

    Ok(true)
}

#[napi]
pub async fn transfer_fname(account: &Account, fname: String, to_fid: u32) -> Result<bool, Error> {
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let owner_address = account.private_key.address();

    let provider = jesse::default_provider(EthereumWallet::new(account.private_key.clone()))
        .map_err(|_| Error::from(JesseError::Generic))?;

    let signature = jesse::fname_sign_hash(owner_address, fname.clone(), timestamp);
    let our_fid = jesse::fid_of(owner_address, &provider).await
        .map_err(|_| Error::from(JesseError::Generic))?;
    let signature = account.private_key.sign_hash(&signature).await
        .map_err(|_| Error::from(JesseError::Generic))?;

    jesse::transfer_fname(fname, signature, Some(our_fid), to_fid as u64, owner_address, timestamp).await
        .map_err(|_| Error::from(JesseError::Generic))
}

#[napi]
pub async fn register_fname(account: &Account, fname: String) -> Result<bool, Error> {
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let owner_address = account.private_key.address();

    let provider = jesse::default_provider(EthereumWallet::new(account.private_key.clone()))
        .map_err(|_| Error::from(JesseError::Generic))?;

    let signature = jesse::fname_sign_hash(owner_address, fname.clone(), timestamp);
    let our_fid = jesse::fid_of(owner_address, &provider).await
        .map_err(|_| Error::from(JesseError::Generic))?;
    let signature = account.private_key.sign_hash(&signature).await
        .map_err(|_| Error::from(JesseError::Generic))?;

    jesse::register_fname(fname, signature, our_fid, owner_address, timestamp).await
        .map_err(|_| Error::from(JesseError::Generic))?;

    Ok(true)
}

#[napi]
/// Get the registered fid of an ethereum address, or 0 if it's unregistered
pub async fn fid_of_address(address_hex: String) -> Result<u32, Error> {

    let address = parse_address(address_hex)?;

    let public_provider = jesse::public_provider()
        .map_err(|_| Error::from(JesseError::Generic))?;

    let fid = jesse::fid_of(address, &public_provider).await
        .map_err(|_| Error::from(JesseError::Generic))?;

    Ok(fid as u32)
}

#[napi]
/// Return the owner of the fname as an optional fid (if it is owned)
pub async fn fid_of_fname(fname: String) -> Result<Option<u32>, Error> {

    let transfers: Vec<jesse::Transfer> = jesse::get_transfers_for_username(&fname)
        .await.map_err(|_| Error::from(JesseError::Generic))?;

    Ok(transfers.last().map(|transfer| transfer.to as u32))
}


#[napi]
/// Holder class for the signer that can be used in registration and fname related operations
pub struct Account {
    private_key: PrivateKeySigner
}

#[napi]
impl Account {

    #[napi(factory)]
    pub fn from_mnemonic(mnemonic: String) -> Result<Self, Error> {
        let mnemonic_signer = MnemonicBuilder::<English>::default()
            .phrase(mnemonic)
            .build()
            .map_err(|_| Error::from(JesseError::InvalidMnemonic))?;

        Ok(
            Self {
                private_key: mnemonic_signer
            }
        )
    }

    #[napi(factory)]
    pub fn from_private_key_hex(private_key_hex: String) -> Result<Self, Error> {
        let signer = PrivateKeySigner::from_str(private_key_hex.as_str())
            .map_err(|_| Error::from(JesseError::HexSerialization))?;

        Ok(
            Self {
                private_key: signer
            }
        )
    }
}