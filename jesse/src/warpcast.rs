use alloy::sol;
use alloy::sol_types::{eip712_domain, Eip712Domain, SolStruct};
use alloy_primitives::{address, Address, Bytes, PrimitiveSignature, B256, U256};
use eyre::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};

const BASE_FNAME_URL: &'static str = "https://fnames.farcaster.xyz/transfers";

sol! {
    #[derive(Debug)]
    struct UserNameProof {
        string name;
        uint256 timestamp;
        address owner;
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
struct TransferResponse {
    pub transfers: Vec<Transfer>
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Transfer {
    pub id: u64,
    pub timestamp: u64,
    pub username: String,
    pub owner: Address,
    pub from: u64,
    pub to: u64,
    pub user_signature: Bytes,
    pub server_signature: Bytes
}

#[derive(Serialize)]
struct UsernameClaim {
    name: String,
    from: u64,
    to: u64,
    fid: u64,
    owner: Address,
    timestamp: u64,
    signature: Bytes
}

const FNAME_DOMAIN: Eip712Domain = eip712_domain! {
    name: "Farcaster name verification",
    version: "1",
    chain_id: 1,
    verifying_contract: address!("e3Be01D99bAa8dB9905b33a3cA391238234B79D1"),
};

/// Generate the signature hash to be signed by an alloy [alloy::signers::Signer] instance
///
/// This could maybe technically be used to claim ownership of an ENS domain as well?
pub fn fname_sign_hash(owner: Address, desired_username: String, timestamp: u64) -> B256 {
    let proof_struct = UserNameProof {
        name: desired_username,
        owner,
        timestamp: U256::from(timestamp)
    };

    proof_struct.eip712_signing_hash(&FNAME_DOMAIN)
}

/// Get the list of username transfers for a specific fid if they exist
pub async fn get_transfers_for_fid(for_fid: u64) -> Result<Vec<Transfer>> {
    let reqwest = Client::new();
    let results: TransferResponse = reqwest.get(BASE_FNAME_URL)
        .query(&[("fid", for_fid)])
        .send().await?.json().await?;
    Ok(results.transfers)
}

/// Get the list of username transfers for a specific name if they exist
pub async fn get_transfers_for_username(name: &str) -> Result<Vec<Transfer>> {
    let reqwest = Client::new();
    let results: TransferResponse = reqwest.get(BASE_FNAME_URL)
        .query(&[("name", name)])
        .send().await?.json().await?;
    Ok(results.transfers)
}

/// Transfer the fname using Warpcast's server, letting the new user 'claim' the name by updating their user profile data
pub async fn transfer_fname(
    username: String,
    user_name_proof: PrimitiveSignature,
    from_fid: Option<u64>,
    for_fid: u64,
    owner: Address,
    timestamp: u64) -> Result<bool> {

    let claim = UsernameClaim {
        name: username,
        from: from_fid.unwrap_or_default(), // 0 default if None (equivalent to claiming)
        to: for_fid,
        fid: for_fid,
        owner,
        timestamp,
        signature: Bytes::from(user_name_proof.as_bytes()),
    };

    let reqwest = Client::new();
    let results = reqwest.post(BASE_FNAME_URL)
        .json(&claim)
        .send().await?;

    Ok(results.status().is_success())

}

/// Register the name with Warpcast's server, before submitting a username update to 'claim' the name
/// by updating your user profile data
pub async fn register_fname(
    username: String,
    user_name_proof: PrimitiveSignature,
    for_fid: u64,
    owner: Address,
    timestamp: u64) -> Result<bool> {

    transfer_fname(
        username,
        user_name_proof,
        None, // equivalent to transfer from_fid = 0
        for_fid,
        owner,
        timestamp
    ).await
}


#[cfg(test)]
mod test {
    use crate::{get_transfers_for_fid, get_transfers_for_username};
    use eyre::Result;

    #[tokio::test]
    pub async fn test_claims_by_various_methods() -> Result<()> {
        let username_transfer = get_transfers_for_username("harris-").await?;
        let fid_transfer = get_transfers_for_fid(402621).await?;
        assert_eq!(username_transfer.len(), 1);
        assert_eq!(fid_transfer.len(), 1);
        assert_eq!(fid_transfer[0], username_transfer[0]);
        Ok(())
    }

    // idk how I'm gonna test username transfers with prod

}