use crate::contracts::IIdGateway::IIdGatewayEvents;
use alloy::providers::Provider;
use alloy::signers::Signer;
use alloy::sol_types::{eip712_domain, Eip712Domain, SolEventInterface, SolValue};
use alloy::transports::http::Http;
use alloy::sol;
use alloy_primitives::{address, Address, Bytes, Signature, U256};
use eyre::{bail, eyre, Result};
use op_alloy::network::Optimism;
use reqwest::Client;
use std::time::SystemTime;

sol! {
    /// to encode to eip712 data
    #[derive(Debug, Default)]
    struct Register {
        address to;
        address recovery;
        uint256 nonce;
        uint256 deadline;
    }

    #[derive(Debug, Default)]
    /// to encode to eip712 data, for add parameters
    struct SignedKeyRequestMetadata {
        uint256 requestFid;
        address requestSigner;
        bytes signature;
        uint256 deadline;
    }

    #[derive(Debug, Default)]
    /// to encode to eip712 data
    struct SignedKeyRequest {
        uint256 requestFid;
        bytes key;
        uint256 deadline;
    }

    #[sol(rpc)]
    contract IIdGateway {
        /**
         * @notice Calculate the total price to register, equal to 1 storage unit.
         *
         * @return Total price in wei.
         */
        function price() external view returns (uint256);

        /**
         * @notice Calculate the total price to register, including additional storage.
         *
         * @param extraStorage Number of additional storage units to rent.
         *
         * @return Total price in wei.
         */
        function price(uint256 extraStorage) external view returns (uint256);

        /**
         * @notice Register a new Farcaster ID (fid) to the caller. The caller must not have an fid.
         *
         * @param recovery Address which can recover the fid. Set to zero to disable recovery.
         *
         * @return fid registered FID.
         */
        function register(address recovery) external payable returns (uint256 fid, uint256 overpayment);

        /**
         * @notice Register a new Farcaster ID (fid) to the caller and rent additional storage.
         *         The caller must not have an fid.
         *
         * @param recovery     Address which can recover the fid. Set to zero to disable recovery.
         * @param extraStorage Number of additional storage units to rent.
         *
         * @return fid registered FID.
         */
        function register(
            address recovery,
            uint256 extraStorage
        ) external payable returns (uint256 fid, uint256 overpayment);

        /**
        * @dev Emit an event when a new Farcaster ID is registered.
        *
        *      Hubs listen for this and update their address-to-fid mapping by adding `to` as the
        *      current owner of `id`. Hubs assume the invariants:
        *
        *      1. Two Register events can never emit with the same `id`
        *
        *      2. Two Register(alice, ..., ...) cannot emit unless a Transfer(alice, bob, ...) emits
        *          in between, where bob != alice.
        *
        * @param to       The custody address that owns the fid
        * @param id       The fid that was registered.
        * @param recovery The address that can initiate a recovery request for the fid.
        */
        #[derive(Debug)]
        event Register(address indexed to, uint256 indexed id, address recovery);
    }

    #[sol(rpc, abi)]
    contract IIdRegistry {
        #[derive(Debug)]
        /// @dev Revert when the caller does not have the authority to perform the action.
        error Unauthorized();

        /// @dev Revert when the caller must have an fid but does not have one.
        error HasNoId();

        /// @dev Revert when the destination must be empty but has an fid.
        error HasId();

        /**
         * @notice Maps each address to an fid, or zero if it does not own an fid.
         */
        function idOf(address owner) external view returns (uint256 fid);

        /**
         * @notice Maps each fid to the address that currently owns it.
         */
        function custodyOf(uint256 fid) external view returns (address owner);

        /**
         * @notice Maps each fid to an address that can initiate a recovery.
         */
        function recoveryOf(uint256 fid) external view returns (address recovery);
    }

    #[sol(rpc, abi)]
    contract IKeyGateway {
        /**
        * @notice Add a key associated with the caller's fid, setting the key state to ADDED.
        *
        * @param keyType      The key's numeric keyType.
        * @param key          Bytes of the key to add.
        * @param metadataType Metadata type ID.
        * @param metadata     Metadata about the key, which is not stored and only emitted in an event.
        */
        function add(uint32 keyType, bytes calldata key, uint8 metadataType, bytes calldata metadata) external;

        /**
         * @notice Add a key on behalf of another fid owner, setting the key state to ADDED.
         *         caller must supply a valid EIP-712 Add signature from the fid owner.
         *
         * @param fidOwner     The fid owner address.
         * @param keyType      The key's numeric keyType.
         * @param key          Bytes of the key to add.
         * @param metadataType Metadata type ID.
         * @param metadata     Metadata about the key, which is not stored and only emitted in an event.
         * @param deadline     Deadline after which the signature expires.
         * @param sig          EIP-712 Add signature generated by fid owner.
         */
        function addFor(
            address fidOwner,
            uint32 keyType,
            bytes calldata key,
            uint8 metadataType,
            bytes calldata metadata,
            uint256 deadline,
            bytes calldata sig
        ) external;
    }

}

const ID_GATEWAY_ADDRESS: Address = address!("00000000Fc25870C6eD6b6c7E41Fb078b7656f69");
const ID_REGISTRY_ADDRESS: Address = address!("00000000Fc6c5F01Fc30151999387Bb99A9f489b");
const KEY_GATEWAY_ADDRESS: Address = address!("00000000fC56947c7E7183f8Ca4B62398CaAdf0B");

const ID_GATEWAY_DOMAIN: Eip712Domain = eip712_domain! {
    name: "Farcaster IdGateway",
    version: "1",
    chain_id: 10,
    verifying_contract: ID_GATEWAY_ADDRESS,
};

const KEY_REQUEST_VALIDATOR_DOMAIN: Eip712Domain = eip712_domain! {
    name: "Farcaster SignedKeyRequestValidator",
    version: "1",
    chain_id: 10,
    verifying_contract: address!("00000000FC700472606ED4fA22623Acf62c60553"),
};

/// Generates bytes of a SignedKeyRequest to include as the metadata signature parameter
pub async fn sign_key_metadata<T: Signer + Sync + Send>(signer: &T, request_fid: u64, deadline: u64, signer_public_key: [u8;32]) -> Result<Signature> {

    let request = SignedKeyRequest {
        requestFid: U256::from(request_fid),
        key: Bytes::from(signer_public_key),
        deadline: U256::from(deadline),
    };

    let signature = signer.sign_typed_data(&request, &KEY_REQUEST_VALIDATOR_DOMAIN).await?;

    Ok(signature)
}

/// Generates the `Add` key signature, different from the signed key request metadata, for a user
///
/// May be useful for adding a key to a fid as an Ethereum transaction from a different evm address!
pub async fn add_key_signature<T>(signer: &T, request_fid: u64, deadline: u64, signer_public_key: [u8; 32]) -> Result<[u8; 65]>
    where T: Signer + Send + Sync {
    todo!()
}

const ED_25519_KEY_TYPE: u32 = 1;
const METADATA_TYPE_SIGNED: u8 = 1;

/// Add a key to the user's fid calling the [IKeyGateway]'s `add(uint32 keyType, bytes calldata key, uint8 metadataType, bytes calldata metadata)` function
///
/// Assumes the provider can sign as well, external signing SOON tm
pub async fn add_key<T: Signer + Sync + Send>(owner: Address, signer_public_key: [u8;32], signer: &T, provider: &impl Provider<Http<Client>, Optimism>) -> Result<()> {

    let fid = fid_of(owner, provider).await?;

    let deadline = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_secs() + 3600; // one hour deadline?

    let key_metadata_signature = sign_key_metadata(signer, fid, deadline, signer_public_key).await?;

    let metadata = SignedKeyRequestMetadata {
        requestFid: U256::from(fid),
        requestSigner: owner,
        signature: Bytes::from(key_metadata_signature.as_bytes()),
        deadline: U256::from(deadline),
    };

    let key_gateway = IKeyGateway::new(KEY_GATEWAY_ADDRESS, provider);

    let pending = key_gateway.add(
        ED_25519_KEY_TYPE,
        Bytes::from(signer_public_key.abi_encode_packed()),
        METADATA_TYPE_SIGNED,
        Bytes::from(metadata.abi_encode())
    ).send().await?;
    let _tx_hash = pending.watch().await?;
    Ok(())
}

/// get the owner's fid that they are registered as, or none if 0x0
pub async fn fid_of(owner: Address, provider: &impl Provider<Http<Client>, Optimism>) -> Result<u64> {
    let registry = IIdRegistry::new(ID_REGISTRY_ADDRESS, provider);
    let fid = registry.idOf(owner).call().await.map(|ret| ret.fid.to())?;
    Ok(fid)
}

/// sign and broadcast a register transaction, returning the signer's new fid
/// Errors here could indicate any of the [IIdRegistryErrors] (currently unaccounted for)
pub async fn register_fid(recovery_option: Option<Address>, provider: &impl Provider<Http<Client>, Optimism>) -> Result<u64> {

    let recovery_address = if let Some(address) = recovery_option {
        address
    } else {
        Address::ZERO
    };

    // get the price for 1 storage on register
    let id_gateway = IIdGateway::new(ID_GATEWAY_ADDRESS, provider);

    let price = id_gateway.price_0().call().await?._0;

    let request= id_gateway.register_0(recovery_address)
            .value(price);
    // idk if just anvil is broken but without this it was failing with an out of gas error
    let estimate:f64 = request.estimate_gas().await? as f64 * 2f64;
    let request = request
        .gas(estimate as u64).send().await?;
    let tx = request.watch().await?;
    let _ = provider.get_transaction_by_hash(tx).await?.ok_or(eyre!("Missing transaction"))?;
    let receipt = provider.get_transaction_receipt(tx).await?.ok_or(eyre!("Missing transaction receipt"))?;

    // would be good to handle specific errors here!

    if let Some(event) = receipt.inner.inner.logs().iter().find_map(|l| IIdGatewayEvents::decode_log(&l.inner, true).ok()) {
        match event.data {
            IIdGatewayEvents::Register(event) => Ok(event.id.to())
        }
    } else {
        bail!("No id registration log")
    }
}


#[cfg(test)]
mod tests {
    use crate::contracts::{add_key, register_fid};
    use alloy::hex;
    use alloy::signers::local::PrivateKeySigner;
    use alloy_primitives::utils::parse_ether;
    use alloy_provider::ext::AnvilApi;
    use alloy_provider::network::EthereumWallet;
    use alloy_provider::ProviderBuilder;
    use ed25519_dalek::ed25519::signature::rand_core::OsRng;
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use eyre::Result;
    use op_alloy::network::Optimism;

    #[tokio::test]
    async fn test_basic_anvil() -> Result<()> {

        let signer = PrivateKeySigner::random();

        let wallet = EthereumWallet::from(signer.clone());
        let rpc_url = "http://127.0.0.1:8545"; // anvil forked op mainnet

        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(wallet.clone())
            .network::<Optimism>()
            .on_http(rpc_url.parse()?);

        let owner_address = signer.address();

        provider.anvil_set_balance(owner_address, parse_ether("1")?).await?;
        provider.anvil_set_logging(true).await?;

        let fid = register_fid(None, &provider).await?;

        // get an ed25519 key for this test
        // (I don't think it's actually verified on-chain as ed25519 but oh well)
        let sk = SigningKey::generate(&mut OsRng);
        let pk = VerifyingKey::from(&sk);
        let pub_bytes = pk.to_bytes();

        println!("pub bytes: {}", hex::encode(pub_bytes));

        add_key(owner_address, pub_bytes, &signer, &provider).await?;

        println!("registered fid is: {fid}");
        println!("added key: {}", hex::encode(pub_bytes));
        Ok(())
    }

}
