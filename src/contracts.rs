use crate::contracts::IIdGateway::IIdGatewayEvents;
use alloy::providers::Provider;
use alloy::signers::Signer;
use alloy::sol_types::{eip712_domain, Eip712Domain, SolEventInterface, SolStruct, SolValue};
use alloy::transports::http::Http;
use alloy::sol;
use alloy_primitives::{address, Address, Bytes, Signature, B256, U256};
use eyre::{bail, eyre, Result};
use op_alloy_network::Optimism;
use reqwest::Client;
use std::time::SystemTime;

sol! {
    
    /// to encode eip712 data addFor call
    #[derive(Debug)]
    struct Add {
        address owner;
        uint32 keyType;
        bytes key;
        uint8 metadataType;
        bytes metadata;
        uint256 nonce;
        uint256 deadline;
    }
    
    /// to encode to eip712 data registerFor call
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
    interface Nonces {
        /**
        * @dev Returns the next unused nonce for an address.
        */
        function nonces(address owner) public view virtual returns (uint256);
    }

    #[sol(rpc)]
    interface IIdGateway is Nonces {
        
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
        * @notice Register a new Farcaster ID (fid) to any address. A signed message from the address
        *         must be provided which approves both the to and the recovery. The address must not
        *         have an fid.
        *
        * @param to       Address which will own the fid.
        * @param recovery Address which can recover the fid. Set to zero to disable recovery.
        * @param deadline Expiration timestamp of the signature.
        * @param sig      EIP-712 Register signature signed by the to address.
        *
        * @return fid registered FID.
        */
        function registerFor(
            address to,
            address recovery,
            uint256 deadline,
            bytes calldata sig
        ) external payable returns (uint256 fid, uint256 overpayment);
    
        /**
         * @notice Register a new Farcaster ID (fid) to any address and rent additional storage.
         *         A signed message from the address must be provided which approves both the to
         *         and the recovery. The address must not have an fid.
         *
         * @param to           Address which will own the fid.
         * @param recovery     Address which can recover the fid. Set to zero to disable recovery.
         * @param deadline     Expiration timestamp of the signature.
         * @param sig          EIP-712 Register signature signed by the to address.
         * @param extraStorage Number of additional storage units to rent.
         *
         * @return fid registered FID.
         */
        function registerFor(
            address to,
            address recovery,
            uint256 deadline,
            bytes calldata sig,
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
    interface IIdRegistry is Nonces {
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
    contract IKeyGateway is Nonces {
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

const KEY_GATEWAY_DOMAIN: Eip712Domain = eip712_domain! {
    name: "Farcaster KeyGateway",
    version: "1",
    chain_id: 10,
    verifying_contract: KEY_GATEWAY_ADDRESS,
};

/// Generates bytes of a SignedKeyRequest to include as the metadata signature parameter
pub async fn sign_key_metadata<T: Signer + Sync + Send>(signer: &T, request_fid: u64, deadline: u64, signer_public_key: [u8; 32]) -> Result<Signature> {
    let request = SignedKeyRequest {
        requestFid: U256::from(request_fid),
        key: Bytes::from(signer_public_key),
        deadline: U256::from(deadline),
    };

    let signature = signer.sign_typed_data(&request, &KEY_REQUEST_VALIDATOR_DOMAIN).await?;

    Ok(signature)
}

/// Get the current nonce for a given address and user, address being probably [KeyGateway] or [IdGateway]
pub async fn get_nonce(fid_owner: Address, key_or_id_gateway: Address, provider: &impl Provider<Http<Client>, Optimism>) -> Result<u64> {
    let nonce_impl = Nonces::new(key_or_id_gateway, provider);
    let nonce = nonce_impl.nonces(fid_owner).call().await?;
    Ok(nonce._0.to())
}

/// Generates the `Register` signing hash
///
/// Used for calling registerFor with parameters from a user, including the signature of this hash
pub fn register_sign_hash(owner: Address, recovery: Option<Address>, nonce: u64, deadline: u64) -> Result<B256> {
    let register_struct = Register {
        to: owner,
        recovery: recovery.unwrap_or_default(),
        nonce: U256::from(nonce),
        deadline: U256::from(deadline),
    };

    Ok(register_struct.eip712_signing_hash(&ID_GATEWAY_DOMAIN))
}

/// Designed to be used by wrapping / proving a SignedKeyRequest's hash has been signed by the request_signer which owns request_fid
/// deadlines must match signed data and this metadata and be in the future from when the block is confirmed
pub fn sign_key_request_metadata(request_fid: u64, request_signer: Address, signed_key_request_signature: Signature, deadline: u64) -> Result<SignedKeyRequestMetadata> {
    Ok(SignedKeyRequestMetadata {
        requestSigner: request_signer,
        requestFid: U256::from(request_fid),
        signature: Bytes::from(signed_key_request_signature.as_bytes()),
        deadline: U256::from(deadline),
    })
}

/// Generate the EIP-712 signing hash of a SignedKeyRequest
/// to be signed and wrapped into a SignedKeyRequestMetadata object via [sign_key_request_metadata]
///
/// Returns the B256 / 32 byte EIP-712 hash bound to the KeyRequestValidator's domain
pub fn sign_key_request_sign_hash(request_fid: u64, deadline: u64, signer_public_key: [u8; 32]) -> B256 {
    let request = SignedKeyRequest {
        requestFid: U256::from(request_fid),
        key: Bytes::from(signer_public_key),
        deadline: U256::from(deadline),
    };

    request.eip712_signing_hash(&KEY_REQUEST_VALIDATOR_DOMAIN)
}

/// Generate the EIP-712 signing hash of an [Add] typehash
/// to be signed and passed into the addFor parameter of the [KeyGateway]
pub fn key_add_sign_hash(owner: Address, key_bytes: [u8; 32], metadata: SignedKeyRequestMetadata, nonce: u64, deadline: u64) -> B256 {
    let add_struct = Add {
        owner,
        keyType: ED25519_KEY_TYPE,
        key: Bytes::from(key_bytes),
        metadataType: METADATA_TYPE_SIGNED,
        metadata: Bytes::from(metadata.abi_encode()),
        nonce: U256::from(nonce),
        deadline: U256::from(deadline),
    };

    add_struct.eip712_signing_hash(&KEY_GATEWAY_DOMAIN)
}

const ED25519_KEY_TYPE: u32 = 1;
const METADATA_TYPE_SIGNED: u8 = 1;

pub fn one_hour_deadline() -> Result<u64> {
    Ok(SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_secs() + 3600) // one hour deadline?
}

/// Add a key to the user's fid calling the [IKeyGateway]'s `add(uint32 keyType, bytes calldata key, uint8 metadataType, bytes calldata metadata)` function
///
/// Assumes the provider can sign as well, external signing SOON tm
pub async fn add_key<T: Signer + Sync + Send>(owner: Address, signer_public_key: [u8; 32], signer: &T, provider: &impl Provider<Http<Client>, Optimism>) -> Result<()> {
    let fid = fid_of(owner, provider).await?;

    let deadline = one_hour_deadline()?;

    let key_metadata_signature = sign_key_metadata(signer, fid, deadline, signer_public_key).await?;

    let metadata = SignedKeyRequestMetadata {
        requestFid: U256::from(fid),
        requestSigner: owner,
        signature: Bytes::from(key_metadata_signature.as_bytes()),
        deadline: U256::from(deadline),
    };

    let key_gateway = IKeyGateway::new(KEY_GATEWAY_ADDRESS, provider);

    let pending = key_gateway.add(
        ED25519_KEY_TYPE,
        Bytes::from(signer_public_key.abi_encode_packed()),
        METADATA_TYPE_SIGNED,
        Bytes::from(metadata.abi_encode()),
    ).send().await?;
    let _tx_hash = pending.watch().await?;
    Ok(())
}

/// Same as [add_key] except designed to be called from a provider signer of a different account,
/// letting you add a key for someone that doesn't want to pay TX fees, the key gateway companion to [register_fid_for]
pub async fn add_key_for(owner: Address, deadline: u64, signature: Signature, key_bytes: [u8; 32], signed_key_request_metadata: SignedKeyRequestMetadata, provider: &impl Provider<Http<Client>, Optimism>) -> Result<()> {
    let key_gateway = IKeyGateway::new(KEY_GATEWAY_ADDRESS, provider);

    let pending = key_gateway.addFor(
        owner,
        ED25519_KEY_TYPE,
        Bytes::from(key_bytes.abi_encode_packed()),
        METADATA_TYPE_SIGNED,
        Bytes::from(signed_key_request_metadata.abi_encode()),
        U256::from(deadline),
        Bytes::from(signature.as_bytes()),
    ).into_transaction_request();

    let pending = provider.send_transaction(pending).await?;

    let _tx_hash = pending.watch().await?;
    Ok(())
}

/// get the owner's fid that they are registered as, or none if 0x0
pub async fn fid_of(owner: Address, provider: &impl Provider<Http<Client>, Optimism>) -> Result<u64> {
    let registry = IIdRegistry::new(ID_REGISTRY_ADDRESS, provider);
    let fid = registry.idOf(owner).call().await.map(|ret| ret.fid.to())?;
    Ok(fid)
}

/// Same as [register_fid] except designed to be called from a provider signer of a different account,
/// letting you register for someone that doesn't want to pay TX fees, the id gateway companion to [add_key_for]
pub async fn register_fid_for(for_owner: Address, recovery: Option<Address>, signature: Signature, deadline: u64, provider: &impl Provider<Http<Client>, Optimism>) -> Result<u64> {
    let id_gateway = IIdGateway::new(ID_GATEWAY_ADDRESS, provider);
    let price = id_gateway.price_0().call().await?._0;

    let tx = id_gateway.registerFor_0(
        for_owner,
        recovery.unwrap_or_default(),
        U256::from(deadline),
        Bytes::from(signature.as_bytes()),
    ).value(price)
        .send().await?
        .watch().await?;

    let receipt = provider.get_transaction_receipt(tx).await?.ok_or(eyre!("Missing transaction receipt"))?;

    if let Some(event) = receipt.inner.inner.logs().iter().find_map(|l| IIdGatewayEvents::decode_log(&l.inner, true).ok()) {
        match event.data {
            IIdGatewayEvents::Register(event) => Ok(event.id.to())
        }
    } else {
        bail!("No id registration log")
    }
}

/// sign and broadcast a register transaction, returning the signer's new fid
/// Errors here could indicate any of the [IIdRegistryErrors] (currently unaccounted for)
pub async fn register_fid(recovery_option: Option<Address>, provider: &impl Provider<Http<Client>, Optimism>) -> Result<u64> {

    // get the price for 1 storage on register
    let id_gateway = IIdGateway::new(ID_GATEWAY_ADDRESS, provider);

    let price = id_gateway.price_0().call().await?._0;

    let request = id_gateway.register_0(recovery_option.unwrap_or_default())
        .value(price)
        .send().await?;
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
    use crate::contracts::Nonces::NoncesInstance;
    use crate::contracts::{add_key, add_key_for, register_sign_hash, register_fid, register_fid_for, ID_GATEWAY_ADDRESS, KEY_GATEWAY_ADDRESS};
    use crate::{key_add_sign_hash, one_hour_deadline, sign_key_request_metadata, sign_key_request_sign_hash};
    use alloy::signers::local::PrivateKeySigner;
    use alloy::signers::Signer;
    use alloy_primitives::utils::parse_ether;
    use alloy_provider::ext::AnvilApi;
    use alloy_provider::network::EthereumWallet;
    use alloy_provider::ProviderBuilder;
    use ed25519_dalek::ed25519::signature::rand_core::OsRng;
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use eyre::Result;
    use op_alloy_network::Optimism;

    #[tokio::test]
    async fn test_basic_anvil_register_add() -> Result<()> {
        let app_signer = PrivateKeySigner::random();
        let app_wallet = EthereumWallet::from(app_signer.clone());

        let rpc_url = "http://127.0.0.1:8545"; // anvil forked op mainnet

        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(app_wallet.clone())
            .network::<Optimism>()
            .on_http(rpc_url.parse()?);

        let app_address = app_signer.address();

        provider.anvil_set_balance(app_address, parse_ether("1")?).await?;

        let app_fid = register_fid(None, &provider).await?;

        // get an ed25519 key for this test
        // (I don't think it's actually verified on-chain as ed25519 but oh well)
        let sk = SigningKey::generate(&mut OsRng);
        let pk = VerifyingKey::from(&sk);
        let pub_bytes = pk.to_bytes();

        add_key(app_address, pub_bytes, &app_signer, &provider).await?;

        Ok(())
    }


    #[tokio::test]
    async fn test_basic_anvil_register_add_for() -> Result<()> {
        let app_signer = PrivateKeySigner::random();
        let app_wallet = EthereumWallet::from(app_signer.clone());

        let user_signer = PrivateKeySigner::random();

        let rpc_url = "http://127.0.0.1:8545"; // anvil forked op mainnet

        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(app_wallet.clone())
            .network::<Optimism>()
            .on_http(rpc_url.parse()?);

        let app_address = app_signer.address();
        let user_address = user_signer.address();

        provider.anvil_set_balance(app_address, parse_ether("1")?).await?;

        let gateway_nonce = NoncesInstance::new(ID_GATEWAY_ADDRESS, &provider);

        // current user_address nonce for IdGateway
        let current_id_nonce = gateway_nonce.nonces(user_address).call().await?._0;

        let deadline = one_hour_deadline()?;

        let register_hash = register_sign_hash(user_address, None, current_id_nonce.to(), deadline)?;

        let register_signature = user_signer.sign_hash(&register_hash).await?;

        let fid = register_fid_for(user_address, None, register_signature, deadline, &provider).await?;

        // get an ed25519 key for this test
        // (I don't think it's actually verified on-chain as ed25519 but oh well)
        let sk = SigningKey::generate(&mut OsRng);
        let pk = VerifyingKey::from(&sk);
        let pub_bytes = pk.to_bytes();

        let key_gateway_nonce = NoncesInstance::new(KEY_GATEWAY_ADDRESS, &provider);
        let current_key_nonce = key_gateway_nonce.nonces(user_address).call().await?._0;

        let metadata_hash = sign_key_request_sign_hash(fid, deadline, pub_bytes);

        let metadata_sig = user_signer.sign_hash(&metadata_hash).await?;

        let metadata = sign_key_request_metadata(fid, user_address, metadata_sig, deadline)?;
        let add_hash = key_add_sign_hash(user_address, pub_bytes, metadata.clone(), current_key_nonce.to(), deadline);

        let add_signature = user_signer.sign_hash(&add_hash).await?;

        add_key_for(user_address, deadline, add_signature, pub_bytes, metadata, &provider).await?;

        Ok(())
    }
}
