# Jesse

![crates.io](https://img.shields.io/crates/v/jesse.svg)

We need to cook

**Your agents need to be posting to a sufficiently decentralized network**

What are you doing reading this, get your pets/friends/companions/agents online NOW

### Concept

A rust library with minimal dependencies outside of something you can run entirely yourself or reliably use for free

- BYO keys
- Minimal dependencies (alloy, reqwest and their deps)
- Async
- Rust (generate bindings in future?)
- Don't overthink it
- Sign using alloy or externally

### Goals

Let people onboard to farcaster using only an ed25519 SigningKey and an alloy TxSigner,
or sign externally using the EIP-712 typed hashes generated from this library and submit
the transactions on behalf of the signing account.

Use [fatline-rs](https://www.github.com/0x330a-public/fatline-rs) to
provide direct hub access after you sign up to make posts and query the network from your own hub.

### Usage

Check out an [example](https://github.com/0x330a-public/jesse-bot/blob/master/src/main.rs#L64-L99) of how this library can be used in action

The basic flow for signing up your own ethereum signer and adding a key would be something like:
```rust
fn main() -> Result<()> {
    // get our ed25519 signing keys
    let ed25519_key = SigningKey::generate(&mut OsRng);
    let ed25519_pub = VerifyingKey::from(&ed25519_key);
    let pub_key_bytes = ed25519_pub.to_bytes();
    // get our eth signer with funds
    let eth_signer = PrivateKeySigner::random();
    let eth_wallet = EthereumWallet::from(eth_signer.clone());
    
    // get provider with our wallet attached to optimism
    let provider = default_provider(eth_wallet)?;
    
    let eth_address = eth_signer.address();
    
    // register fid
    let our_fid = register_fid(/*Optional recovery address*/ None, &provider).await?;
    
    // add ed25519 key
    add_key(eth_address, pub_key_bytes, &eth_signer, &provider).await?;
    
    // ... post or do something else
    Ok(())
}
```