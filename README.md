# Jesse

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

Check out an [example](https://www.github.com/0x330a-public/jesse-bot) of how this library can be used in action