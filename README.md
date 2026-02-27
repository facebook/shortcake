# shortcake

[![Rust CI](https://github.com/facebook/shortcake/actions/workflows/main.yml/badge.svg)](https://github.com/facebook/shortcake/actions/workflows/main.yml)
[![crates.io](https://img.shields.io/crates/v/shortcake.svg)](https://crates.io/crates/shortcake)
[![docs.rs](https://docs.rs/shortcake/badge.svg)](https://docs.rs/shortcake)

A generic, `#![no_std]`-compatible Rust implementation of the
Pasini-Vaudenay 3-move SAS-based authenticated key agreement protocol.

## Overview

This crate implements a short authenticated strings (SAS) protocol for
establishing a shared secret between two parties (Initiator and Responder)
with human verification of a short code.

The protocol is generic over a [`CipherSuite`](https://docs.rs/shortcake/latest/shortcake/trait.CipherSuite.html)
that bundles a KEM and hash function.

## Features

- `x25519-sha256` — Ready-to-use ciphersuite using X25519 and SHA-256
- `mlkem768-sha256` — Post-quantum ciphersuite using ML-KEM-768 (FIPS 203) and SHA-256
- `std` — Enable `std::error::Error` impl for the error type (disabled by default for `no_std`)

## Installation

```toml
[dependencies]
shortcake = { version = "0.1", features = ["x25519-sha256"] }
```

## Example

See [`examples/protocol.rs`](examples/protocol.rs) for a full 3-move protocol
demo. Run it with:

```sh
cargo run --example protocol --features x25519-sha256
```

## Minimum Supported Rust Version

Rust **1.72** or higher.

## License

This project is licensed under either of

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

at your option.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
