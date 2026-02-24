## shortcake ![Build Status](https://github.com/kevinlewi/shortcake/actions/workflows/ci.yml/badge.svg)

A SAS-based (Short Authentication String) authenticated key exchange protocol.

**Warning: This crate has not been audited. Use at your own risk.**

Overview
--------

`shortcake` (**SHORT** **C**ode **A**uthenticated **K**ey **E**xchange)
implements a 3-message authenticated key exchange protocol based on
the Pasini-Vaudenay (2006) message cross-authentication scheme. The
protocol allows two parties to establish a shared secret over an untrusted
channel, with authentication provided by a short authentication string
(SAS) that users compare out-of-band.

The commitment scheme prevents an attacker from adaptively choosing a
public key after observing the other party's key, and the SAS ensures
that both parties can detect any man-in-the-middle attack with
probability 1 - 2^{-40} per attempt.

Documentation
-------------

The API can be found [here](https://docs.rs/shortcake).

Installation
------------

Add the following to your `Cargo.toml`:

```toml
[dependencies]
shortcake = "0.1.0-pre.1"
```

Usage
-----

```rust
use shortcake::{Initiator, Responder};
use rand::rngs::OsRng;

let mut rng = OsRng;

// Step 1: Initiator starts the protocol
let (msg1, initiator) = Initiator::start(&mut rng);
// --> send msg1 to responder

// Step 2: Responder processes msg1 and responds
let (msg2, responder) = Responder::respond(&msg1, &mut rng).unwrap();
// --> send msg2 to initiator

// Step 3: Initiator completes and produces msg3
let (msg3, initiator_output) = initiator.finish(&msg2).unwrap();
// --> send msg3 to responder

// Step 4: Responder verifies commitment and completes
let responder_output = responder.finish(&msg3).unwrap();

// Both parties compare SAS out-of-band
assert_eq!(initiator_output.sas, responder_output.sas);

// After SAS verification, both have the same shared secret
assert_eq!(initiator_output.shared_secret, responder_output.shared_secret);
```

Protocol
--------

```text
Initiator                                   Responder
    |                                           |
    |  1. MessageOne { pk_I, commitment }       |
    |------------------------------------------>|
    |                                           |
    |  2. MessageTwo { pk_R, nonce_R }          |
    |<------------------------------------------|
    |                                           |
    |  3. MessageThree { nonce_I }              |
    |------------------------------------------>|
    |                                           |
    |  [Both compute SAS and shared secret]     |
    |  [Users verify SAS match out-of-band]     |
```

Where:
- `commitment = SHA-256(pk_I || nonce_I)` binds the initiator to their
  public key before seeing the responder's key
- `SAS = XOR(nonce_R, SHA-256(nonce_I || pk_R))` truncated to 40 bits
- `shared_secret = HKDF-SHA256(ECDH(sk, pk), transcript)` derives
  key material bound to the full protocol transcript

Contributors
------------

- Kevin Lewi ([kevinlewi](https://github.com/kevinlewi))

### References

- S. Pasini and S. Vaudenay, "An Optimal Non-Interactive Message
  Authentication Protocol," CT-RSA 2006.

License
-------

This project is dual-licensed under either the [MIT](LICENSE-MIT) or
[Apache 2.0](LICENSE-APACHE) license, at your option.
