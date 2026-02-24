// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! Core protocol implementation for the shortcake key exchange.

use core::fmt;

use digest::Digest;
use generic_array::typenum::Unsigned;
use generic_array::GenericArray;
use hkdf::Hkdf;
use hmac::SimpleHmac;
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::ciphersuite::{
    CipherSuite, HashOutputLen, KxSecretKey, PublicKeyLen, SasLen, SharedSecretLen,
};
use crate::errors::ShortcakeError;
use crate::key_exchange::KeyExchange;
use crate::messages::{MessageOne, MessageThree, MessageTwo};

/// The length of the derived shared secret in bytes.
pub const SHARED_SECRET_LENGTH: usize = 32;

/// Domain separator for commitment computation.
const COMMITMENT_DST: &[u8] = b"shortcake-v1 commitment";

/// Domain separator for SAS computation.
const SAS_DST: &[u8] = b"shortcake-v1 sas";

/// Domain separator for HKDF transcript hash (salt).
const TRANSCRIPT_DST: &[u8] = b"shortcake-v1 transcript";

/// Domain separator for HKDF shared secret derivation.
const HKDF_INFO: &[u8] = b"shortcake-v1 shared secret";

pub(crate) type Result<T> = core::result::Result<T, ShortcakeError>;

/// The output of a completed protocol execution.
///
/// Contains the short authentication string (SAS) for out-of-band
/// verification, and the shared secret for establishing encrypted
/// communication.
///
/// **Important**: The [`shared_secret`](Output::shared_secret) should only be
/// used after the user has verified that the SAS values match on both sides.
#[must_use]
pub struct Output<CS: CipherSuite> {
    sas: GenericArray<u8, SasLen<CS>>,
    shared_secret: [u8; SHARED_SECRET_LENGTH],
}

impl<CS: CipherSuite> Output<CS> {
    /// Returns the short authentication string (SAS).
    ///
    /// Both parties should display this value to the user for out-of-band
    /// comparison. If the values match, the key exchange is authenticated.
    pub fn sas(&self) -> &GenericArray<u8, SasLen<CS>> {
        &self.sas
    }

    /// Returns the derived shared secret.
    ///
    /// This value is identical for both parties after a successful protocol
    /// execution. It is derived from the ECDH shared secret using HKDF,
    /// with the protocol transcript bound into the derivation.
    pub fn shared_secret(&self) -> &[u8; SHARED_SECRET_LENGTH] {
        &self.shared_secret
    }
}

impl<CS: CipherSuite> fmt::Debug for Output<CS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Output")
            .field("sas", &self.sas)
            .field("shared_secret", &"[REDACTED]")
            .finish()
    }
}

impl<CS: CipherSuite> Zeroize for Output<CS> {
    fn zeroize(&mut self) {
        self.shared_secret.zeroize();
    }
}

impl<CS: CipherSuite> Drop for Output<CS> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Generates a random nonce of hash-output length for the given cipher suite.
fn random_nonce<CS: CipherSuite>(
    rng: &mut (impl CryptoRng + RngCore),
) -> GenericArray<u8, HashOutputLen<CS>> {
    let mut nonce = GenericArray::<u8, HashOutputLen<CS>>::default();
    rng.fill_bytes(nonce.as_mut_slice());
    nonce
}

/// The initiator's protocol state.
///
/// Created by [`Initiator::start()`] and consumed by [`Initiator::finish()`],
/// ensuring that the ephemeral secret key material cannot be reused.
pub struct Initiator<CS: CipherSuite> {
    secret_key: KxSecretKey<CS>,
    nonce: GenericArray<u8, HashOutputLen<CS>>,
}

impl<CS: CipherSuite> Initiator<CS> {
    /// Starts the protocol by generating an ephemeral key pair, a random
    /// nonce, and a commitment.
    ///
    /// Returns the first protocol message to send to the responder, along
    /// with the initiator state needed to complete the protocol.
    #[must_use]
    pub fn start(rng: &mut (impl CryptoRng + RngCore)) -> (MessageOne<CS>, Self) {
        let (secret_key, public_key) = CS::KeyExchange::generate_keypair(&mut *rng);

        let nonce = random_nonce::<CS>(&mut *rng);

        let commitment = compute_commitment::<CS>(&public_key, &nonce);

        let msg = MessageOne {
            public_key,
            commitment,
        };
        let state = Self { secret_key, nonce };

        (msg, state)
    }

    /// Completes the protocol from the initiator's side.
    ///
    /// Processes the responder's [`MessageTwo`], computes the SAS and shared
    /// secret, and produces [`MessageThree`] to send to the responder.
    ///
    /// # Errors
    ///
    /// Returns [`ShortcakeError::InvalidPublicKey`] if the responder's public
    /// key is invalid (e.g., all zeros, identical to the initiator's key, or
    /// results in a degenerate ECDH output).
    #[must_use = "the returned MessageThree must be sent to the responder"]
    pub fn finish(self, msg2: &MessageTwo<CS>) -> Result<(MessageThree<CS>, Output<CS>)> {
        let our_public_key = CS::KeyExchange::public_key(&self.secret_key);

        validate_public_key::<CS>(&msg2.public_key, &our_public_key)?;

        let sas = compute_sas::<CS>(&self.nonce, &msg2.nonce, &msg2.public_key);

        let mut dh_output = CS::KeyExchange::diffie_hellman(self.secret_key, &msg2.public_key)?;

        let shared_secret = derive_shared_secret::<CS>(
            &dh_output,
            &our_public_key,
            &msg2.public_key,
            &self.nonce,
            &msg2.nonce,
        );

        dh_output.zeroize();

        let msg3 = MessageThree::new(self.nonce);
        let output = Output { sas, shared_secret };

        Ok((msg3, output))
    }
}

/// The responder's protocol state.
///
/// Created by [`Responder::respond()`] and consumed by
/// [`Responder::finish()`], ensuring that the ephemeral secret key material
/// cannot be reused.
pub struct Responder<CS: CipherSuite> {
    secret_key: KxSecretKey<CS>,
    public_key: GenericArray<u8, PublicKeyLen<CS>>,
    nonce: GenericArray<u8, HashOutputLen<CS>>,
    initiator_public_key: GenericArray<u8, PublicKeyLen<CS>>,
    commitment: GenericArray<u8, HashOutputLen<CS>>,
}

impl<CS: CipherSuite> Responder<CS> {
    /// Processes the initiator's [`MessageOne`] and generates a response.
    ///
    /// Returns the second protocol message to send back to the initiator,
    /// along with the responder state needed to complete the protocol.
    ///
    /// # Errors
    ///
    /// Returns [`ShortcakeError::InvalidPublicKey`] if the initiator's public
    /// key is all zeros.
    #[must_use = "the returned MessageTwo must be sent to the initiator"]
    pub fn respond(
        msg1: &MessageOne<CS>,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<(MessageTwo<CS>, Self)> {
        CS::KeyExchange::validate_public_key(&msg1.public_key)?;

        let (secret_key, public_key) = CS::KeyExchange::generate_keypair(&mut *rng);

        let nonce = random_nonce::<CS>(&mut *rng);

        let msg = MessageTwo {
            public_key: public_key.clone(),
            nonce: nonce.clone(),
        };

        let state = Self {
            secret_key,
            public_key,
            nonce,
            initiator_public_key: msg1.public_key.clone(),
            commitment: msg1.commitment.clone(),
        };

        Ok((msg, state))
    }

    /// Completes the protocol from the responder's side.
    ///
    /// Processes the initiator's [`MessageThree`], verifies the commitment,
    /// and computes the SAS and shared secret.
    ///
    /// # Errors
    ///
    /// Returns [`ShortcakeError::InvalidCommitment`] if the commitment
    /// verification fails, indicating that the initiator's public key or
    /// nonce may have been tampered with.
    ///
    /// Returns [`ShortcakeError::InvalidPublicKey`] if the initiator's public
    /// key is identical to the responder's (reflection attack) or results in
    /// a degenerate ECDH output.
    #[must_use = "the returned Output must be used"]
    pub fn finish(self, msg3: &MessageThree<CS>) -> Result<Output<CS>> {
        // Verify the commitment: H(initiator_pk || initiator_nonce) == stored
        let expected = compute_commitment::<CS>(&self.initiator_public_key, &msg3.nonce);
        if expected
            .as_slice()
            .ct_eq(self.commitment.as_slice())
            .unwrap_u8()
            != 1
        {
            return Err(ShortcakeError::InvalidCommitment);
        }

        // Reject reflection attacks
        validate_public_key::<CS>(&self.initiator_public_key, &self.public_key)?;

        let sas = compute_sas::<CS>(&msg3.nonce, &self.nonce, &self.public_key);

        let mut dh_output =
            CS::KeyExchange::diffie_hellman(self.secret_key, &self.initiator_public_key)?;

        let shared_secret = derive_shared_secret::<CS>(
            &dh_output,
            &self.initiator_public_key,
            &self.public_key,
            &msg3.nonce,
            &self.nonce,
        );

        dh_output.zeroize();

        Ok(Output { sas, shared_secret })
    }
}

/// Computes the hash commitment: `H("shortcake-v1 commitment" || public_key || nonce)`.
fn compute_commitment<CS: CipherSuite>(
    public_key: &GenericArray<u8, PublicKeyLen<CS>>,
    nonce: &GenericArray<u8, HashOutputLen<CS>>,
) -> GenericArray<u8, HashOutputLen<CS>> {
    let mut hasher = CS::Hash::new();
    hasher.update(COMMITMENT_DST);
    hasher.update(public_key);
    hasher.update(nonce);
    hasher.finalize()
}

/// Computes the SAS:
///   `XOR(responder_nonce, H("shortcake-v1 sas" || initiator_nonce || responder_pk))`
/// truncated to `CS::SasLength` bytes.
fn compute_sas<CS: CipherSuite>(
    initiator_nonce: &GenericArray<u8, HashOutputLen<CS>>,
    responder_nonce: &GenericArray<u8, HashOutputLen<CS>>,
    responder_public_key: &GenericArray<u8, PublicKeyLen<CS>>,
) -> GenericArray<u8, SasLen<CS>> {
    assert!(
        SasLen::<CS>::USIZE <= HashOutputLen::<CS>::USIZE,
        "SAS length ({}) must not exceed hash output length ({})",
        SasLen::<CS>::USIZE,
        HashOutputLen::<CS>::USIZE,
    );

    let mut hasher = CS::Hash::new();
    hasher.update(SAS_DST);
    hasher.update(initiator_nonce);
    hasher.update(responder_public_key);
    let hash = hasher.finalize();

    let mut sas = GenericArray::<u8, SasLen<CS>>::default();
    for i in 0..SasLen::<CS>::USIZE {
        sas[i] = responder_nonce[i] ^ hash[i];
    }
    sas
}

/// Derives the shared secret using HKDF.
///
/// The salt is the hash of the protocol transcript (domain separator, both
/// public keys, and both nonces), ensuring the shared secret is bound to the
/// specific exchange without requiring allocation.
fn derive_shared_secret<CS: CipherSuite>(
    dh_output: &GenericArray<u8, SharedSecretLen<CS>>,
    initiator_public_key: &GenericArray<u8, PublicKeyLen<CS>>,
    responder_public_key: &GenericArray<u8, PublicKeyLen<CS>>,
    initiator_nonce: &GenericArray<u8, HashOutputLen<CS>>,
    responder_nonce: &GenericArray<u8, HashOutputLen<CS>>,
) -> [u8; SHARED_SECRET_LENGTH] {
    // Hash the transcript into a fixed-size salt (no allocation needed).
    let mut transcript_hasher = CS::Hash::new();
    transcript_hasher.update(TRANSCRIPT_DST);
    transcript_hasher.update(initiator_public_key);
    transcript_hasher.update(responder_public_key);
    transcript_hasher.update(initiator_nonce);
    transcript_hasher.update(responder_nonce);
    let salt = transcript_hasher.finalize();

    let hk = Hkdf::<CS::Hash, SimpleHmac<CS::Hash>>::new(Some(&salt), dh_output.as_slice());
    let mut shared_secret = [0u8; SHARED_SECRET_LENGTH];
    hk.expand(HKDF_INFO, &mut shared_secret)
        .expect("32 bytes is a valid HKDF output length");
    shared_secret
}

/// Validates a public key using the key exchange primitive's validation,
/// and additionally rejects keys identical to our own (reflection attack).
fn validate_public_key<CS: CipherSuite>(
    their_key: &GenericArray<u8, PublicKeyLen<CS>>,
    our_key: &GenericArray<u8, PublicKeyLen<CS>>,
) -> Result<()> {
    CS::KeyExchange::validate_public_key(their_key)?;
    if their_key.as_slice().ct_eq(our_key.as_slice()).unwrap_u8() == 1 {
        return Err(ShortcakeError::InvalidPublicKey);
    }
    Ok(())
}
