// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree, or the
// Apache License, Version 2.0 found in the LICENSE-APACHE file.

//! Responder protocol implementation.
//!
//! The Responder responds to the Initiator's first message by encapsulating
//! to their public key and sending back a ciphertext and nonce.

use core::marker::PhantomData;

use digest::Output;
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::ciphersuite::{CipherSuite, Kem};
use crate::commitment;
use crate::error::Error;
use crate::kdf;
use crate::sas::{compute_sas, Sas};
use crate::Nonce;

/// The Responder's response message.
#[derive(Clone)]
pub struct ResponderResponse<CS: CipherSuite> {
    /// The ciphertext from KEM encapsulation.
    pub ct: <CS::Kem as Kem>::Ciphertext,
    /// The Responder's nonce.
    pub responder_nonce: Nonce,
}

/// Entry point for the Responder protocol.
pub struct Responder<CS: CipherSuite> {
    _marker: PhantomData<CS>,
}

impl<CS: CipherSuite> Responder<CS>
where
    <CS::Kem as Kem>::SharedSecret: Zeroize,
{
    /// Start the protocol as Responder upon receiving Initiator's first message.
    ///
    /// # Arguments
    ///
    /// * `rng` - A cryptographically secure random number generator.
    /// * `ek` - The Initiator's encapsulation (public) key.
    /// * `commitment` - The Initiator's commitment.
    ///
    /// # Returns
    ///
    /// A tuple of (next_state, response_message) on success.
    pub fn start(
        rng: &mut impl CryptoRngCore,
        ek: <CS::Kem as Kem>::EncapsulationKey,
        commitment: Output<CS::Hash>,
    ) -> Result<(ResponderAwaitingNonce<CS>, ResponderResponse<CS>), Error> {
        // Encapsulate to Initiator's public key
        let (ct, shared_secret) =
            CS::Kem::encaps(&ek, rng).map_err(|_| Error::EncapsulationFailed)?;

        // Generate Responder's nonce
        let mut responder_nonce = [0u8; 32];
        rng.fill_bytes(&mut responder_nonce);

        let state = ResponderAwaitingNonce {
            ek,
            commitment,
            responder_nonce,
            ct: ct.clone(),
            shared_secret: Some(shared_secret),
            _marker: PhantomData,
        };

        let message = ResponderResponse {
            ct,
            responder_nonce,
        };

        Ok((state, message))
    }
}

/// Responder state after sending response, awaiting Initiator's nonce.
pub struct ResponderAwaitingNonce<CS: CipherSuite> {
    ek: <CS::Kem as Kem>::EncapsulationKey,
    commitment: Output<CS::Hash>,
    responder_nonce: Nonce,
    ct: <CS::Kem as Kem>::Ciphertext,
    /// Wrapped in `Option` so the consuming method can `.take()` the value
    /// before `self` is dropped (Drop still zeroizes if present).
    shared_secret: Option<<CS::Kem as Kem>::SharedSecret>,
    _marker: PhantomData<CS>,
}

impl<CS: CipherSuite> Drop for ResponderAwaitingNonce<CS>
where
    <CS::Kem as Kem>::SharedSecret: Zeroize,
{
    fn drop(&mut self) {
        self.responder_nonce.zeroize();
        if let Some(ref mut ss) = self.shared_secret {
            ss.zeroize();
        }
    }
}

impl<CS: CipherSuite> ResponderAwaitingNonce<CS>
where
    <CS::Kem as Kem>::SharedSecret: Zeroize,
{
    /// Handle the Initiator's third message containing their nonce.
    ///
    /// This verifies the commitment and computes the SAS.
    ///
    /// # Arguments
    ///
    /// * `initiator_nonce` - The Initiator's nonce (opens the commitment).
    ///
    /// # Returns
    ///
    /// The next state on success.
    pub fn handle_initiator_nonce(
        mut self,
        initiator_nonce: Nonce,
    ) -> Result<ResponderAwaitingSasConfirmation<CS>, Error> {
        // Verify commitment
        commitment::open::<CS::Hash>(self.ek.as_ref(), &initiator_nonce, &self.commitment)?;

        // Compute SAS
        let sas =
            compute_sas::<CS::Hash>(&self.responder_nonce, &initiator_nonce, self.ct.as_ref());

        // Take shared_secret out (will be None after this, but we're consuming self anyway)
        let shared_secret = self
            .shared_secret
            .take()
            .expect("shared_secret should always be Some");

        Ok(ResponderAwaitingSasConfirmation {
            sas,
            shared_secret,
            _marker: PhantomData,
        })
    }
}

/// Responder state after verifying commitment and computing SAS, awaiting user confirmation.
#[derive(ZeroizeOnDrop)]
pub struct ResponderAwaitingSasConfirmation<CS: CipherSuite> {
    #[zeroize(skip)]
    sas: Sas,
    shared_secret: <CS::Kem as Kem>::SharedSecret,
    #[zeroize(skip)]
    _marker: PhantomData<CS>,
}

impl<CS: CipherSuite> ResponderAwaitingSasConfirmation<CS>
where
    <CS::Kem as Kem>::SharedSecret: Zeroize,
{
    /// Get the SAS for display to the user.
    pub fn sas(&self) -> &Sas {
        &self.sas
    }

    /// Finalize the protocol after user confirms SAS match.
    ///
    /// Derives the shared encryption key using HKDF.
    ///
    /// # Arguments
    ///
    /// * `salt` - Salt for HKDF (can be empty).
    /// * `info` - Application-specific context info.
    /// * `out` - Buffer to write the derived key into.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success.
    pub fn finalize(self, salt: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), Error> {
        kdf::derive_key::<CS::Hash>(self.shared_secret.as_ref(), salt, info, out)
    }
}
