// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree, or the
// Apache License, Version 2.0 found in the LICENSE-APACHE file.

//! Primary (responder) protocol implementation.
//!
//! The Primary responds to the Companion's first message by encapsulating
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

/// The Primary's response message.
#[derive(Clone)]
pub struct PrimaryResponse<CS: CipherSuite> {
    /// The ciphertext from KEM encapsulation.
    pub ct: <CS::Kem as Kem>::Ciphertext,
    /// The Primary's nonce.
    pub primary_nonce: Nonce,
}

/// Entry point for the Primary protocol.
pub struct Primary<CS: CipherSuite> {
    _marker: PhantomData<CS>,
}

impl<CS: CipherSuite> Primary<CS>
where
    <CS::Kem as Kem>::SharedSecret: Zeroize,
{
    /// Start the protocol as Primary upon receiving Companion's first message.
    ///
    /// # Arguments
    ///
    /// * `rng` - A cryptographically secure random number generator.
    /// * `ek` - The Companion's encapsulation (public) key.
    /// * `commitment` - The Companion's commitment.
    ///
    /// # Returns
    ///
    /// A tuple of (next_state, response_message) on success.
    pub fn start(
        rng: &mut impl CryptoRngCore,
        ek: <CS::Kem as Kem>::EncapsulationKey,
        commitment: Output<CS::Hash>,
    ) -> Result<(PrimaryAwaitingNonce<CS>, PrimaryResponse<CS>), Error> {
        // Encapsulate to Companion's public key
        let (ct, shared_secret) =
            CS::Kem::encaps(&ek, rng).map_err(|_| Error::EncapsulationFailed)?;

        // Generate Primary's nonce
        let mut primary_nonce = [0u8; 32];
        rng.fill_bytes(&mut primary_nonce);

        let state = PrimaryAwaitingNonce {
            ek,
            commitment,
            primary_nonce,
            ct: ct.clone(),
            shared_secret: Some(shared_secret),
            _marker: PhantomData,
        };

        let message = PrimaryResponse { ct, primary_nonce };

        Ok((state, message))
    }
}

/// Primary state after sending response, awaiting Companion's nonce.
pub struct PrimaryAwaitingNonce<CS: CipherSuite>
where
    <CS::Kem as Kem>::SharedSecret: Zeroize,
{
    ek: <CS::Kem as Kem>::EncapsulationKey,
    commitment: Output<CS::Hash>,
    primary_nonce: Nonce,
    ct: <CS::Kem as Kem>::Ciphertext,
    shared_secret: Option<<CS::Kem as Kem>::SharedSecret>,
    _marker: PhantomData<CS>,
}

impl<CS: CipherSuite> Drop for PrimaryAwaitingNonce<CS>
where
    <CS::Kem as Kem>::SharedSecret: Zeroize,
{
    fn drop(&mut self) {
        self.primary_nonce.zeroize();
        if let Some(ref mut ss) = self.shared_secret {
            ss.zeroize();
        }
    }
}

impl<CS: CipherSuite> PrimaryAwaitingNonce<CS>
where
    <CS::Kem as Kem>::SharedSecret: Zeroize,
{
    /// Handle the Companion's third message containing their nonce.
    ///
    /// This verifies the commitment and computes the SAS.
    ///
    /// # Arguments
    ///
    /// * `companion_nonce` - The Companion's nonce (opens the commitment).
    ///
    /// # Returns
    ///
    /// The next state on success.
    pub fn handle_companion_nonce(
        mut self,
        companion_nonce: Nonce,
    ) -> Result<PrimaryAwaitingSasConfirmation<CS>, Error> {
        // Verify commitment
        commitment::open::<CS::Hash>(self.ek.as_ref(), &companion_nonce, &self.commitment)?;

        // Compute SAS
        let sas = compute_sas::<CS::Hash>(&self.primary_nonce, &companion_nonce, self.ct.as_ref());

        // Take shared_secret out (will be None after this, but we're consuming self anyway)
        let shared_secret = self
            .shared_secret
            .take()
            .expect("shared_secret should always be Some");

        Ok(PrimaryAwaitingSasConfirmation {
            sas,
            shared_secret,
            _marker: PhantomData,
        })
    }
}

/// Primary state after verifying commitment and computing SAS, awaiting user confirmation.
#[derive(ZeroizeOnDrop)]
pub struct PrimaryAwaitingSasConfirmation<CS: CipherSuite>
where
    <CS::Kem as Kem>::SharedSecret: Zeroize,
{
    #[zeroize(skip)]
    sas: Sas,
    shared_secret: <CS::Kem as Kem>::SharedSecret,
    #[zeroize(skip)]
    _marker: PhantomData<CS>,
}

impl<CS: CipherSuite> PrimaryAwaitingSasConfirmation<CS>
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
