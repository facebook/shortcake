// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree, or the
// Apache License, Version 2.0 found in the LICENSE-APACHE file.

//! Initiator protocol implementation.
//!
//! The Initiator starts the 3-move SAS protocol by generating a KEM keypair,
//! creating a commitment, and sending the first message.

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

/// The first message sent by the Initiator.
#[derive(Clone)]
pub struct InitiatorFirstMessage<CS: CipherSuite> {
    /// The Initiator's encapsulation (public) key.
    pub ek: <CS::Kem as Kem>::EncapsulationKey,
    /// Commitment to the encapsulation key and nonce.
    pub commitment: Output<CS::Hash>,
}

/// The third message sent by the Initiator (after receiving Responder's response).
#[derive(Clone, Debug)]
pub struct InitiatorThirdMessage {
    /// The Initiator's nonce, opening the commitment.
    pub initiator_nonce: Nonce,
}

/// Entry point for the Initiator protocol.
pub struct Initiator<CS: CipherSuite> {
    _marker: PhantomData<CS>,
}

impl<CS: CipherSuite> Initiator<CS> {
    /// Start the protocol as Initiator.
    ///
    /// # Arguments
    ///
    /// * `rng` - A cryptographically secure random number generator.
    /// * `ek` - The Initiator's encapsulation (public) key.
    /// * `dk` - The Initiator's decapsulation (private) key.
    ///
    /// # Returns
    ///
    /// A tuple of (next_state, first_message) to send to the Responder.
    pub fn start(
        rng: &mut impl CryptoRngCore,
        ek: <CS::Kem as Kem>::EncapsulationKey,
        dk: <CS::Kem as Kem>::DecapsulationKey,
    ) -> (InitiatorAwaitingResponse<CS>, InitiatorFirstMessage<CS>) {
        let mut initiator_nonce = [0u8; 32];
        rng.fill_bytes(&mut initiator_nonce);

        let commitment = commitment::commit::<CS::Hash>(ek.as_ref(), &initiator_nonce);

        let state = InitiatorAwaitingResponse {
            dk: Some(dk),
            ek: ek.clone(),
            initiator_nonce,
            _marker: PhantomData,
        };

        let message = InitiatorFirstMessage { ek, commitment };

        (state, message)
    }
}

/// Initiator state after sending the first message, awaiting Responder's response.
pub struct InitiatorAwaitingResponse<CS: CipherSuite>
where
    <CS::Kem as Kem>::DecapsulationKey: Zeroize,
{
    dk: Option<<CS::Kem as Kem>::DecapsulationKey>,
    ek: <CS::Kem as Kem>::EncapsulationKey,
    initiator_nonce: Nonce,
    _marker: PhantomData<CS>,
}

impl<CS: CipherSuite> Drop for InitiatorAwaitingResponse<CS>
where
    <CS::Kem as Kem>::DecapsulationKey: Zeroize,
{
    fn drop(&mut self) {
        self.initiator_nonce.zeroize();
        if let Some(ref mut dk) = self.dk {
            dk.zeroize();
        }
    }
}

impl<CS: CipherSuite> InitiatorAwaitingResponse<CS>
where
    <CS::Kem as Kem>::DecapsulationKey: Zeroize,
    <CS::Kem as Kem>::SharedSecret: Zeroize,
{
    /// Handle the Responder's response message.
    ///
    /// This decapsulates the ciphertext to recover the shared secret,
    /// checks for reflection attacks, and computes the SAS.
    ///
    /// # Arguments
    ///
    /// * `ct` - The ciphertext from the Responder.
    /// * `responder_nonce` - The Responder's nonce.
    ///
    /// # Returns
    ///
    /// A tuple of (next_state, third_message) on success.
    pub fn handle_responder_response(
        mut self,
        ct: <CS::Kem as Kem>::Ciphertext,
        responder_nonce: Nonce,
    ) -> Result<(InitiatorAwaitingSasConfirmation<CS>, InitiatorThirdMessage), Error> {
        // Check for reflection attack: ek must not equal ct
        if self.ek.as_ref() == ct.as_ref() {
            return Err(Error::ReflectionDetected);
        }

        // Take dk out (will be None after this, but we're consuming self anyway)
        let dk = self.dk.take().expect("dk should always be Some");

        // Decapsulate to get shared secret
        let shared_secret = CS::Kem::decaps(&dk, &ct).map_err(|_| Error::DecapsulationFailed)?;

        // Compute SAS
        let sas = compute_sas::<CS::Hash>(&responder_nonce, &self.initiator_nonce, ct.as_ref());

        let next_state = InitiatorAwaitingSasConfirmation {
            sas,
            shared_secret,
            _marker: PhantomData,
        };

        let message = InitiatorThirdMessage {
            initiator_nonce: self.initiator_nonce,
        };

        Ok((next_state, message))
    }
}

/// Initiator state after computing the SAS, awaiting user confirmation.
#[derive(ZeroizeOnDrop)]
pub struct InitiatorAwaitingSasConfirmation<CS: CipherSuite>
where
    <CS::Kem as Kem>::SharedSecret: Zeroize,
{
    #[zeroize(skip)]
    sas: Sas,
    shared_secret: <CS::Kem as Kem>::SharedSecret,
    #[zeroize(skip)]
    _marker: PhantomData<CS>,
}

impl<CS: CipherSuite> InitiatorAwaitingSasConfirmation<CS>
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
