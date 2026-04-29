// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! Initiator protocol implementation.
//!
//! The Initiator starts the 3-move SAS protocol by generating a KEM keypair,
//! creating a commitment, and sending the first message.

use core::marker::PhantomData;

use digest::Output;
use rand_core::CryptoRng;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use digest::Digest;

use crate::ciphersuite::{CipherSuite, Kem};
use crate::commitment;
use crate::error::Error;
use crate::responder::MessageTwo;
use crate::sas::compute_sas;
use crate::verification::ProtocolOutput;
use crate::Nonce;

/// The first protocol message (Initiator -> Responder).
#[derive(Clone)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound(
        serialize = "<CS::Kem as Kem>::EncapsulationKey: serde::Serialize",
        deserialize = "<CS::Kem as Kem>::EncapsulationKey: serde::Deserialize<'de>",
    ))
)]
pub struct MessageOne<CS: CipherSuite> {
    /// The Initiator's encapsulation (public) key.
    pub(crate) ek: <CS::Kem as Kem>::EncapsulationKey,
    /// Commitment to the encapsulation key and nonce.
    pub(crate) commitment: Output<CS::Hash>,
}

/// The third protocol message (Initiator -> Responder).
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MessageThree {
    /// The Initiator's nonce, opening the commitment.
    pub(crate) initiator_nonce: Nonce,
}

/// Initiator state in the 3-move SAS protocol.
///
/// Created by [`Initiator::start`], which generates a KEM keypair internally
/// and produces the first protocol message. Call [`Initiator::finish`] after
/// receiving the responder's reply to obtain a [`ProtocolOutput`] and the
/// final protocol message.
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound(
        serialize = "<CS::Kem as Kem>::DecapsulationKey: serde::Serialize, <CS::Kem as Kem>::EncapsulationKey: serde::Serialize",
        deserialize = "<CS::Kem as Kem>::DecapsulationKey: serde::Deserialize<'de>, <CS::Kem as Kem>::EncapsulationKey: serde::Deserialize<'de>",
    ))
)]
pub struct Initiator<CS: CipherSuite> {
    dk: <CS::Kem as Kem>::DecapsulationKey,
    ek: <CS::Kem as Kem>::EncapsulationKey,
    initiator_nonce: Nonce,
    _marker: PhantomData<CS>,
}

impl<CS: CipherSuite> Drop for Initiator<CS> {
    fn drop(&mut self) {
        self.initiator_nonce.zeroize();
        self.dk.zeroize();
        self.ek.zeroize();
    }
}

impl<CS: CipherSuite> Initiator<CS> {
    /// Start the protocol as Initiator.
    ///
    /// Generates a KEM keypair internally and produces the first protocol
    /// message to send to the Responder.
    ///
    /// # Arguments
    ///
    /// * `rng` - A cryptographically secure random number generator.
    ///
    /// # Returns
    ///
    /// A tuple of (initiator_state, first_message).
    pub fn start(rng: &mut impl CryptoRng) -> (Self, MessageOne<CS>) {
        let (dk, ek) = CS::Kem::generate(rng);

        let mut initiator_nonce = [0u8; 32];
        rng.fill_bytes(&mut initiator_nonce);

        let commitment = commitment::commit::<CS::Hash>(ek.as_ref(), &initiator_nonce);

        let state = Self {
            dk,
            ek: ek.clone(),
            initiator_nonce,
            _marker: PhantomData,
        };

        let message = MessageOne { ek, commitment };

        (state, message)
    }

    /// Process the responder's message and produce the protocol output.
    ///
    /// This decapsulates the ciphertext to recover the shared secret,
    /// checks for reflection attacks, and computes the SAS.
    ///
    /// # Arguments
    ///
    /// * `msg2` - The second protocol message from the Responder.
    ///
    /// # Returns
    ///
    /// A tuple of (protocol_output, third_message) on success.
    pub fn finish(self, msg2: MessageTwo<CS>) -> Result<(ProtocolOutput<CS>, MessageThree), Error> {
        // Check for reflection attack: ek must not equal ct.
        // For KEMs where ek and ct have different sizes (e.g., X-Wing),
        // this check is always false and acts as defense-in-depth.
        if self.ek.as_ref().ct_eq(msg2.ct.as_ref()).into() {
            return Err(Error::ReflectionDetected);
        }

        // Decapsulate to get KEM shared secret
        let mut kem_ss =
            CS::Kem::decaps(&self.dk, &msg2.ct).map_err(|_| Error::DecapsulationFailed)?;

        // Derive session key from full transcript (ordered by message flow)
        let session_key = {
            let mut h = CS::Hash::new();
            h.update(b"shortcake-session-key-v1");
            h.update((self.ek.as_ref().len() as u64).to_be_bytes());
            h.update(self.ek.as_ref());
            h.update((msg2.ct.as_ref().len() as u64).to_be_bytes());
            h.update(msg2.ct.as_ref());
            h.update(msg2.responder_nonce);
            h.update(self.initiator_nonce);
            h.update((kem_ss.as_ref().len() as u64).to_be_bytes());
            h.update(kem_ss.as_ref());
            h.finalize()
        };
        kem_ss.zeroize();

        // Compute SAS
        let sas = compute_sas::<CS::Hash>(
            &msg2.responder_nonce,
            &self.initiator_nonce,
            msg2.ct.as_ref(),
        );

        let output = ProtocolOutput {
            sas,
            session_key,
            _marker: PhantomData,
        };

        let message = MessageThree {
            initiator_nonce: self.initiator_nonce,
        };

        Ok((output, message))
    }
}
