// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! Responder protocol implementation.
//!
//! The Responder responds to the Initiator's first message by encapsulating
//! to their public key and sending back a ciphertext and nonce.

use core::marker::PhantomData;

use digest::Output;
use rand_core::CryptoRng;
use zeroize::Zeroize;

use crate::ciphersuite::{CipherSuite, Kem};
use crate::commitment;
use crate::error::Error;
use crate::initiator::{MessageOne, MessageThree};
use crate::sas::compute_sas;
use crate::verification::VerificationCode;
use crate::Nonce;

/// The second protocol message (Responder -> Initiator).
#[derive(Clone)]
pub struct MessageTwo<CS: CipherSuite> {
    /// The ciphertext from KEM encapsulation.
    pub(crate) ct: <CS::Kem as Kem>::Ciphertext,
    /// The Responder's nonce.
    pub(crate) responder_nonce: Nonce,
}

#[cfg(feature = "serde")]
impl<CS: CipherSuite> serde::Serialize for MessageTwo<CS>
where
    <CS::Kem as Kem>::Ciphertext: serde::Serialize,
{
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("MessageTwo", 2)?;
        s.serialize_field("ct", &self.ct)?;
        s.serialize_field("responder_nonce", &self.responder_nonce)?;
        s.end()
    }
}

#[cfg(feature = "serde")]
impl<'de, CS: CipherSuite> serde::Deserialize<'de> for MessageTwo<CS>
where
    <CS::Kem as Kem>::Ciphertext: serde::Deserialize<'de>,
{
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct MessageTwoVisitor<CS>(core::marker::PhantomData<CS>);
        impl<'de, CS: CipherSuite> serde::de::Visitor<'de> for MessageTwoVisitor<CS>
        where
            <CS::Kem as Kem>::Ciphertext: serde::Deserialize<'de>,
        {
            type Value = MessageTwo<CS>;
            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "MessageTwo struct with ct and responder_nonce fields")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let ct = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let responder_nonce: Nonce = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                Ok(MessageTwo {
                    ct,
                    responder_nonce,
                })
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut ct = None;
                let mut responder_nonce = None;
                while let Some(key) = map.next_key::<&str>()? {
                    match key {
                        "ct" => {
                            ct = Some(map.next_value()?);
                        }
                        "responder_nonce" => {
                            responder_nonce = Some(map.next_value()?);
                        }
                        _ => {
                            let _ = map.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }
                let ct = ct.ok_or_else(|| serde::de::Error::missing_field("ct"))?;
                let responder_nonce = responder_nonce
                    .ok_or_else(|| serde::de::Error::missing_field("responder_nonce"))?;
                Ok(MessageTwo {
                    ct,
                    responder_nonce,
                })
            }
        }
        deserializer.deserialize_struct(
            "MessageTwo",
            &["ct", "responder_nonce"],
            MessageTwoVisitor(core::marker::PhantomData),
        )
    }
}

/// Responder state in the 3-move SAS protocol.
///
/// Created by [`Responder::start`] upon receiving the initiator's first
/// message. Call [`Responder::finish`] after receiving the initiator's
/// final message to obtain a [`VerificationCode`].
pub struct Responder<CS: CipherSuite> {
    ek: <CS::Kem as Kem>::EncapsulationKey,
    commitment: Output<CS::Hash>,
    responder_nonce: Nonce,
    ct: <CS::Kem as Kem>::Ciphertext,
    /// Wrapped in `Option` so the consuming method can `.take()` the value
    /// before `self` is dropped (Drop still zeroizes if present).
    shared_secret: Option<<CS::Kem as Kem>::SharedSecret>,
    _marker: PhantomData<CS>,
}

impl<CS: CipherSuite> Drop for Responder<CS> {
    fn drop(&mut self) {
        self.responder_nonce.zeroize();
        self.ek.zeroize();
        self.ct.zeroize();
        self.commitment.as_mut_slice().zeroize();
        if let Some(ref mut ss) = self.shared_secret {
            ss.zeroize();
        }
        // Zero the Option wrapper to clear discriminant and any residual bytes.
        unsafe {
            core::ptr::write_bytes(
                &mut self.shared_secret as *mut _ as *mut u8,
                0,
                core::mem::size_of::<Option<<CS::Kem as Kem>::SharedSecret>>(),
            );
        }
    }
}

impl<CS: CipherSuite> Responder<CS> {
    /// Start the protocol as Responder upon receiving the Initiator's first message.
    ///
    /// # Arguments
    ///
    /// * `rng` - A cryptographically secure random number generator.
    /// * `msg1` - The first protocol message from the Initiator.
    ///
    /// # Returns
    ///
    /// A tuple of (responder_state, second_message) on success.
    pub fn start(
        rng: &mut impl CryptoRng,
        msg1: MessageOne<CS>,
    ) -> Result<(Self, MessageTwo<CS>), Error> {
        // Encapsulate to Initiator's public key
        let (ct, shared_secret) =
            CS::Kem::encaps(&msg1.ek, rng).map_err(|_| Error::EncapsulationFailed)?;

        // Generate Responder's nonce
        let mut responder_nonce = [0u8; 32];
        rng.fill_bytes(&mut responder_nonce);

        let state = Self {
            ek: msg1.ek,
            commitment: msg1.commitment,
            responder_nonce,
            ct: ct.clone(),
            shared_secret: Some(shared_secret),
            _marker: PhantomData,
        };

        let message = MessageTwo {
            ct,
            responder_nonce,
        };

        Ok((state, message))
    }

    /// Process the initiator's final message and produce a verification code.
    ///
    /// This verifies the commitment and computes the SAS.
    ///
    /// # Arguments
    ///
    /// * `msg3` - The third protocol message from the Initiator.
    ///
    /// # Returns
    ///
    /// A [`VerificationCode`] on success.
    pub fn finish(mut self, msg3: MessageThree) -> Result<VerificationCode<CS>, Error> {
        // Verify commitment
        commitment::open::<CS::Hash>(self.ek.as_ref(), &msg3.initiator_nonce, &self.commitment)?;

        // Compute SAS
        let sas = compute_sas::<CS::Hash>(
            &self.responder_nonce,
            &msg3.initiator_nonce,
            self.ct.as_ref(),
        );

        // Take shared_secret out (will be None after this, but we're consuming self anyway)
        let shared_secret = self
            .shared_secret
            .take()
            .expect("shared_secret should always be Some");

        Ok(VerificationCode {
            sas,
            shared_secret: Some(shared_secret),
            _marker: PhantomData,
        })
    }
}
