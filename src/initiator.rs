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
use zeroize::Zeroize;

use crate::ciphersuite::{CipherSuite, Kem};
use crate::commitment;
use crate::error::Error;
use crate::responder::MessageTwo;
use crate::sas::compute_sas;
use crate::verification::VerificationCode;
use crate::Nonce;

/// The first protocol message (Initiator -> Responder).
#[derive(Clone)]
pub struct MessageOne<CS: CipherSuite> {
    /// The Initiator's encapsulation (public) key.
    pub(crate) ek: <CS::Kem as Kem>::EncapsulationKey,
    /// Commitment to the encapsulation key and nonce.
    pub(crate) commitment: Output<CS::Hash>,
}

#[cfg(feature = "serde")]
impl<CS: CipherSuite> serde::Serialize for MessageOne<CS>
where
    <CS::Kem as Kem>::EncapsulationKey: serde::Serialize,
{
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("MessageOne", 2)?;
        s.serialize_field("ek", &self.ek)?;
        s.serialize_field("commitment", self.commitment.as_slice())?;
        s.end()
    }
}

#[cfg(feature = "serde")]
impl<'de, CS: CipherSuite> serde::Deserialize<'de> for MessageOne<CS>
where
    <CS::Kem as Kem>::EncapsulationKey: serde::Deserialize<'de>,
{
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use digest::OutputSizeUser;

        struct MessageOneVisitor<CS>(core::marker::PhantomData<CS>);
        impl<'de, CS: CipherSuite> serde::de::Visitor<'de> for MessageOneVisitor<CS>
        where
            <CS::Kem as Kem>::EncapsulationKey: serde::Deserialize<'de>,
        {
            type Value = MessageOne<CS>;
            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "MessageOne struct with ek and commitment fields")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let ek = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let commitment_bytes: &[u8] = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                let expected_len = <CS::Hash as OutputSizeUser>::output_size();
                if commitment_bytes.len() != expected_len {
                    return Err(serde::de::Error::invalid_length(
                        commitment_bytes.len(),
                        &self,
                    ));
                }
                let mut commitment = Output::<CS::Hash>::default();
                commitment.copy_from_slice(commitment_bytes);
                Ok(MessageOne { ek, commitment })
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut ek = None;
                let mut commitment = None;
                while let Some(key) = map.next_key::<&str>()? {
                    match key {
                        "ek" => {
                            ek = Some(map.next_value()?);
                        }
                        "commitment" => {
                            let bytes: &[u8] = map.next_value()?;
                            let expected_len = <CS::Hash as OutputSizeUser>::output_size();
                            if bytes.len() != expected_len {
                                return Err(serde::de::Error::invalid_length(bytes.len(), &self));
                            }
                            let mut c = Output::<CS::Hash>::default();
                            c.copy_from_slice(bytes);
                            commitment = Some(c);
                        }
                        _ => {
                            let _ = map.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }
                let ek = ek.ok_or_else(|| serde::de::Error::missing_field("ek"))?;
                let commitment =
                    commitment.ok_or_else(|| serde::de::Error::missing_field("commitment"))?;
                Ok(MessageOne { ek, commitment })
            }
        }
        deserializer.deserialize_struct(
            "MessageOne",
            &["ek", "commitment"],
            MessageOneVisitor(core::marker::PhantomData),
        )
    }
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
/// receiving the responder's reply to obtain a [`VerificationCode`] and the
/// final protocol message.
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

    /// Process the responder's message and produce a verification code.
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
    /// A tuple of (verification_code, third_message) on success.
    pub fn finish(
        self,
        msg2: MessageTwo<CS>,
    ) -> Result<(VerificationCode<CS>, MessageThree), Error> {
        // Check for reflection attack: ek must not equal ct.
        // For KEMs where ek and ct have different sizes (e.g., X-Wing),
        // this check is always false and acts as defense-in-depth.
        if self.ek.as_ref() == msg2.ct.as_ref() {
            return Err(Error::ReflectionDetected);
        }

        // Decapsulate to get shared secret
        let shared_secret =
            CS::Kem::decaps(&self.dk, &msg2.ct).map_err(|_| Error::DecapsulationFailed)?;

        // Compute SAS
        let sas = compute_sas::<CS::Hash>(
            &msg2.responder_nonce,
            &self.initiator_nonce,
            msg2.ct.as_ref(),
        );

        let code = VerificationCode {
            sas,
            shared_secret: Some(shared_secret),
            _marker: PhantomData,
        };

        let message = MessageThree {
            initiator_nonce: self.initiator_nonce,
        };

        Ok((code, message))
    }
}
