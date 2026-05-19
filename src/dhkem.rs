// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! DHKEM ciphersuites per RFC 9180 Section 4.1.
//!
//! Provides KEM constructions from ECDH on NIST curves with HKDF extraction,
//! producing uniform shared secrets suitable for use as IND-CCA KEMs.

use core::fmt;

use elliptic_curve::ecdh;
use elliptic_curve::sec1::ToSec1Point;
use elliptic_curve::{NonZeroScalar, PublicKey};

use elliptic_curve::common::Generate;
use hkdf::HkdfExtract;
use rand_core::CryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::ciphersuite::{CipherSuite, Kem};
use crate::util::byte_array_newtype;

const HPKE_VERSION: &[u8] = b"HPKE-v1";

/// RFC 9180 LabeledExtract using incremental HMAC (no heap allocation).
///
/// ```text
/// labeled_ikm = concat("HPKE-v1", suite_id, label, ikm)
/// return HKDF-Extract(salt, labeled_ikm)
/// ```
fn labeled_extract<H: ecdh::EagerHash>(
    salt: &[u8],
    suite_id: &[u8],
    label: &[u8],
    ikm: &[u8],
) -> hkdf::Hkdf<H> {
    let mut extract = HkdfExtract::<H>::new(Some(salt));
    extract.input_ikm(HPKE_VERSION);
    extract.input_ikm(suite_id);
    extract.input_ikm(label);
    extract.input_ikm(ikm);
    let (_prk, hkdf) = extract.finalize();
    hkdf
}

/// RFC 9180 LabeledExpand using multi-info expand (no heap allocation).
///
/// ```text
/// labeled_info = concat(I2OSP(L, 2), "HPKE-v1", suite_id, label, info)
/// return HKDF-Expand(prk, labeled_info, L)
/// ```
fn labeled_expand<H: ecdh::EagerHash>(
    prk: &hkdf::Hkdf<H>,
    suite_id: &[u8],
    label: &[u8],
    info: &[u8],
    out: &mut [u8],
) {
    let l_bytes = (out.len() as u16).to_be_bytes();
    prk.expand_multi_info(&[&l_bytes, HPKE_VERSION, suite_id, label, info], out)
        .expect("output length is valid");
}

/// RFC 9180 Section 4.1 ExtractAndExpand.
///
/// ```text
/// kem_context = concat(enc, pkR)
/// prk = LabeledExtract("", "eae_prk", dh)
/// return LabeledExpand(prk, "shared_secret", kem_context, Nsecret)
/// ```
fn extract_and_expand<H: ecdh::EagerHash>(
    suite_id: &[u8],
    dh: &[u8],
    kem_context: &[u8],
    out: &mut [u8],
) {
    let prk = labeled_extract::<H>(b"", suite_id, b"eae_prk", dh);
    labeled_expand::<H>(&prk, suite_id, b"shared_secret", kem_context, out);
}

/// Error type for DHKEM operations.
#[derive(Debug, Clone, Copy)]
pub struct DhKemError;

impl fmt::Display for DhKemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DHKEM operation failed")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DhKemError {}

macro_rules! dhkem_ciphersuite {
    (
        curve = $curve:ty,
        hash = $hash:ty,
        kem_name = $kem_name:ident,
        suite_name = $suite_name:ident,
        suite_id = $suite_id:expr,
        ek_size = $ek_size:expr,
        sk_size = $sk_size:expr,
        ss_size = $ss_size:expr,
        dk_name = $dk_name:ident,
        ek_type = $ek_type:ident,
        ct_type = $ct_type:ident,
        ss_type = $ss_type:ident,
        feature = $feature:expr,
        kem_doc = $kem_doc:expr,
        suite_doc = $suite_doc:expr,
    ) => {
        byte_array_newtype! {
            #[doc = concat!("Encapsulation (public) key for ", $kem_doc, ".")]
            #[cfg_attr(docsrs, doc(cfg(feature = $feature)))]
            pub struct $ek_type([u8; $ek_size]);
            label = concat!($kem_doc, " encapsulation key");
        }

        byte_array_newtype! {
            #[doc = concat!("Ciphertext for ", $kem_doc, ".")]
            #[cfg_attr(docsrs, doc(cfg(feature = $feature)))]
            pub struct $ct_type([u8; $ek_size]);
            label = concat!($kem_doc, " ciphertext");
        }

        #[doc = concat!("Shared secret for ", $kem_doc, " (", stringify!($ss_size), " bytes).")]
        #[cfg_attr(docsrs, doc(cfg(feature = $feature)))]
        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct $ss_type([u8; $ss_size]);

        impl AsRef<[u8]> for $ss_type {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        #[cfg(feature = "serde")]
        impl serde::Serialize for $ss_type {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_bytes(&self.0)
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> serde::Deserialize<'de> for $ss_type {
            fn deserialize<D: serde::Deserializer<'de>>(
                deserializer: D,
            ) -> Result<Self, D::Error> {
                struct SsVisitor;
                impl<'de> serde::de::Visitor<'de> for SsVisitor {
                    type Value = $ss_type;
                    fn expecting(
                        &self,
                        f: &mut core::fmt::Formatter<'_>,
                    ) -> core::fmt::Result {
                        write!(f, "{} bytes for shared secret", $ss_size)
                    }
                    fn visit_bytes<E: serde::de::Error>(
                        self,
                        v: &[u8],
                    ) -> Result<Self::Value, E> {
                        if v.len() != $ss_size {
                            return Err(E::invalid_length(v.len(), &self));
                        }
                        let mut arr = [0u8; $ss_size];
                        arr.copy_from_slice(v);
                        Ok($ss_type(arr))
                    }
                }
                deserializer.deserialize_bytes(SsVisitor)
            }
        }

        #[doc = concat!("Decapsulation (private) key for ", $kem_doc, ".")]
        #[cfg_attr(docsrs, doc(cfg(feature = $feature)))]
        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct $dk_name {
            scalar_bytes: [u8; $sk_size],
            ek_bytes: [u8; $ek_size],
        }

        #[cfg(feature = "serde")]
        impl serde::Serialize for $dk_name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_bytes(&self.scalar_bytes)
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> serde::Deserialize<'de> for $dk_name {
            fn deserialize<D: serde::Deserializer<'de>>(
                deserializer: D,
            ) -> Result<Self, D::Error> {
                struct DkVisitor;
                impl<'de> serde::de::Visitor<'de> for DkVisitor {
                    type Value = $dk_name;
                    fn expecting(
                        &self,
                        f: &mut core::fmt::Formatter<'_>,
                    ) -> core::fmt::Result {
                        write!(f, "{} bytes for decapsulation key", $sk_size)
                    }
                    fn visit_bytes<E: serde::de::Error>(
                        self,
                        v: &[u8],
                    ) -> Result<Self::Value, E> {
                        if v.len() != $sk_size {
                            return Err(E::invalid_length(v.len(), &self));
                        }
                        let mut scalar_bytes = [0u8; $sk_size];
                        scalar_bytes.copy_from_slice(v);

                        // Reconstruct the public key from the scalar
                        let scalar = NonZeroScalar::<$curve>::try_from(
                            scalar_bytes.as_slice(),
                        )
                        .map_err(|_| E::custom("invalid scalar"))?;
                        let pk = PublicKey::<$curve>::from_secret_scalar(&scalar);
                        let ep = pk.as_affine().to_sec1_point(false);
                        let mut ek_bytes = [0u8; $ek_size];
                        ek_bytes.copy_from_slice(ep.as_bytes());

                        Ok($dk_name {
                            scalar_bytes,
                            ek_bytes,
                        })
                    }
                }
                deserializer.deserialize_bytes(DkVisitor)
            }
        }

        #[doc = concat!($kem_doc, " KEM (RFC 9180 Section 4.1).")]
        #[cfg_attr(docsrs, doc(cfg(feature = $feature)))]
        #[derive(Debug, Clone, Copy)]
        pub struct $kem_name;

        impl Kem for $kem_name {
            type EncapsulationKey = $ek_type;
            type DecapsulationKey = $dk_name;
            type Ciphertext = $ct_type;
            type SharedSecret = $ss_type;
            type Error = DhKemError;

            fn generate(
                rng: &mut impl CryptoRng,
            ) -> (Self::DecapsulationKey, Self::EncapsulationKey) {
                let scalar = NonZeroScalar::<$curve>::generate_from_rng(rng);
                let pk = PublicKey::<$curve>::from_secret_scalar(&scalar);
                let ep = pk.as_affine().to_sec1_point(false);

                let mut scalar_bytes = [0u8; $sk_size];
                scalar_bytes.copy_from_slice(&scalar.to_bytes());

                let mut ek_bytes = [0u8; $ek_size];
                ek_bytes.copy_from_slice(ep.as_bytes());

                let dk = $dk_name {
                    scalar_bytes,
                    ek_bytes,
                };
                let ek = $ek_type(ek_bytes);
                (dk, ek)
            }

            fn encaps(
                ek: &Self::EncapsulationKey,
                rng: &mut impl CryptoRng,
            ) -> Result<(Self::Ciphertext, Self::SharedSecret), Self::Error> {
                let pk_r = PublicKey::<$curve>::from_sec1_bytes(&ek.0)
                    .map_err(|_| DhKemError)?;

                // Generate ephemeral keypair
                let sk_e = NonZeroScalar::<$curve>::generate_from_rng(rng);
                let pk_e = PublicKey::<$curve>::from_secret_scalar(&sk_e);

                // Raw ECDH
                let dh = ecdh::diffie_hellman(&sk_e, pk_r.as_affine());

                // Serialize ephemeral public key (enc) as uncompressed SEC1
                let enc_point = pk_e.as_affine().to_sec1_point(false);
                let mut enc = [0u8; $ek_size];
                enc.copy_from_slice(enc_point.as_bytes());

                // kem_context = concat(enc, pkR)
                // Use a stack buffer: 2 * ek_size
                let mut kem_context = [0u8; $ek_size * 2];
                kem_context[..$ek_size].copy_from_slice(&enc);
                kem_context[$ek_size..].copy_from_slice(&ek.0);

                // ExtractAndExpand per RFC 9180
                let mut ss = [0u8; $ss_size];
                extract_and_expand::<$hash>(
                    $suite_id,
                    dh.raw_secret_bytes(),
                    &kem_context,
                    &mut ss,
                );

                Ok(($ct_type(enc), $ss_type(ss)))
            }

            fn decaps(
                dk: &Self::DecapsulationKey,
                ct: &Self::Ciphertext,
            ) -> Result<Self::SharedSecret, Self::Error> {
                let pk_e = PublicKey::<$curve>::from_sec1_bytes(&ct.0)
                    .map_err(|_| DhKemError)?;

                // Reconstruct scalar from stored bytes
                let scalar = NonZeroScalar::<$curve>::try_from(
                    dk.scalar_bytes.as_slice(),
                )
                .map_err(|_| DhKemError)?;

                // Raw ECDH
                let dh = ecdh::diffie_hellman(&scalar, pk_e.as_affine());

                // kem_context = concat(enc, pkR)
                let mut kem_context = [0u8; $ek_size * 2];
                kem_context[..$ek_size].copy_from_slice(&ct.0);
                kem_context[$ek_size..].copy_from_slice(&dk.ek_bytes);

                // ExtractAndExpand per RFC 9180
                let mut ss = [0u8; $ss_size];
                extract_and_expand::<$hash>(
                    $suite_id,
                    dh.raw_secret_bytes(),
                    &kem_context,
                    &mut ss,
                );

                Ok($ss_type(ss))
            }
        }

        #[doc = $suite_doc]
        #[cfg_attr(docsrs, doc(cfg(feature = $feature)))]
        #[derive(Debug, Clone, Copy)]
        pub struct $suite_name;

        impl CipherSuite for $suite_name {
            type Kem = $kem_name;
            type Hash = $hash;
        }
    };
}

// ── DHKEM(P-256, HKDF-SHA256) ── RFC 9180 kem_id = 0x0010 ──

#[cfg(feature = "dhkem-p256")]
dhkem_ciphersuite! {
    curve = p256::NistP256,
    hash = sha2::Sha256,
    kem_name = P256Kem,
    suite_name = DhkemP256Sha256,
    suite_id = b"KEM\x00\x10",
    ek_size = 65,    // uncompressed SEC1 point
    sk_size = 32,    // scalar
    ss_size = 32,    // Nsecret
    dk_name = P256DecapsulationKey,
    ek_type = P256EncapsulationKey,
    ct_type = P256Ciphertext,
    ss_type = P256SharedSecret,
    feature = "dhkem-p256",
    kem_doc = "DHKEM(P-256, HKDF-SHA256)",
    suite_doc = "DHKEM(P-256, HKDF-SHA256) + SHA-256 ciphersuite.",
}

// ── DHKEM(P-384, HKDF-SHA384) ── RFC 9180 kem_id = 0x0011 ──

#[cfg(feature = "dhkem-p384")]
dhkem_ciphersuite! {
    curve = p384::NistP384,
    hash = sha2::Sha384,
    kem_name = P384Kem,
    suite_name = DhkemP384Sha384,
    suite_id = b"KEM\x00\x11",
    ek_size = 97,    // uncompressed SEC1 point
    sk_size = 48,    // scalar
    ss_size = 48,    // Nsecret
    dk_name = P384DecapsulationKey,
    ek_type = P384EncapsulationKey,
    ct_type = P384Ciphertext,
    ss_type = P384SharedSecret,
    feature = "dhkem-p384",
    kem_doc = "DHKEM(P-384, HKDF-SHA384)",
    suite_doc = "DHKEM(P-384, HKDF-SHA384) + SHA-384 ciphersuite.",
}
