// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! Shared utilities for ciphersuite implementations.

macro_rules! byte_array_newtype {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident([u8; $size:expr]);
        label = $label:expr;
    ) => {
        $(#[$meta])*
        #[derive(Clone)]
        $vis struct $name([u8; $size]);

        #[cfg(feature = "serde")]
        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_bytes(&self.0)
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                struct Visitor;
                impl<'de> serde::de::Visitor<'de> for Visitor {
                    type Value = $name;
                    fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                        write!(f, "{} bytes for {}", $size, $label)
                    }
                    fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                        $name::from_bytes(v).ok_or_else(|| E::invalid_length(v.len(), &self))
                    }
                }
                deserializer.deserialize_bytes(Visitor)
            }
        }

        impl $name {
            /// Create from raw bytes.
            ///
            /// Returns `None` if the byte slice is not exactly the correct length.
            pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
                if bytes.len() != $size {
                    return None;
                }
                let mut arr = [0u8; $size];
                arr.copy_from_slice(bytes);
                Some(Self(arr))
            }

            /// Get the raw bytes.
            pub fn as_bytes(&self) -> &[u8; $size] {
                &self.0
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl Zeroize for $name {
            fn zeroize(&mut self) {
                self.0.zeroize();
            }
        }
    };
}

pub(crate) use byte_array_newtype;
