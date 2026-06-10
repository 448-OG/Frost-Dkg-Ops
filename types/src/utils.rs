use core::fmt;

use bitcode::{Decode, Encode};
use tai64::Tai64N;
use zeroize::Zeroize;

#[cfg(feature = "frost_ops")]
use crate::{FrostOpsError, FrostOpsResult};

#[cfg(feature = "frost_ops")]
use std::str::FromStr;

#[derive(Default, PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Hash, Encode, Decode)]
pub struct Byte32Array([u8; 32]);

impl Byte32Array {
    pub fn ct_eq(&self, other: &Byte32Array) -> bool {
        use subtle::ConstantTimeEq;

        self.0.ct_eq(&other.0).into()
    }
}

impl fmt::Debug for Byte32Array {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Byte32Array")
            .field(&faster_hex::hex_string_upper(&self.0))
            .finish()
    }
}

#[derive(Default, PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Hash, Encode, Decode)]
pub struct Tai64NTimestamp([u8; 12]);

impl Tai64NTimestamp {
    pub fn now() -> Self {
        Self(Tai64N::now().to_bytes())
    }

    pub fn new_epoch() -> Self {
        Self(Self::epoch_timestamp().to_bytes())
    }

    pub fn epoch_timestamp() -> Tai64N {
        Tai64N::UNIX_EPOCH
    }

    #[cfg(feature = "frost_ops")]
    pub fn parse(&self) -> FrostOpsResult<Tai64N> {
        Ok(Tai64N::try_from(self.0)?)
    }

    pub fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub fn take(self) -> [u8; 12] {
        self.0
    }

    pub fn format_rfc_2822_long(tai64n_time: Tai64N, offset: i32) -> String {
        let duration = tai64n_time
            .duration_since(&tai64::Tai64N::UNIX_EPOCH)
            .unwrap_or_default();
        let timestamp = hifitime::Epoch::from_unix_seconds(duration.as_secs_f64());
        let tz = hifitime::Duration::from_seconds(offset as f64);
        let fmt = hifitime::efmt::Formatter::with_timezone(
            timestamp,
            tz,
            hifitime::efmt::consts::RFC2822_LONG,
        );

        format!("{fmt}")
    }
}

impl fmt::Debug for Tai64NTimestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let system_time = Tai64N::from_slice(&self.0)
            .unwrap_or(Tai64N::UNIX_EPOCH)
            .to_system_time();

        let formatted = humantime::format_rfc3339(system_time).to_string();
        f.debug_tuple("Tai64NTimestamp").field(&formatted).finish()
    }
}

impl Zeroize for Tai64NTimestamp {
    fn zeroize(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Default, PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Hash, Encode, Decode)]
pub struct Blake3HashBytes([u8; 32]);

impl Blake3HashBytes {
    pub fn new(message: impl AsRef<[u8]>) -> Self {
        Self(*blake3::hash(message.as_ref()).as_bytes())
    }

    pub fn pre_hashed(hash: blake3::Hash) -> Self {
        Self(*hash.as_bytes())
    }

    pub fn to_hash(&self) -> blake3::Hash {
        self.0.into()
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[cfg(feature = "frost_ops")]
    pub fn from_slice(slice: &[u8]) -> FrostOpsResult<Self> {
        let to_array: [u8; 32] = slice
            .get(..32)
            .ok_or(FrostOpsError::BindingHashNot32Bytes)?
            .try_into()
            .or(Err(FrostOpsError::BindingHashNot32Bytes))?;

        Ok(Self(to_array))
    }
}

impl AsRef<[u8]> for Blake3HashBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Debug for Blake3HashBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Blake3HashBytes")
            .field(&faster_hex::hex_string_upper(&self.0))
            .finish()
    }
}

impl Zeroize for Blake3HashBytes {
    fn zeroize(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Debug, Default, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Encode, Decode)]
pub struct SldTld {
    unchecked: String,
    checked: String,
    activity_id: Byte32Array,
}

impl SldTld {
    #[cfg(feature = "frost_ops")]
    pub fn new(sld_tld_str: &str, activity_id: Byte32Array) -> FrostOpsResult<Self> {
        let checked = fqdn::FQDN::from_str(sld_tld_str)
            .or(Err(FrostOpsError::InvalidSldTld))?
            .to_string();
        let (first, second) = checked
            .split_once(".")
            .ok_or(FrostOpsError::InvalidSldTld)?;

        if first.is_empty() || second.is_empty() {
            return Err(FrostOpsError::InvalidSldTld);
        }

        Ok(Self {
            unchecked: sld_tld_str.to_string(),
            checked,
            activity_id,
        })
    }

    pub fn unchecked(&self) -> &str {
        self.unchecked.as_str()
    }

    pub fn checked(&self) -> &str {
        self.checked.as_str()
    }

    pub fn activity_id(&self) -> Byte32Array {
        self.activity_id
    }

    pub fn to_storage_key(&self) -> Blake3HashBytes {
        let mut hasher = blake3::Hasher::new();
        hasher
            .update(self.checked.as_bytes())
            .update(&self.activity_id.0);

        Blake3HashBytes::pre_hashed(hasher.finalize())
    }
}
