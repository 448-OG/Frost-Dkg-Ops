use getrandom::SysRng;
use rand_chacha::{
    ChaCha12Rng, ChaCha20Rng,
    rand_core::{Rng, SeedableRng},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{FrostOpsError, FrostOpsResult};

pub struct RandomBytes<const N: usize>(Zeroizing<[u8; N]>);

impl<const N: usize> RandomBytes<N> {
    pub fn generate() -> FrostOpsResult<Self> {
        let mut rng =
            ChaCha20Rng::try_from_rng(&mut SysRng).or(Err(FrostOpsError::BadRandomness))?;

        let mut buffer = Zeroizing::new([0u8; N]);

        rng.fill_bytes(buffer.as_mut());

        Ok(Self(buffer))
    }

    pub fn generate_chacha_12() -> FrostOpsResult<Self> {
        let mut rng =
            ChaCha12Rng::try_from_rng(&mut SysRng).or(Err(FrostOpsError::BadRandomness))?;

        let mut buffer = Zeroizing::new([0u8; N]);

        rng.fill_bytes(buffer.as_mut());

        Ok(Self(buffer))
    }

    pub fn expose(&self) -> &[u8; N] {
        &self.0
    }

    pub fn take(self) -> Zeroizing<[u8; N]> {
        self.0
    }

    pub fn const_cmp(&self, other: &RandomBytes<N>) -> bool {
        self.expose().ct_eq(other.expose()).into()
    }

    pub fn const_cmp_bytes(&self, other: &[u8; N]) -> bool {
        self.expose().ct_eq(other.as_slice()).into()
    }
}
