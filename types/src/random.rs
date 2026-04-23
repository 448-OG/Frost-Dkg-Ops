use rand_chacha::{
    ChaCha12Rng, ChaCha20Rng,
    rand_core::{RngCore, SeedableRng},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub struct RandomBytes<const N: usize>(Zeroizing<[u8; N]>);

impl<const N: usize> RandomBytes<N> {
    pub fn generate() -> Self {
        let mut rng = ChaCha20Rng::from_os_rng();

        let mut buffer = Zeroizing::new([0u8; N]);

        rng.fill_bytes(buffer.as_mut());

        Self(buffer)
    }

    pub fn generate_chacha_12() -> Self {
        let mut rng = ChaCha12Rng::from_os_rng();

        let mut buffer = Zeroizing::new([0u8; N]);

        rng.fill_bytes(buffer.as_mut());

        Self(buffer)
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
