use bitcode::{Decode, Encode};

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Encode, Decode, Hash)]
pub enum TransmitType {
    Unicast = 0,
    NarrowCast = 1,
    Broadcast = 2,
}
