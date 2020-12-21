use std::fmt;
use string::StaticStr;
use state::UpdateMsg;
use state::Updater;

#[derive(Copy, Clone)]
pub enum Hash {
    RIPEMD160,
    BLAKE2B,
    BLAKE2S,
    SHA2_256,
    SHA2_384,
    SHA2_512,
    SHA3_256,
    SHA3_384,
    SHA3_512,
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_static_str())
    }
}

impl StaticStr for Hash {
    fn as_static_str(&self) -> &'static str {
        match self {
            Hash::RIPEMD160 => "RIPEMD-160",
            Hash::BLAKE2B => "BLAKE2B",
            Hash::BLAKE2S => "BLAKE2S",
            Hash::SHA2_256 => "SHA-256",
            Hash::SHA2_384 => "SHA-384",
            Hash::SHA2_512 => "SHA-512",
            Hash::SHA3_256 => "SHA3-256",
            Hash::SHA3_384 => "SHA3-384",
            Hash::SHA3_512 => "SHA3-512",
        }
    }
}

impl Updater for Hash {
    fn update(&self) -> UpdateMsg {
        UpdateMsg::Hash(*self)
    }
}

impl Default for Hash {
    fn default() -> Self {
        Hash::SHA2_256
    }
}
