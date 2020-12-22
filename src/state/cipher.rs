use state::UpdateMsg;
use state::Updater;
use std::fmt;
use string::StaticStr;

#[derive(Copy, Clone)]
pub enum Cipher {
    AESCBC,
    CHACHA20,
    SALSA20,
}

impl fmt::Display for Cipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_static_str())
    }
}

impl StaticStr for Cipher {
    fn as_static_str(&self) -> &'static str {
        match self {
            Cipher::AESCBC => "AES-CBC",
            Cipher::CHACHA20 => "CHACHA20",
            Cipher::SALSA20 => "SALSA20",
        }
    }
}

impl Updater for Cipher {
    fn update(&self) -> UpdateMsg {
        UpdateMsg::Cipher(*self)
    }
}

impl Default for Cipher {
    fn default() -> Self {
        Cipher::AESCBC
    }
}
