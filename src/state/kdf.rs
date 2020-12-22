use state::iterations::Iterations;
use state::UpdateMsg;
use state::Updater;
use std::fmt;
use string::StaticStr;

#[derive(Copy, Clone)]
pub enum KDF {
    PBKDF2,
    ARGON2,
}

pub enum KDFCost {
    // iterations
    PBKDF2(u32),
    // mem cost, time cost
    ARGON2(u32, u32),
}

impl fmt::Display for KDF {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_static_str())
    }
}

impl StaticStr for KDF {
    fn as_static_str(&self) -> &'static str {
        match self {
            KDF::PBKDF2 => "PBKDF2",
            KDF::ARGON2 => "ARGON2",
        }
    }
}

impl Updater for KDF {
    fn update(&self) -> UpdateMsg {
        UpdateMsg::KDF(*self)
    }
}

impl Default for KDF {
    fn default() -> Self {
        KDF::PBKDF2
    }
}

impl KDF {
    pub fn cost(&self, iterations: Iterations) -> KDFCost {
        match self {
            KDF::PBKDF2 => match iterations {
                Iterations::LOW => KDFCost::PBKDF2(10_000),
                Iterations::MEDIUM => KDFCost::PBKDF2(100_000),
                Iterations::HIGH => KDFCost::PBKDF2(1_000_000),
            },
            KDF::ARGON2 => match iterations {
                Iterations::LOW => KDFCost::ARGON2(65536, 10),
                Iterations::MEDIUM => KDFCost::ARGON2(65536, 10),
                Iterations::HIGH => KDFCost::ARGON2(65536, 10),
            },
        }
    }
}
