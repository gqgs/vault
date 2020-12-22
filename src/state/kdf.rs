use state::cost::Cost;
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
    // Cost
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
    pub fn cost(&self, cost: Cost) -> KDFCost {
        match self {
            KDF::PBKDF2 => match cost {
                Cost::LOW => KDFCost::PBKDF2(10_000),
                Cost::MEDIUM => KDFCost::PBKDF2(100_000),
                Cost::HIGH => KDFCost::PBKDF2(1_000_000),
            },
            KDF::ARGON2 => match cost {
                Cost::LOW => KDFCost::ARGON2(u32::pow(2, 16), 6),
                Cost::MEDIUM => KDFCost::ARGON2(u32::pow(2, 20), 8),
                Cost::HIGH => KDFCost::ARGON2(u32::pow(2, 22), 10),
            },
        }
    }
}
