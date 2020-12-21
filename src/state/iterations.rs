use std::fmt;
use string::StaticStr;
use state::UpdateMsg;
use state::Updater;

#[derive(Copy, Clone)]
pub enum Iterations {
    LOW,
    MEDIUM,
    HIGH,
}

impl fmt::Display for Iterations {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_static_str())
    }
}

impl StaticStr for Iterations {
    fn as_static_str(&self) -> &'static str {
        match self {
            Iterations::LOW => "LOW",
            Iterations::MEDIUM => "MEDIUM",
            Iterations::HIGH => "HIGH",
        }
    }
}

impl Updater for Iterations {
    fn update(&self) -> UpdateMsg {
        UpdateMsg::Iterations(*self)
    }
}

impl Default for Iterations {
    fn default() -> Self {
        Iterations::MEDIUM
    }
}
