use state::UpdateMsg;
use state::Updater;
use std::fmt;
use string::StaticStr;

#[derive(Copy, Clone)]
pub enum Cost {
    LOW,
    MEDIUM,
    HIGH,
}

impl fmt::Display for Cost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_static_str())
    }
}

impl StaticStr for Cost {
    fn as_static_str(&self) -> &'static str {
        match self {
            Cost::LOW => "LOW",
            Cost::MEDIUM => "MEDIUM",
            Cost::HIGH => "HIGH",
        }
    }
}

impl Updater for Cost {
    fn update(&self) -> UpdateMsg {
        UpdateMsg::Cost(*self)
    }
}

impl Default for Cost {
    fn default() -> Self {
        Cost::MEDIUM
    }
}
