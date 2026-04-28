/// Discriminant for an `OnionCell`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnionCellType {
    RelayData = 0,
    RelayControl = 1,
    Padding = 2,
    Cover = 3,
    Destroy = 4,
    KeepAlive = 5,
}

impl OnionCellType {
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::RelayData),
            1 => Some(Self::RelayControl),
            2 => Some(Self::Padding),
            3 => Some(Self::Cover),
            4 => Some(Self::Destroy),
            5 => Some(Self::KeepAlive),
            _ => None,
        }
    }
}
