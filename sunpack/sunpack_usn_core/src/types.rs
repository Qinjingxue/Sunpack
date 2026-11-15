#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ChangeReasons {
    pub all: u32,
    pub without_close: u32,
}

#[cfg(feature = "journal")]
impl ChangeReasons {
    pub(crate) fn observe(&mut self, reason: u32) {
        self.all |= reason;
        if reason & 0x8000_0000 == 0 {
            self.without_close |= reason;
        }
    }
}
