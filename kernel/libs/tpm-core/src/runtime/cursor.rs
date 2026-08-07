/// 大端读取游标（runtime 版）。
#[derive(Clone, Copy, Debug, Default)]
pub struct Cursor {
    pub pos: usize,
}

impl Cursor {
    #[inline]
    pub fn new() -> Self {
        Self { pos: 0 }
    }

    #[inline]
    pub fn at(pos: usize) -> Self {
        Self { pos }
    }

    #[inline]
    pub fn read_be32(&mut self, data: &[u8]) -> Option<u32> {
        let n = data.len();
        if n >= 4 && self.pos <= n - 4 {
            let b0 = data[self.pos];
            let b1 = data[self.pos + 1];
            let b2 = data[self.pos + 2];
            let b3 = data[self.pos + 3];
            self.pos += 4;
            Some(u32::from_be_bytes([b0, b1, b2, b3]))
        } else {
            None
        }
    }
}
