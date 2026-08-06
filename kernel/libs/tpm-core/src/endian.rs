
pub fn be16_of_exec(b0: u8, b1: u8) -> u16 {
    ((b0 as u16) << 8) | (b1 as u16)
}
pub fn be32_of_exec(b0: u8, b1: u8, b2: u8, b3: u8) -> u32 {
    ((b0 as u32) << 24) | ((b1 as u32) << 16) | ((b2 as u32) << 8) | (b3 as u32)
}
