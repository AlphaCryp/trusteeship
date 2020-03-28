//! pub use const BUNDLED_CELL: Files
//! pub use const CODE_HASH_DAO: [u8; 32]

#![allow(clippy::unreadable_literal)]

include!(concat!(env!("OUT_DIR"), "/bundled.rs"));
include!(concat!(env!("OUT_DIR"), "/code_hashes.rs"));

#[cfg(test)]
mod tests;
