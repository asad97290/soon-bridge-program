#![allow(clippy::arithmetic_side_effects)]
#![deny(missing_docs)]
#![cfg_attr(not(test), forbid(unsafe_code))]

//! A withdrawal bridge for the soon blockchain

pub mod error;
pub mod instruction;
pub mod pda;
pub mod processor;
pub mod state;

#[cfg(not(feature = "no-entrypoint"))]
mod entrypoint;

pub use solana_program;
use solana_program::{
    entrypoint::ProgramResult, program_error::ProgramError, pubkey, pubkey::Pubkey,
};

solana_program::declare_id!("Bridge1111111111111111111111111111111111111");

/// No-sig tx payer pubkey
pub const NO_SIG_TX_PAYER: Pubkey = pubkey!("NoSigTxPayer1111111111111111111111111111111");

/// Checks that the supplied program ID is the correct one for bridge
pub fn check_program_account(bridge_program_id: &Pubkey) -> ProgramResult {
    if bridge_program_id != &id() {
        return Err(ProgramError::IncorrectProgramId);
    }
    Ok(())
}





#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_str_encoding() -> Result<(), ProgramError> {
        let s = "hello";
        let packed = BridgeInstruction::pack_str(s)?;
        let (unpacked, _) = BridgeInstruction::unpack_str(&packed)?;
        assert_eq!(s, unpacked);

        let s = "abcdefghijklmnopqrstuvwxyz1234567890";
        let packed = BridgeInstruction::pack_str(s)?;
        let (unpacked, _) = BridgeInstruction::unpack_str(&packed)?;
        assert_eq!(s, unpacked);

        // Test string at max length
        let mut long_str = String::new();
        for _ in 0..=256 {
            long_str.push('a');
        }
        let packed = BridgeInstruction::pack_str(s)?;
        let (unpacked, _) = BridgeInstruction::unpack_str(&packed)?;
        assert_eq!(s, unpacked);

        // Test string too long
        long_str = String::new();
        for _ in 0..=257 {
            long_str.push('a');
        }
        assert_eq!(
            BridgeInstruction::pack_str(&long_str),
            Err(BridgeError::StringLengthTooLong)
        );
        Ok(())
    }

    #[test]
    fn test_create_spl_encoding() -> Result<(), ProgramError> {
        let remote_token = [0u8; 20];
        let name = "name";
        let symbol = "symbol";
        let decimals = 18;

        let instruction = BridgeInstruction::CreateSPL {
            remote_token: remote_token.into(),
            name,
            symbol,
            decimals,
        };

        let packed_data = instruction.pack()?;
        let unpacked_instruction = BridgeInstruction::unpack(&packed_data)?;
        assert_eq!(
            instruction, unpacked_instruction,
            "Unpacked instruction did not match original"
        );
        Ok(())
    }
}