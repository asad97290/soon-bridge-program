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
        instruction::AccountMeta,
    entrypoint::ProgramResult, program_error::ProgramError, pubkey, pubkey::Pubkey,
};
use solana_sdk::transaction::{SanitizedTransaction, Transaction, VersionedTransaction};
use solana_sdk::signature::{Keypair, Signature, Signer};
use solana_program_test::*;



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
    use ethabi::Address;
    use solana_program::account_info::AccountInfo;
    use spl_token::state::Account;

    use super::*;
   
    #[tokio::test] // for async test
    async fn test_create_spl_encoding() -> Result<(), ProgramError> {
        println!("-------------------------->");

        let program_id = crate::id();
        let (soon_client, payer, recent_blockhash) =
            ProgramTest::new("soon-bridge", program_id, processor!(entrypoint::process_instruction))
                .start()
                .await;
        // let payer = Keypair::new();

        let remote_token = [0u8; 20];
        let name = "name";
        let symbol = "symbol";
        let decimals = 9;

        let instruction = instruction::create_spl(
            remote_token.into(),
            payer.pubkey(),
            name,
            symbol,
            decimals,
        )?;
        // println!("-------------------------->{:?}",instruction);
        let payer2 = &payer;
        let mut tx = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&payer.pubkey()),
            &[&payer],
            recent_blockhash,
        );
        tx.sign(&[payer2], recent_blockhash);
        let transaction_result = soon_client.process_transaction(tx).await;
        println!("-------------------------->{:?}",transaction_result);



        Ok(())

    }
}
