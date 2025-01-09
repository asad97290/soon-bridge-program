//! Program state processor

use crate::state::BridgeOwner;
use ethnum::U256;
use spl_associated_token_account::instruction::create_associated_token_account_idempotent;
use {
    crate::{
        error::BridgeError,
        instruction::BridgeInstruction,
        pda::*,
        state::{
            BridgeConfig, ETHWithdrawalCalldata, ETHWithdrawalTransaction, SPLWithdrawalCalldata,
            SPLWithdrawalTransaction, WithdrawalCounter, ETH_WITHDRAWAL_TRANSACTION_CALLDATA_LEN,
            SPL_WITHDRAWAL_TRANSACTION_CALLDATA_LEN,
        },
    },
    arrayref::array_ref,
    ethabi::{encode, Address, Bytes, Token, Uint},
    keccak_hash::keccak_256,
    //mpl_token_metadata::{
    //    instructions::{CreateMetadataAccountV3, CreateMetadataAccountV3InstructionArgs},
    //    programs::MPL_TOKEN_METADATA_ID,
    //    types::DataV2,
    //},
    solana_program::{
        account_info::AccountInfo,
        entrypoint::ProgramResult,
        msg,
        program::invoke,
        program::invoke_signed,
        program_error::ProgramError,
        program_memory::sol_memcmp,
        program_pack::Pack,
        pubkey::{Pubkey, PUBKEY_BYTES},
        system_instruction::{create_account, transfer},
        sysvar::{rent::Rent, Sysvar},
    },
    spl_token::{
        check_program_account,
        instruction::{burn, initialize_mint, mint_to},
        state::Mint,
    },
};

/// SPE Bridge share decimal
pub const SPL_SHARE_DECIMAL: u8 = 12;

/// Program state handler.
pub struct Processor {}
impl Processor {
    #[deprecated(note = "This processor is no longer used")]
    fn create_vault_account(_program_id: &Pubkey, _accounts: &[AccountInfo]) -> ProgramResult {
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn deposit_eth(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        _from: Address,
        _to: Address,
        _mint: u128,
        value: u128,
        _gas: u64,
        _is_creation: bool,
        _l1_block_num: u64,
        _l1_block_hash: [u8; 32],
        _log_index: u128,
        _deposit_type: u8,
        _deposit_from: Address,
        deposit_to: Pubkey,
        _deposit_amount: u128,
        _deposit_extra_data: [u8; 32],
        _deposit_l2_contract: Pubkey,
        _deposit_l1_contract: Address,
    ) -> ProgramResult {
        const NUM_FIXED: usize = 4;
        let accounts = array_ref![accounts, 0, NUM_FIXED];
        let [
            system_program_account,    // read
            depositor_account,         // read
            vault_account,             // write
            no_sig_tx_payer_account,   // read
        ] = accounts;

        if !Self::cmp_pubkeys(no_sig_tx_payer_account.key, &crate::NO_SIG_TX_PAYER)
            || !no_sig_tx_payer_account.is_signer
        {
            return Err(BridgeError::InvalidNoSigTxPayer.into());
        }

        let (vault_key, vault_seed) = vault_pubkey_and_bump(program_id);
        if !Self::cmp_pubkeys(&vault_key, vault_account.key) {
            return Err(BridgeError::InvalidVaultAccount.into());
        }

        if !Self::cmp_pubkeys(&deposit_to, depositor_account.key) {
            return Err(BridgeError::InvalidDepositorAccount.into());
        }

        // Transfer lamports from vault to depositor
        let min_balance = Rent::get()?.minimum_balance(0);
        let mut transfer_value = value as u64;

        // Only do this if the depositor account does not exist
        if transfer_value < min_balance && depositor_account.lamports() == 0 {
            transfer_value = min_balance;
        }
        msg!("Deposit value: {}", value);
        msg!("Transfer value: {}", transfer_value);

        let instruction = transfer(vault_account.key, depositor_account.key, transfer_value);
        invoke_signed(
            &instruction,
            &[
                system_program_account.clone(),
                vault_account.clone(),
                depositor_account.clone(),
            ],
            &[&vault_signer_seeds(&[vault_seed])],
        )?;

        Ok(())
    }

    #[deprecated(note = "This processor is no longer used")]
    fn create_withdrawal_counter_account(
        _program_id: &Pubkey,
        _accounts: &[AccountInfo],
    ) -> ProgramResult {
        Ok(())
    }

    fn withdraw_eth(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        target: Address,
        value: u128,
        gas_limit: u128,
    ) -> ProgramResult {
        const NUM_FIXED: usize = 7;
        let accounts = array_ref![accounts, 0, NUM_FIXED];
        let [
            system_program_account,              // read
            rent_sysvar_account,                 // read
            user_withdrawal_counter_account,     // write
            withdrawal_transaction_account,      // write
            vault_account,                       // write
            bridge_config_account,               // read
            payer_account                        // signer
        ] = accounts;

        let bridge_config_key = config_pubkey();
        if !Self::cmp_pubkeys(&bridge_config_key, bridge_config_account.key) {
            return Err(BridgeError::InvalidBridgeConfigAccount.into());
        }

        let (user_withdrawal_counter_key, _) =
            user_withdrawal_counter_pubkey_and_bump(program_id, payer_account.key);
        if !Self::cmp_pubkeys(
            &user_withdrawal_counter_key,
            user_withdrawal_counter_account.key,
        ) {
            return Err(BridgeError::InvalidWithdrawalCounterAccount.into());
        }
        let counter =
            WithdrawalCounter::unpack(&user_withdrawal_counter_account.data.borrow())?.counter;
        let new_count = counter + 1;
        WithdrawalCounter::pack(
            WithdrawalCounter { counter: new_count },
            &mut user_withdrawal_counter_account.data.borrow_mut(),
        )?;

        let (withdrawal_transaction_key, bump) =
            withdrawal_transaction_pubkey_and_bump(payer_account.key, counter, program_id);
        if !Self::cmp_pubkeys(
            &withdrawal_transaction_key,
            withdrawal_transaction_account.key,
        ) {
            return Err(BridgeError::InvalidWithdrawalTransactionAccount.into());
        }

        // Ensure provided vault key is the right derived address
        let vault_key = vault_pubkey();
        if !Self::cmp_pubkeys(&vault_key, vault_account.key) {
            return Err(BridgeError::InvalidVaultAccount.into());
        }

        // transfer withdraw value to vault account
        msg!("Withdrawal value: {}", value);
        if value > 0 {
            
            let transfer_instruction = transfer(payer_account.key, &vault_key, value as u64); // @audit unsafe down cast from u128 to u64
            invoke(
                &transfer_instruction,
                &[
                    payer_account.clone(),
                    vault_account.clone(),
                    system_program_account.clone(),
                ],
            )?;
        }

        let withdrawal_transaction_size = ETHWithdrawalTransaction::LEN;
        let rent = Rent::from_account_info(rent_sysvar_account)?;
        let create_withdrawal_transaction_instruction = create_account(
            payer_account.key,
            withdrawal_transaction_account.key,
            rent.minimum_balance(withdrawal_transaction_size),
            withdrawal_transaction_size as u64,
            program_id,
        );
        let create_withdrawal_transaction_accounts = [
            system_program_account.clone(),
            payer_account.clone(),
            withdrawal_transaction_account.clone(),
        ];
        invoke_signed(
            &create_withdrawal_transaction_instruction,
            &create_withdrawal_transaction_accounts,
            // &[&withdrawal_transaction_signer_seeds(payer_account.key, &counter.to_le_bytes(), &[bump])],
            &[&[payer_account.key.as_ref(), &counter.to_le_bytes(), &[bump]]],
        )?;

        let bridge_config = BridgeConfig::unpack(&bridge_config_account.data.borrow())?;
        let calldata = get_bridge_eth_calldata(
            program_id,
            &bridge_config.l1_standard_bridge,
            payer_account.key,
            &target,
            value,
            gas_limit,
            counter,
        );
        let calldata_bytes: [u8; ETH_WITHDRAWAL_TRANSACTION_CALLDATA_LEN] = calldata
            .try_into()
            .map_err(|_| ProgramError::InvalidAccountData)?;
        let withdrawal_transaction_info = ETHWithdrawalTransaction {
            nonce: U256::from(counter),
            sender: *program_id,
            target: bridge_config.l1_cross_domain_messenger,
            value: U256::from(value),
            gas_limit: U256::from(gas_limit),
            data: ETHWithdrawalCalldata {
                data: calldata_bytes,
            },
        };

        ETHWithdrawalTransaction::pack(
            withdrawal_transaction_info,
            &mut withdrawal_transaction_account.data.borrow_mut(),
        )?;

        Ok(())
    }

    fn change_bridge_admin(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        new_admin: Pubkey,
    ) -> ProgramResult {
        const NUM_FIXED: usize = 2;
        let accounts = array_ref![accounts, 0, NUM_FIXED];
        let [
            bridge_owner_account,      // write
            admin_account,             // signer
        ] = accounts;

        // Check bridge owner account and admin
        let (bridge_owner_key, _) = bridge_owner_pubkey_and_bump(program_id);
        if !Self::cmp_pubkeys(&bridge_owner_key, bridge_owner_account.key) {
            return Err(BridgeError::InvalidBridgeOwnerAccount.into());
        }
        let mut bridge_owner = BridgeOwner::unpack(&bridge_owner_account.data.borrow())?;
        if bridge_owner.admin != *admin_account.key || !admin_account.is_signer {
            return Err(BridgeError::InvalidAdmin.into());
        }
        // @audit single step admin change
        bridge_owner.admin = new_admin;
        BridgeOwner::pack(bridge_owner, &mut bridge_owner_account.data.borrow_mut())?;

        Ok(())
    }

    fn create_spl(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        remote_token: Address,
        name: &str,
        symbol: &str,
        decimals: u8,
    ) -> ProgramResult {
        const NUM_FIXED: usize = 8;
        let accounts = array_ref![accounts, 0, NUM_FIXED];
        let [
            system_program_account,       // read
            rent_sysvar_account,          // read
            spl_token_program_account,    // read
            spl_token_owner_account,      // read
            spl_token_mint_account,       // write
            vault_account,                // write
            bridge_owner_account,         // read
            admin_account,                // read,signer
            ] = accounts;
            
            check_program_account(spl_token_program_account.key)
            .map_err(|_| BridgeError::InvalidSPLTokenProgramId)?;
        
        /*
        if !Self::cmp_pubkeys(&mpl_token_metadata_account.key, &MPL_TOKEN_METADATA_ID) {
            return Err(BridgeError::InvalidMPLTokenMetadataAccount.into());
            }
            
            // TODO:
            // check metadata account
            // address=find_metadata_account(&index_token_mint.key()).0
            */
            
            // Ensure provided vault key is the right derived address
            let (vault_key, vault_bump) = vault_pubkey_and_bump(program_id);
            if !Self::cmp_pubkeys(&vault_key, vault_account.key) {
                return Err(BridgeError::InvalidVaultAccount.into());
            }
            
            // Check bridge owner account and admin
            let (bridge_owner_key, _) = bridge_owner_pubkey_and_bump(program_id);
            if !Self::cmp_pubkeys(&bridge_owner_key, bridge_owner_account.key) {
                return Err(BridgeError::InvalidBridgeOwnerAccount.into());
            }
            println!("===========create_spl============{:?},{:?}",bridge_owner_key,bridge_owner_account.key);
            let bridge_owner = BridgeOwner::unpack(&bridge_owner_account.data.borrow())?;
            if bridge_owner.admin != *admin_account.key || !admin_account.is_signer {
                return Err(BridgeError::InvalidAdmin.into());
            }
            
            // Create SPL token owner
            let (spl_token_owner_key, _) = spl_token_owner_pubkey_and_bump(&remote_token, program_id);
            if !Self::cmp_pubkeys(&spl_token_owner_key, spl_token_owner_account.key) {
                return Err(BridgeError::InvalidSPLTokenOwnerAccount.into());
            }
            
            // Create & init SPL token mint
            let (spl_token_mint_key, spl_token_mint_bump) =
            spl_token_mint_pubkey_and_bump(&remote_token, program_id);
            if !Self::cmp_pubkeys(&spl_token_mint_key, spl_token_mint_account.key) {
                return Err(BridgeError::InvalidSPLTokenMintAccount.into());
            }
            
        let rent = Rent::from_account_info(rent_sysvar_account)?;
        let instruction = create_account(
            vault_account.key,
            spl_token_mint_account.key,
            rent.minimum_balance(Mint::LEN),
            Mint::LEN as u64,
            spl_token_program_account.key,
        );
        invoke_signed(
            &instruction,
            &[
                system_program_account.clone(),
                vault_account.clone(),
                spl_token_mint_account.clone(),
            ],
            &[
                &vault_signer_seeds(&[vault_bump]),
                &spl_token_mint_signer_seeds(&remote_token, &[spl_token_mint_bump]),
            ],
        )?;

        let instruction = initialize_mint(
            spl_token_program_account.key,
            &spl_token_mint_key,
            &spl_token_owner_key,
            None,
            decimals,
        )?;
        invoke(
            &instruction,
            &[spl_token_mint_account.clone(), rent_sysvar_account.clone()],
        )?;

        /*
        // Store SPL token metadata
        invoke_signed(
            &CreateMetadataAccountV3::instruction(
                &CreateMetadataAccountV3 {
                    metadata: *metadata_account.key,
                    mint: spl_token_mint_key,
                    mint_authority: spl_token_info_key,
                    payer: admin,
                    update_authority: (admin, false),
                    system_program: *system_program_account.key,
                    rent: Some(*rent_sysvar_account.key),
                },
                CreateMetadataAccountV3InstructionArgs {
                    data: DataV2 {
                        name: name.to_string(),
                        symbol: symbol.to_string(),
                        uri: "".to_string(),
                        seller_fee_basis_points: 0,
                        creators: None,
                        collection: None,
                        uses: None,
                    },
                    is_mutable: true,
                    collection_details: None,
                },
            ),
            &[
                metadata_account.clone(),
                spl_token_mint_account.clone(),
                spl_token_info_account.clone(),
                admin_account.clone(),
                rent_sysvar_account.clone(),
            ],
            &[&[remote_token.as_ref(), &[spl_token_mint_bump]]],
        )?;
         */

        msg!("name: {:?}", name);
        msg!("symbol: {:?}", symbol);
        msg!("decimals: {:?}", decimals);

        Ok(())
    }

    fn deposit_erc20(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        local_token: Pubkey,
        remote_token: Address,
        _from: Address,
        to: Pubkey,
        amount: u128,
    ) -> ProgramResult {
        const NUM_FIXED: usize = 9;
        let accounts = array_ref![accounts, 0, NUM_FIXED];
        let [
            system_program_account,               // read
            spl_token_program_account,            // read
            associated_token_program_account,     // read
            spl_token_owner_account,              // read
            spl_token_mint_account,               // write
            depositor_account,                    // read
            depositor_associated_token_account,   // write
            vault_account,                        // write
            no_sig_tx_payer_account,              // read
        ] = accounts;

        if !Self::cmp_pubkeys(no_sig_tx_payer_account.key, &crate::NO_SIG_TX_PAYER)
            || !no_sig_tx_payer_account.is_signer
        {
            return Err(BridgeError::InvalidNoSigTxPayer.into());
        }

        check_program_account(spl_token_program_account.key)
            .map_err(|_| BridgeError::InvalidSPLTokenProgramId)?;

        if associated_token_program_account.key != &spl_associated_token_account::ID {
            return Err(BridgeError::InvalidAssociatedTokenProgramId.into());
        }

        if !Self::cmp_pubkeys(&to, depositor_account.key) {
            return Err(BridgeError::InvalidDepositorAccount.into());
        }

        // Ensure provided vault key is the right derived address
        let (vault_key, vault_bump) = vault_pubkey_and_bump(program_id);
        if !Self::cmp_pubkeys(&vault_key, vault_account.key) {
            return Err(BridgeError::InvalidVaultAccount.into());
        }

        if !Self::cmp_pubkeys(&local_token, spl_token_mint_account.key) {
            return Err(BridgeError::InvalidSPLTokenMintAccount.into());
        }

        let (spl_token_owner_key, spl_token_owner_bump) =
            spl_token_owner_pubkey_and_bump(&remote_token, program_id);
        if !Self::cmp_pubkeys(&spl_token_owner_key, spl_token_owner_account.key) {
            return Err(BridgeError::InvalidSPLTokenOwnerAccount.into());
        }

        let (spl_token_mint_key, _) = spl_token_mint_pubkey_and_bump(&remote_token, program_id);
        if !Self::cmp_pubkeys(&spl_token_mint_key, spl_token_mint_account.key) {
            return Err(BridgeError::InvalidSPLTokenMintAccount.into());
        }

        // Create spl token account if not exists
        let instruction = create_associated_token_account_idempotent(
            vault_account.key,
            depositor_account.key,
            spl_token_mint_account.key,
            spl_token_program_account.key,
        );
        invoke_signed(
            &instruction,
            &[
                system_program_account.clone(),
                spl_token_program_account.clone(),
                associated_token_program_account.clone(),
                depositor_account.clone(),
                depositor_associated_token_account.clone(),
                spl_token_mint_account.clone(),
                vault_account.clone(),
            ],
            &[&vault_signer_seeds(&[vault_bump])],
        )?;

        // Mint spl tokens to the target
        let spl_token_decimals = Mint::unpack(&spl_token_mint_account.data.borrow())?.decimals;
        let amount = Self::convert_decimal(amount, SPL_SHARE_DECIMAL, spl_token_decimals);
        msg!("Deposit amount: {}", amount);

        let instruction = mint_to(
            spl_token_program_account.key,
            spl_token_mint_account.key,
            depositor_associated_token_account.key,
            spl_token_owner_account.key,
            &[],
            amount as u64,
        )?;
        invoke_signed(
            &instruction,
            &[
                spl_token_program_account.clone(),
                spl_token_mint_account.clone(),
                depositor_associated_token_account.clone(),
                spl_token_owner_account.clone(),
                vault_account.clone(),
            ],
            &[&spl_token_owner_signer_seeds(
                &remote_token,
                &[spl_token_owner_bump],
            )],
        )?;

        Ok(())
    }

    fn withdraw_spl(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        remote_token: Address,
        to: Address,
        amount: u128,
        gas_limit: u128,
    ) -> ProgramResult {
        const NUM_FIXED: usize = 10;
        let accounts = array_ref![accounts, 0, NUM_FIXED];
        let [
            system_program_account,                 // read
            rent_sysvar_account,                    // read
            spl_token_program_account,              // read
            user_withdrawal_counter_account,        // write
            withdrawal_transaction_account,         // write
            spl_token_owner_account,                // read
            spl_token_mint_account,                 // write
            payer_spl_associated_token_account,     // write
            bridge_config_account,                  // read
            payer_account                           // signer
        ] = accounts;

        let (bridge_config_key, _) = config_pubkey_and_bump(program_id);
        if !Self::cmp_pubkeys(&bridge_config_key, bridge_config_account.key) {
            return Err(BridgeError::InvalidBridgeConfigAccount.into());
        }

        check_program_account(spl_token_program_account.key)
            .map_err(|_| BridgeError::InvalidSPLTokenProgramId)?;

        let (user_withdrawal_counter_key, _) =
            user_withdrawal_counter_pubkey_and_bump(program_id, payer_account.key);
        if !Self::cmp_pubkeys(
            &user_withdrawal_counter_key,
            user_withdrawal_counter_account.key,
        ) {
            return Err(BridgeError::InvalidWithdrawalCounterAccount.into());
        }
        let counter =
            WithdrawalCounter::unpack(&user_withdrawal_counter_account.data.borrow())?.counter;
        let new_count = counter + 1;
        WithdrawalCounter::pack(
            WithdrawalCounter { counter: new_count },
            &mut user_withdrawal_counter_account.data.borrow_mut(),
        )?;

        let (withdrawal_transaction_key, bump) =
            withdrawal_transaction_pubkey_and_bump(payer_account.key, counter, program_id);
        if !Self::cmp_pubkeys(
            &withdrawal_transaction_key,
            withdrawal_transaction_account.key,
        ) {
            return Err(BridgeError::InvalidWithdrawalTransactionAccount.into());
        }

        let (spl_token_owner_key, _) = spl_token_owner_pubkey_and_bump(&remote_token, program_id);
        if !Self::cmp_pubkeys(&spl_token_owner_key, spl_token_owner_account.key) {
            return Err(BridgeError::InvalidSPLTokenOwnerAccount.into());
        }
        let (spl_token_mint_key, _) = spl_token_mint_pubkey_and_bump(&remote_token, program_id);
        if !Self::cmp_pubkeys(&spl_token_mint_key, spl_token_mint_account.key) {
            return Err(BridgeError::InvalidSPLTokenMintAccount.into());
        }

        // Burn SPL token on L2
        let spl_token_decimals = Mint::unpack(&spl_token_mint_account.data.borrow())?.decimals;
        let amount = Self::remove_dust(amount, spl_token_decimals, SPL_SHARE_DECIMAL);
        msg!("Withdrawal amount: {}", amount);
        if amount > 0 {
            let instruction = burn(
                spl_token_program_account.key,
                payer_spl_associated_token_account.key,
                spl_token_mint_account.key,
                payer_account.key,
                &[],
                amount as u64,
            )?;
            invoke(
                &instruction,
                &[
                    spl_token_program_account.clone(),
                    payer_spl_associated_token_account.clone(),
                    spl_token_mint_account.clone(),
                    payer_account.clone(),
                ],
            )?;
        }

        let withdrawal_transaction_size = SPLWithdrawalTransaction::LEN;
        let rent = Rent::from_account_info(rent_sysvar_account)?;
        let create_withdrawal_transaction_instruction = create_account(
            payer_account.key,
            withdrawal_transaction_account.key,
            rent.minimum_balance(withdrawal_transaction_size),
            withdrawal_transaction_size as u64,
            program_id,
        );
        let create_withdrawal_transaction_accounts = [
            system_program_account.clone(),
            payer_account.clone(),
            withdrawal_transaction_account.clone(),
        ];
        invoke_signed(
            &create_withdrawal_transaction_instruction,
            &create_withdrawal_transaction_accounts,
            &[&withdrawal_transaction_signer_seeds(
                payer_account.key,
                &counter.to_le_bytes(),
                &[bump],
            )],
        )?;

        let amount = Self::convert_decimal(amount, spl_token_decimals, SPL_SHARE_DECIMAL);
        let bridge_config = BridgeConfig::unpack(&bridge_config_account.data.borrow())?;
        let calldata = get_bridge_erc20_calldata(
            program_id,
            &bridge_config.l1_standard_bridge,
            spl_token_mint_account.key,
            &remote_token,
            payer_account.key,
            &to,
            amount,
            gas_limit,
            counter,
        );
        let calldata_bytes: [u8; SPL_WITHDRAWAL_TRANSACTION_CALLDATA_LEN] = calldata
            .try_into()
            .map_err(|_| ProgramError::InvalidAccountData)?;
        let withdrawal_transaction_info = SPLWithdrawalTransaction {
            nonce: U256::from(counter),
            sender: *program_id,
            target: bridge_config.l1_cross_domain_messenger,
            value: U256::from(0u128),
            gas_limit: U256::from(gas_limit),
            data: SPLWithdrawalCalldata {
                data: calldata_bytes,
            },
        };

        SPLWithdrawalTransaction::pack(
            withdrawal_transaction_info,
            &mut withdrawal_transaction_account.data.borrow_mut(),
        )?;

        Ok(())
    }

    #[deprecated(note = "This processor is no longer used")]
    fn create_bridge_config_account(
        _program_id: &Pubkey,
        _accounts: &[AccountInfo],
        _l1_cross_domain_messenger: Address,
        _l1_standard_bridge: Address,
    ) -> ProgramResult {
        Ok(())
    }

    fn create_user_withdrawal_counter_account(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
    ) -> ProgramResult {
        const NUM_FIXED: usize = 4;
        let accounts = array_ref![accounts, 0, NUM_FIXED];
        let [
            system_program_account,              // read
            rent_sysvar_account,                 // read
            user_withdrawal_counter_account,     // write
            payer_account                        // read
        ] = accounts;

        let (user_withdrawal_counter_key, bump) =
            user_withdrawal_counter_pubkey_and_bump(program_id, payer_account.key);
        if !Self::cmp_pubkeys(
            &user_withdrawal_counter_key,
            user_withdrawal_counter_account.key,
        ) {
            return Err(BridgeError::InvalidWithdrawalCounterAccount.into());
        }

        let user_withdrawal_counter_size = WithdrawalCounter::LEN;
        let rent = Rent::from_account_info(rent_sysvar_account)?;
        let create_user_withdrawal_counter_instruction = create_account(
            payer_account.key,
            user_withdrawal_counter_account.key,
            rent.minimum_balance(user_withdrawal_counter_size),
            user_withdrawal_counter_size as u64,
            program_id,
        );
        let create_user_withdrawal_counter_accounts = [
            system_program_account.clone(),
            payer_account.clone(),
            user_withdrawal_counter_account.clone(),
        ];
        invoke_signed(
            &create_user_withdrawal_counter_instruction,
            &create_user_withdrawal_counter_accounts,
            &[&user_withdrawal_counter_seeds(payer_account.key, &[bump])],
        )?;

        let withdrawal_counter = WithdrawalCounter { counter: 0 };
        WithdrawalCounter::pack(
            withdrawal_counter,
            &mut user_withdrawal_counter_account.data.borrow_mut(),
        )?;

        Ok(())
    }

    /// Processes an [Instruction](enum.Instruction.html).
    pub fn process(program_id: &Pubkey, accounts: &[AccountInfo], input: &[u8]) -> ProgramResult {
        let instruction = BridgeInstruction::unpack(input)?;

        match instruction {
            #[allow(deprecated)]
            BridgeInstruction::CreateVaultAccount => {
                msg!("Deprecated Instruction: CreateVaultAccount");
                Self::create_vault_account(program_id, accounts)
            }
            BridgeInstruction::DepositETH {
                from,
                to,
                mint,
                value,
                gas,
                is_creation,
                l1_block_num,
                l1_block_hash,
                log_index,
                deposit_type,
                deposit_from,
                deposit_to,
                deposit_amount,
                deposit_extra_data,
                deposit_l2_contract,
                deposit_l1_contract,
            } => {
                msg!("Instruction: Deposit");
                Self::deposit_eth(
                    program_id,
                    accounts,
                    from,
                    to,
                    mint,
                    value,
                    gas,
                    is_creation,
                    l1_block_num,
                    l1_block_hash,
                    log_index,
                    deposit_type,
                    deposit_from,
                    deposit_to,
                    deposit_amount,
                    deposit_extra_data,
                    deposit_l2_contract,
                    deposit_l1_contract,
                )
            }
            #[allow(deprecated)]
            BridgeInstruction::CreateWithdrawalCounterAccount => {
                msg!("Instruction: CreateWithdrawalCounterAccount");
                Self::create_withdrawal_counter_account(program_id, accounts)
            }
            BridgeInstruction::WithdrawETH {
                target,
                value,
                gas_limit,
            } => {
                msg!("Instruction: WithdrawETH");
                Self::withdraw_eth(program_id, accounts, target, value, gas_limit)
            }
            BridgeInstruction::CreateSPL {
                remote_token,
                name,
                symbol,
                decimals,
            } => {
                msg!("Instruction: CreateSPL");
                Self::create_spl(program_id, accounts, remote_token, name, symbol, decimals)
            }
            BridgeInstruction::DepositERC20 {
                local_token,
                remote_token,
                from,
                to,
                amount,
            } => {
                msg!("Instruction: DepositERC20");
                Self::deposit_erc20(
                    program_id,
                    accounts,
                    local_token,
                    remote_token,
                    from,
                    to,
                    amount,
                )
            }
            BridgeInstruction::WithdrawSPL {
                remote_token,
                to,
                amount,
                gas_limit,
            } => {
                msg!("Instruction: WithdrawSPL");
                Self::withdraw_spl(program_id, accounts, remote_token, to, amount, gas_limit)
            }
            #[allow(deprecated)]
            BridgeInstruction::CreateBridgeConfigAccount {
                l1_cross_domain_messenger,
                l1_standard_bridge,
            } => {
                msg!("Deprecated Instruction: CreateBridgeConfigAccount");
                Self::create_bridge_config_account(
                    program_id,
                    accounts,
                    l1_cross_domain_messenger,
                    l1_standard_bridge,
                )
            }
            BridgeInstruction::ChangeBridgeAdmin { new_admin } => {
                msg!("Instruction: ChangeBridgeAdmin");
                Self::change_bridge_admin(program_id, accounts, new_admin)
            }
            BridgeInstruction::CreateUserWithdrawalCounterAccount => {
                msg!("Instruction: CreateUserWithdrawalCounterAccount");
                Self::create_user_withdrawal_counter_account(program_id, accounts)
            }
        }
    }

    /// Checks two pubkeys for equality in a computationally cheap way using `sol_memcmp`
    pub fn cmp_pubkeys(a: &Pubkey, b: &Pubkey) -> bool {
        sol_memcmp(a.as_ref(), b.as_ref(), PUBKEY_BYTES) == 0
    }

    /// Checks two addresses for equality in a computationally cheap way using `sol_memcmp`
    pub fn cmp_addresses(a: &Address, b: &Address) -> bool {
        sol_memcmp(a.as_ref(), b.as_ref(), 20) == 0
    }

    /// Remove dust from the giving source decimals into the giving target decimals.
    pub fn remove_dust(amount: u128, from_decimal: u8, to_decimal: u8) -> u128 {
        if from_decimal <= to_decimal {
            return amount;
        }

        let conversion_rate: u128 = 10_u128.pow((from_decimal - to_decimal) as u32);
        amount / conversion_rate * conversion_rate
    }

    /// Convert an amount from the giving source decimals into the giving target decimals.
    pub fn convert_decimal(amount: u128, from_decimal: u8, to_decimal: u8) -> u128 {
        if from_decimal > to_decimal {
            let conversion_rate: u128 = 10_u128.pow((from_decimal - to_decimal) as u32);
            amount / conversion_rate
        } else {
            let conversion_rate: u128 = 10_u128.pow((to_decimal - from_decimal) as u32);
            amount * conversion_rate
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn get_bridge_eth_calldata(
    program_id: &Pubkey,
    l1_standard_bridge: &Address,
    sender: &Pubkey,
    target: &Address,
    value: u128,
    gas_limit: u128,
    counter: u64,
) -> Vec<u8> {
    let inner_selector = "finalizeBridgeETH(bytes32,address,uint256,bytes)"; // from, to, value, extraData
    let sender_token = Token::FixedBytes(Bytes::from(sender.to_bytes()));
    let target_token = Token::Address(*target);
    let value_token = Token::Uint(value.into());

    let extra_data = b"";
    let extra_data_bytes = Bytes::from(extra_data.as_ref());
    let extra_data_token = Token::Bytes(extra_data_bytes);

    let inner_params = vec![
        sender_token,
        target_token.clone(),
        value_token.clone(),
        extra_data_token.clone(),
    ];
    let inner_encoded_data = encode_with_selector(inner_selector, inner_params);
    let message_token = Token::Bytes(inner_encoded_data);

    let sender_token = Token::FixedBytes(Bytes::from(program_id.to_bytes()));
    let l1_standard_bridge_token = Token::Address(*l1_standard_bridge);
    let gas_limit_token = Token::Uint(gas_limit.into());

    let msg_nonce = encode_versioned_nonce(counter);
    let nonce_token = Token::Uint(msg_nonce);

    let outer_params = vec![
        nonce_token.clone(),
        sender_token.clone(),
        l1_standard_bridge_token.clone(),
        value_token.clone(),
        gas_limit_token.clone(),
        message_token.clone(),
    ];

    // nonce, sender, target, value, mint_gas_limit, message
    let outer_selector = "relayMessage(uint256,bytes32,address,uint256,uint256,bytes)";
    encode_with_selector(outer_selector, outer_params)
}

#[allow(clippy::too_many_arguments)]
fn get_bridge_erc20_calldata(
    program_id: &Pubkey,
    l1_standard_bridge: &Address,
    local_token: &Pubkey,
    remote_token: &Address,
    from: &Pubkey,
    to: &Address,
    amount: u128,
    gas_limit: u128,
    counter: u64,
) -> Vec<u8> {
    let inner_selector = "finalizeBridgeERC20(address,bytes32,bytes32,address,uint256,bytes)"; // remoteToken, localToken, from, to, extraData
    let local_token_bytes = Bytes::from(local_token.to_bytes());
    let local_token_token = Token::FixedBytes(local_token_bytes);

    let remote_token_token = Token::Address(*remote_token);
    let from_bytes = Bytes::from(from.to_bytes());
    let from_token = Token::FixedBytes(from_bytes);
    let to_token = Token::Address(*to);
    let amount_token = Token::Uint(amount.into());

    let extra_data = b"";
    let extra_data_bytes = Bytes::from(extra_data.as_ref());
    let extra_data_token = Token::Bytes(extra_data_bytes);

    // Because this call will be executed on the remote chain, we reverse the order of
    // the remote and local token addresses relative to their order in the
    // finalizeBridgeERC20 function.
    let inner_params = vec![
        remote_token_token.clone(),
        local_token_token.clone(),
        from_token,
        to_token.clone(),
        amount_token.clone(),
        extra_data_token.clone(),
    ];
    let inner_encoded_data = encode_with_selector(inner_selector, inner_params);
    let message_token = Token::Bytes(inner_encoded_data);

    let sender_token = Token::FixedBytes(Bytes::from(program_id.to_bytes()));
    let l1_standard_bridge_token = Token::Address(*l1_standard_bridge);
    let gas_limit_token = Token::Uint(gas_limit.into());

    let msg_nonce = encode_versioned_nonce(counter);
    let nonce_token = Token::Uint(msg_nonce);

    let msg_value = 0u128;
    let msg_value_token = Token::Uint(msg_value.into());

    let outer_params = vec![
        nonce_token.clone(),
        sender_token.clone(),
        l1_standard_bridge_token.clone(),
        msg_value_token.clone(),
        gas_limit_token.clone(),
        message_token.clone(),
    ];

    // nonce, sender, target, value, mint_gas_limit, message
    let outer_selector = "relayMessage(uint256,bytes32,address,uint256,uint256,bytes)";
    encode_with_selector(outer_selector, outer_params)
}

fn encode_with_selector(selector_str: &str, params: Vec<Token>) -> Vec<u8> {
    let mut hash_bytes = [0u8; 32];
    keccak_256(selector_str.as_bytes(), &mut hash_bytes);
    let selector = &hash_bytes[..4];

    let encoded_params = encode(&params);
    [selector, encoded_params.as_slice()].concat()
}

const MESSAGE_VERSION: u16 = 1;
fn encode_versioned_nonce(nonce: u64) -> Uint {
    let version_shifted = Uint::from(MESSAGE_VERSION) << 240;
    let nonce_u256 = Uint::from(nonce);

    version_shifted | nonce_u256
}
