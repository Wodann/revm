use crate::{
    common::keccak256,
    db::Database,
    gas,
    instructions::{Eval, Reason},
    interpreter::{self, bytecode::Bytecode},
    interpreter::{Contract, Interpreter},
    journaled_state::{Account, JournaledState, State},
    models::SelfDestructResult,
    precompiles, return_ok, return_revert, AnalysisKind, CallContext, CallInputs, CallOutputs,
    CallScheme, CreateInputs, CreateOutputs, CreateScheme, Env, ExecutionResult, Gas, Inspector,
    Log, Return, Spec,
    SpecId::{self, *},
    TransactOut, TransactTo, Transfer, B160, B256, KECCAK_EMPTY, U256,
};
use alloc::vec::Vec;
use bytes::Bytes;
use core::{cmp::min, marker::PhantomData};
use hashbrown::HashMap as Map;
use revm_precompiles::{Precompile, Precompiles};
use std::fmt::Debug;

pub struct EVMData<'a, DB: Database> {
    pub env: &'a mut Env,
    pub journaled_state: JournaledState,
    pub db: &'a mut DB,
}

pub struct EVMImpl<'a, GSPEC: Spec, DB: Database, const INSPECT: bool> {
    data: EVMData<'a, DB>,
    precompiles: Precompiles,
    inspector: &'a mut dyn Inspector<DB>,
    _phantomdata: PhantomData<GSPEC>,
}

/// Indicates that the EVM has experienced an exceptional halt. This causes execution to
/// immediately end with all gas being consumed.
#[derive(Debug, thiserror::Error)]
pub enum ExceptionalHalt {
    #[error("The new contract code starts with 0xEF")]
    InvalidContractPrefix,
    /// Occurs when the destination of a jump operation doesn't meet any of the following criteria:
    ///
    /// - The jump destination is less than the length of the code.
    /// - The jump destination should have the `JUMPDEST` opcode (0x5B).
    /// - The jump destination shouldn't be part of the data corresponding to `PUSH-N` opcodes.
    #[error("Invalid jump destination encountered")]
    InvalidJump,
    #[error("Invalid opcode is encountered")]
    InvalidOpcode,
    #[error("Invalid parameters are passed")]
    InvalidParameter,
    #[error("Reading data beyond the boundaries of the buffer")]
    OutOfBoundsRead,
    #[error("The operation costs more than the amount of gas left in the frame")]
    OutOfGas,
    #[error("The message depth is greater than `1024`")]
    StackDepthLimit,
    #[error("A push is executed on a stack at max capacity")]
    StackOverflow,
    #[error("A pop is executed on an empty stack")]
    StackUnderflow,
    #[error("Modifying the state while operating inside of a STATICCALL context")]
    WriteInStaticContext,
}

impl From<precompiles::Error> for ExceptionalHalt {
    fn from(error: precompiles::Error) -> Self {
        match error {
            revm_precompiles::Error::OutOfGas => Self::OutOfGas,
            revm_precompiles::Error::Blake2WrongLength
            | revm_precompiles::Error::Blake2WrongFinalIndicatorFlag => Self::InvalidParameter,
            // TODO: Reference implementation pads right with zeroes
            revm_precompiles::Error::ModexpExpOverflow
            | revm_precompiles::Error::ModexpBaseOverflow
            | revm_precompiles::Error::ModexpModOverflow => unreachable!(),
            revm_precompiles::Error::Bn128FieldPointNotAMember
            | revm_precompiles::Error::Bn128AffineGFailedToCreate
            | revm_precompiles::Error::Bn128PairLength => Self::OutOfGas,
        }
    }
}

/// All Ethereum errors that might occur by the specification during normal operation.
#[derive(Debug, thiserror::Error)]
pub enum EthereumError {
    #[error(transparent)]
    ExceptionalHalt(#[from] ExceptionalHalt),
    #[error("The block being processed is found to be invalid")]
    InvalidBlock,
    #[error("RLP decoding failed")]
    InvalidRlpDecoding,
    #[error("RLP encoding failed")]
    InvalidRlpEncoding,
}

#[derive(Debug, thiserror::Error)]
pub enum EvmError<DE: Debug> {
    #[error("The database returned an error")]
    DatabaseFailure(DE),
    #[error(transparent)]
    EthereumError(#[from] EthereumError),
}

impl<DE: Debug> From<ExceptionalHalt> for EvmError<DE> {
    fn from(other: ExceptionalHalt) -> Self {
        Self::EthereumError(EthereumError::ExceptionalHalt(other))
    }
}

pub type EvmResult<T, E> = Result<T, EvmError<E>>;

#[derive(Debug, thiserror::Error)]
pub enum TransactionError<DE: Debug> {
    #[error("Transaction's gas limit is more than block's gas limit")]
    CallerGasLimitMoreThanBlock,
    #[error("The database returned an error")]
    DatabaseFailure(#[from] DE),
    #[error("Transaction's priority fee is greater than max fee")]
    GasMaxFeeGreaterThanPriorityFee,
    #[error("Transaction's effective gas price is less than block's base fee")]
    GasPriceLessThanBasefee,
    #[error("Account does not have enough funds to be able to afford transaction's gas limit")]
    LackOfFundForGasLimit,
    #[error("Incrementing nonce causes arithmetic overflow")]
    NonceOverflow(B160),
    #[error("Account is out of funds")]
    OutOfFund,
    #[error("Transaction is out of gas")]
    OutOfGas,
    #[error("Transaction's payment calculation causes arithmetic overflow")]
    OverflowPayment,
    #[error("Prevrando was not set for a post-merge spec")]
    PrevrandaoNotSet,
    #[error("Transaction originated from sender with deployed code (EIP-3607)")]
    RejectCallerWithCode,
}

pub type TransactionResult<T, DE: Debug> = Result<T, TransactionError<DE>>;

pub trait Transact {
    type Error;

    /// Do transaction.
    /// Return Return, Output for call or Address if we are creating contract, gas spend, gas refunded, State that needs to be applied.
    fn transact(&mut self) -> Result<(ExecutionResult, State), Self::Error>;
}

impl<'a, GSPEC: Spec, DB: Database, const INSPECT: bool> Transact
    for EVMImpl<'a, GSPEC, DB, INSPECT>
{
    type Error = TransactionError<DB::Error>;

    fn transact(&mut self) -> Result<(ExecutionResult, State), Self::Error> {
        let caller = self.data.env.tx.caller;
        let value = self.data.env.tx.value;
        let data = self.data.env.tx.data.clone();
        let gas_limit = self.data.env.tx.gas_limit;
        let exit = |reason: Return| (ExecutionResult::new_with_reason(reason), State::new());

        if GSPEC::enabled(MERGE) && self.data.env.block.prevrandao.is_none() {
            return Err(TransactionError::PrevrandaoNotSet);
        }

        if GSPEC::enabled(LONDON) {
            if let Some(priority_fee) = self.data.env.tx.gas_priority_fee {
                if priority_fee > self.data.env.tx.gas_price {
                    // or gas_max_fee for eip1559
                    return Err(TransactionError::GasMaxFeeGreaterThanPriorityFee);
                }
            }
            let effective_gas_price = self.data.env.effective_gas_price();
            let basefee = self.data.env.block.basefee;

            // check minimal cost against basefee
            // TODO maybe do this checks when creating evm. We already have all data there
            // or should be move effective_gas_price inside transact fn
            if effective_gas_price < basefee {
                return Err(TransactionError::GasPriceLessThanBasefee);
            }
            // check if priority fee is lower then max fee
        }

        #[cfg(feature = "optional_block_gas_limit")]
        let disable_block_gas_limit = self.env().cfg.disable_block_gas_limit;
        #[cfg(not(feature = "optional_block_gas_limit"))]
        let disable_block_gas_limit = false;

        // unusual to be found here, but check if gas_limit is more than block_gas_limit
        if !disable_block_gas_limit && U256::from(gas_limit) > self.data.env.block.gas_limit {
            return Err(TransactionError::CallerGasLimitMoreThanBlock);
        }

        let mut gas = Gas::new(gas_limit);
        // record initial gas cost. if not using gas metering init will return 0
        if !gas.record_cost(self.initialization::<GSPEC>()) {
            return Err(TransactionError::OutOfGas);
        }

        // load acc
        if let Err(e) = self.data.journaled_state.load_account(caller, self.data.db) {
            return Err(TransactionError::DatabaseFailure(e));
        }

        #[cfg(feature = "optional_eip3607")]
        let disable_eip3607 = self.env().cfg.disable_eip3607;
        #[cfg(not(feature = "optional_eip3607"))]
        let disable_eip3607 = false;

        // EIP-3607: Reject transactions from senders with deployed code
        // This EIP is introduced after london but there was no colision in past
        // so we can leave it enabled always
        if !disable_eip3607
            && self.data.journaled_state.account(caller).info.code_hash != KECCAK_EMPTY
        {
            return Err(TransactionError::RejectCallerWithCode);
        }

        #[cfg(feature = "optional_balance_check")]
        let disable_balance_check = self.env().cfg.disable_balance_check;
        #[cfg(not(feature = "optional_balance_check"))]
        let disable_balance_check = false;

        // substract gas_limit*gas_price from current account.
        if let Some(payment_value) =
            U256::from(gas_limit).checked_mul(self.data.env.effective_gas_price())
        {
            let balance = &mut self
                .data
                .journaled_state
                .state
                .get_mut(&caller)
                .unwrap()
                .info
                .balance;

            if payment_value > *balance {
                if disable_balance_check {
                    *balance = U256::ZERO;
                } else {
                    return Err(TransactionError::LackOfFundForGasLimit);
                }
            } else {
                *balance -= payment_value;
            }
        } else {
            return Err(TransactionError::OverflowPayment);
        }

        // check if we have enought balance for value transfer.
        let difference = self.data.env.tx.gas_price - self.data.env.effective_gas_price();
        if !disable_balance_check
            && difference + value > self.data.journaled_state.account(caller).info.balance
        {
            return Err(TransactionError::OutOfFund);
        }

        // record all as cost;
        let gas_limit = gas.remaining();
        if crate::USE_GAS {
            gas.record_cost(gas_limit);
        }

        // call inner handling of call/create
        let (exit_reason, ret_gas, out) = match self.data.env.tx.transact_to {
            TransactTo::Call(address) => {
                if self.data.journaled_state.inc_nonce(caller).is_none() {
                    // overflow
                    return Err(TransactionError::NonceOverflow(caller));
                }
                let context = CallContext {
                    caller,
                    address,
                    code_address: address,
                    apparent_value: value,
                    scheme: CallScheme::Call,
                };
                let mut call_input = CallInputs {
                    contract: address,
                    transfer: Transfer {
                        source: caller,
                        target: address,
                        value,
                    },
                    input: data,
                    gas_limit,
                    context,
                    is_static: false,
                };
                let CallOutputs {
                    exit_reason: eval,
                    gas,
                    return_value: out,
                } = self.call_inner(&mut call_input)?;
                (eval, gas, TransactOut::Call(out))
            }
            TransactTo::Create(scheme) => {
                let mut create_input = CreateInputs {
                    caller,
                    scheme,
                    value,
                    init_code: data,
                    gas_limit,
                };
                let (exit, address, ret_gas, bytes) = self.create_inner(&mut create_input)?;
                (exit, ret_gas, TransactOut::Create(bytes, address))
            }
        };

        if crate::USE_GAS {
            match exit_reason {
                return_ok!() => {
                    gas.erase_cost(ret_gas.remaining());
                    gas.record_refund(ret_gas.refunded());
                }
                Eval::Revert => {
                    gas.erase_cost(ret_gas.remaining());
                }
                _ => {}
            }
        }

        let (state, logs, gas_used, gas_refunded) = self.finalize::<GSPEC>(caller, &gas);
        Ok((
            ExecutionResult {
                exit_reason,
                out,
                gas_used,
                gas_refunded,
                logs,
            },
            state,
        ))
    }
}

impl<'a, GSPEC: Spec, DB: Database, const INSPECT: bool> EVMImpl<'a, GSPEC, DB, INSPECT> {
    pub fn new(
        db: &'a mut DB,
        env: &'a mut Env,
        inspector: &'a mut dyn Inspector<DB>,
        precompiles: Precompiles,
    ) -> Self {
        let journaled_state = if GSPEC::enabled(SpecId::SPURIOUS_DRAGON) {
            JournaledState::new(precompiles.len())
        } else {
            JournaledState::new_legacy(precompiles.len())
        };
        Self {
            data: EVMData {
                env,
                journaled_state,
                db,
            },
            precompiles,
            inspector,
            _phantomdata: PhantomData {},
        }
    }

    fn finalize<SPEC: Spec>(
        &mut self,
        caller: B160,
        gas: &Gas,
    ) -> (Map<B160, Account>, Vec<Log>, u64, u64) {
        let coinbase = self.data.env.block.coinbase;
        let (gas_used, gas_refunded) = if crate::USE_GAS {
            let effective_gas_price = self.data.env.effective_gas_price();
            let basefee = self.data.env.block.basefee;

            #[cfg(feature = "optional_gas_refund")]
            let disable_gas_refund = self.env().cfg.disable_gas_refund;
            #[cfg(not(feature = "optional_gas_refund"))]
            let disable_gas_refund = false;

            let gas_refunded = if disable_gas_refund {
                0
            } else {
                // EIP-3529: Reduction in refunds
                let max_refund_quotient = if SPEC::enabled(LONDON) { 5 } else { 2 };
                min(gas.refunded() as u64, gas.spend() / max_refund_quotient)
            };
            let acc_caller = self.data.journaled_state.state().get_mut(&caller).unwrap();
            acc_caller.info.balance = acc_caller
                .info
                .balance
                .saturating_add(effective_gas_price * U256::from(gas.remaining() + gas_refunded));

            // EIP-1559
            let coinbase_gas_price = if SPEC::enabled(LONDON) {
                effective_gas_price.saturating_sub(basefee)
            } else {
                effective_gas_price
            };

            // TODO
            let _ = self
                .data
                .journaled_state
                .load_account(coinbase, self.data.db);
            self.data.journaled_state.touch(&coinbase);
            let acc_coinbase = self
                .data
                .journaled_state
                .state()
                .get_mut(&coinbase)
                .unwrap();
            acc_coinbase.info.balance = acc_coinbase
                .info
                .balance
                .saturating_add(coinbase_gas_price * U256::from(gas.spend() - gas_refunded));
            (gas.spend() - gas_refunded, gas_refunded)
        } else {
            // touch coinbase
            // TODO return
            let _ = self
                .data
                .journaled_state
                .load_account(coinbase, self.data.db);
            self.data.journaled_state.touch(&coinbase);
            (0, 0)
        };
        let (mut new_state, logs) = self.data.journaled_state.finalize();
        // precompiles are special case. If there is precompiles in finalized Map that means some balance is
        // added to it, we need now to load precompile address from db and add this amount to it so that we
        // will have sum.
        if self.data.env.cfg.perf_all_precompiles_have_balance {
            for address in self.precompiles.addresses() {
                let address = B160(*address);
                if let Some(precompile) = new_state.get_mut(&address) {
                    // we found it.
                    precompile.info.balance += self
                        .data
                        .db
                        .basic(address)
                        .ok()
                        .flatten()
                        .map(|acc| acc.balance)
                        .unwrap_or_default();
                }
            }
        }

        (new_state, logs, gas_used, gas_refunded)
    }

    fn initialization<SPEC: Spec>(&mut self) -> u64 {
        let is_create = matches!(self.data.env.tx.transact_to, TransactTo::Create(_));
        let input = &self.data.env.tx.data;

        if crate::USE_GAS {
            let zero_data_len = input.iter().filter(|v| **v == 0).count() as u64;
            let non_zero_data_len = input.len() as u64 - zero_data_len;
            let (accessed_accounts, accessed_slots) = {
                if SPEC::enabled(BERLIN) {
                    let mut accessed_slots = 0_u64;

                    for (address, slots) in self.data.env.tx.access_list.iter() {
                        // TODO return
                        let _ = self
                            .data
                            .journaled_state
                            .load_account(*address, self.data.db);
                        accessed_slots += slots.len() as u64;
                        // TODO return
                        for slot in slots {
                            let _ = self
                                .data
                                .journaled_state
                                .sload(*address, *slot, self.data.db);
                        }
                    }
                    (self.data.env.tx.access_list.len() as u64, accessed_slots)
                } else {
                    (0, 0)
                }
            };

            let transact = if is_create {
                if SPEC::enabled(HOMESTEAD) {
                    // EIP-2: Homestead Hard-fork Changes
                    53000
                } else {
                    21000
                }
            } else {
                21000
            };

            // EIP-2028: Transaction data gas cost reduction
            let gas_transaction_non_zero_data = if SPEC::enabled(ISTANBUL) { 16 } else { 68 };

            transact
                + zero_data_len * gas::TRANSACTION_ZERO_DATA
                + non_zero_data_len * gas_transaction_non_zero_data
                + accessed_accounts * gas::ACCESS_LIST_ADDRESS
                + accessed_slots * gas::ACCESS_LIST_STORAGE_KEY
        } else {
            0
        }
    }

    fn create_inner(
        &mut self,
        inputs: &mut CreateInputs,
    ) -> EvmResult<CreateOutputs<Reason>, DB::Error> {
        // Call inspector
        if INSPECT {
            let outputs = self.inspector.create(&mut self.data, inputs);
            if outputs.exit_reason != Eval::Continue {
                return Ok(self.inspector.create_end(&mut self.data, inputs, outputs));
            }
        }

        let gas = Gas::new(inputs.gas_limit);
        self.load_account(inputs.caller);

        // Check depth of calls
        if self.data.journaled_state.depth() > interpreter::CALL_STACK_LIMIT {
            return Ok(CreateOutputs {
                exit_reason: Reason::Failure(ExceptionalHalt::CallTooDeep),
                address: None,
                gas,
                return_value: Bytes::new(),
            });
        }
        // Check balance of caller and value. Do this before increasing nonce
        match self.balance(inputs.caller) {
            Ok(i) if i.0 < inputs.value => {
                return Ok(CreateOutputs {
                    exit_reason: Reason::OutOfFund,
                    address: None,
                    gas,
                    return_value: Bytes::new(),
                })
            }
            Ok(_) => (),
            Err(e) => return Err(TransactionError::DatabaseFailure(e)),
        }

        // Increase nonce of caller and check if it overflows
        let old_nonce;
        if let Some(nonce) = self.data.journaled_state.inc_nonce(inputs.caller) {
            old_nonce = nonce - 1;
        } else {
            return Err(TransactionError::NonceOverflow(inputs.caller));
        }

        // Create address
        let code_hash = keccak256(&inputs.init_code);
        let created_address = match inputs.scheme {
            CreateScheme::Create => create_address(inputs.caller, old_nonce),
            CreateScheme::Create2 { salt } => create2_address(inputs.caller, code_hash, salt),
        };
        let address = Some(created_address);

        // Load account so that it will be hot
        self.load_account(created_address);

        // Enter subroutine
        let checkpoint = self.data.journaled_state.checkpoint();

        // Create contract account and check for collision
        match self.data.journaled_state.create_account(
            created_address,
            self.precompiles.contains(&created_address),
            self.data.db,
        ) {
            Ok(false) => {
                self.data.journaled_state.checkpoint_revert(checkpoint);
                return Ok((Return::CreateCollision, address, gas, Bytes::new()));
            }
            Err(e) => return Err(TransactionError::DatabaseFailure(e)),
            Ok(true) => (),
        }

        // Transfer value to contract address
        self.data.journaled_state.transfer(
            &inputs.caller,
            &created_address,
            inputs.value,
            self.data.db,
        )?;

        // EIP-161: State trie clearing (invariant-preserving alternative)
        if GSPEC::enabled(SPURIOUS_DRAGON) {
            self.data
                .journaled_state
                .inc_nonce(created_address)
                // TODO: Validate transaction + block
                .expect("Transaction has already been validated");
        }

        // Create new interpreter and execute initcode
        let contract = Contract::new::<GSPEC>(
            Bytes::new(),
            Bytecode::new_raw(inputs.init_code.clone()),
            created_address,
            inputs.caller,
            inputs.value,
        );

        #[cfg(feature = "memory_limit")]
        let mut interpreter = Interpreter::new_with_memory_limit::<GSPEC>(
            contract,
            gas.limit(),
            false,
            self.data.env.cfg.memory_limit,
        );

        #[cfg(not(feature = "memory_limit"))]
        let mut interpreter = Interpreter::new::<GSPEC>(contract, gas.limit(), false);

        if INSPECT {
            self.inspector
                .initialize_interp(&mut interpreter, &mut self.data, false);
        }
        let exit_reason = interpreter.run::<Self, GSPEC>(self, INSPECT);

        // Host error if present on execution\
        // let (ret, address, gas, out)
        let outputs = match exit_reason {
            return_ok!() => {
                // if ok, check contract creation limit and calculate gas deduction on output len.
                let mut return_value = interpreter.return_value();

                // EIP-3541: Reject new contract code starting with the 0xEF byte
                if GSPEC::enabled(LONDON)
                    && !return_value.is_empty()
                    && return_value.first() == Some(&0xEF)
                {
                    self.data.journaled_state.checkpoint_revert(checkpoint);
                    return Ok(CreateOutputs {
                        exit_reason: Reason::Failure(ExceptionalHalt::InvalidContractPrefix),
                        address,
                        gas,
                        return_value,
                    });
                }

                // EIP-170: Contract code size limit
                // By default limit is 0x6000 (~25kb)
                if GSPEC::enabled(SPURIOUS_DRAGON)
                    && return_value.len()
                        > self.data.env.cfg.limit_contract_code_size.unwrap_or(0x6000)
                {
                    self.data.journaled_state.checkpoint_revert(checkpoint);
                    return Ok(CreateOutputs {
                        exit_reason: Reason::Failure(ExceptionalHalt::OutOfGas),
                        address,
                        gas,
                        return_value,
                    });
                }
                if crate::USE_GAS {
                    let gas_for_code = return_value.len() as u64 * crate::gas::CODEDEPOSIT;
                    if !interpreter.gas.record_cost(gas_for_code) {
                        // record code deposit gas cost and check if we are out of gas.
                        // EIP-2 point 3: If contract creation does not have enough gas to pay for the
                        // final gas fee for adding the contract code to the state, the contract
                        //  creation fails (i.e. goes out-of-gas) rather than leaving an empty contract.
                        if GSPEC::enabled(HOMESTEAD) {
                            self.data.journaled_state.checkpoint_revert(checkpoint);
                            return Ok(CreateOutputs {
                                exit_reason: Reason::Failure(ExceptionalHalt::OutOfGas),
                                address,
                                gas: interpreter.gas,
                                return_value,
                            });
                        } else {
                            return_value = Bytes::new();
                        }
                    }
                }
                // if we have enought gas
                self.data.journaled_state.checkpoint_commit();
                // Do analasis of bytecode streight away.
                let bytecode = match self.data.env.cfg.perf_analyse_created_bytecodes {
                    AnalysisKind::Raw => Bytecode::new_raw(return_value.clone()),
                    AnalysisKind::Check => Bytecode::new_raw(return_value.clone()).to_checked(),
                    AnalysisKind::Analyse => {
                        Bytecode::new_raw(return_value.clone()).to_analysed::<GSPEC>()
                    }
                };

                self.data
                    .journaled_state
                    .set_code(created_address, bytecode);

                CreateOutputs {
                    exit_reason: Reason::Success(Eval::Continue),
                    address,
                    gas: interpreter.gas,
                    return_value,
                }
            }
            _ => {
                self.data.journaled_state.checkpoint_revert(checkpoint);
                CreateOutputs {
                    exit_reason,
                    address,
                    gas: interpreter.gas,
                    return_value: interpreter.return_value(),
                }
            }
        };

        Ok(if INSPECT {
            self.inspector.create_end(&mut self.data, inputs, outputs)
        } else {
            outputs
        })
    }

    fn call_inner(
        &mut self,
        inputs: &mut CallInputs,
    ) -> Result<CallOutputs<Reason>, TransactionError<DB::Error>> {
        // Call the inspector
        if INSPECT {
            let outputs = self
                .inspector
                .call(&mut self.data, inputs, inputs.is_static);
            if outputs.exit_reason != Eval::Continue {
                return Ok(self.inspector.call_end(
                    &mut self.data,
                    inputs,
                    CallOutputs {
                        exit_reason: Reason::from(outputs.exit_reason),
                        ..outputs
                    },
                ));
            }
        }

        let mut gas = Gas::new(inputs.gas_limit);
        // Load account and get code. Account is now hot.
        let bytecode = self
            .code(inputs.contract)
            .map_err(TransactionError::DatabaseFailure)?
            .0;

        // Check depth
        if self.data.journaled_state.depth() > interpreter::CALL_STACK_LIMIT {
            let outputs = CallOutputs {
                exit_reason: Reason::Failure(ExceptionalHalt::StackDepthLimit),
                gas,
                return_value: Bytes::new(),
            };
            if INSPECT {
                return Ok(self.inspector.call_end(
                    &mut self.data,
                    inputs,
                    outputs,
                    inputs.is_static,
                ));
            } else {
                return Ok(outputs);
            }
        }

        // Create subroutine checkpoint
        let checkpoint = self.data.journaled_state.checkpoint();

        // Touch address. For "EIP-158 State Clear", this will erase empty accounts.
        if inputs.transfer.value == U256::ZERO {
            self.load_account(inputs.context.address)?;
            self.data.journaled_state.touch(&inputs.context.address);
        }

        // Transfer value from caller to called account
        self.data.journaled_state.transfer(
            &inputs.transfer.source,
            &inputs.transfer.target,
            inputs.transfer.value,
            self.data.db,
        )?;

        // Call precompiles
        let (ret, gas, out) = if let Some(precompile) = self.precompiles.get(&inputs.contract) {
            let out = match precompile {
                Precompile::Standard(fun) => fun(inputs.input.as_ref(), inputs.gas_limit),
                Precompile::Custom(fun) => fun(inputs.input.as_ref(), inputs.gas_limit),
            };
            match out {
                Ok((gas_used, data)) => {
                    if !crate::USE_GAS || gas.record_cost(gas_used) {
                        self.data.journaled_state.checkpoint_commit();
                        CallOutputs {
                            exit_reason: Reason::Success(Eval::Continue),
                            gas,
                            return_value: Bytes::from(data),
                        }
                    } else {
                        self.data.journaled_state.checkpoint_revert(checkpoint);
                        CallOutputs {
                            exit_reason: Reason::Failure(ExceptionalHalt::OutOfGas),
                            gas,
                            return_value: Bytes::new(),
                        }
                    }
                }
                Err(e) => {
                    self.data.journaled_state.checkpoint_revert(checkpoint);

                    CallOutputs {
                        exit_reason: Reason::from(ExceptionalHalt::from(e)),
                        gas,
                        return_value: Bytes::new(),
                    }
                }
            }
        } else {
            // Create interpreter and execute subcall
            let contract = Contract::new_with_context::<GSPEC>(
                inputs.input.clone(),
                bytecode,
                &inputs.context,
            );

            #[cfg(feature = "memory_limit")]
            let mut interpreter = Interpreter::new_with_memory_limit::<GSPEC>(
                contract,
                gas.limit(),
                inputs.is_static,
                self.data.env.cfg.memory_limit,
            );

            #[cfg(not(feature = "memory_limit"))]
            let mut interpreter =
                Interpreter::new::<GSPEC>(contract, gas.limit(), inputs.is_static);

            if INSPECT {
                // create is always no static call.
                self.inspector
                    .initialize_interp(&mut interpreter, &mut self.data, false);
            }
            let exit_reason = interpreter.run::<Self, GSPEC>(self, INSPECT);
            if matches!(exit_reason, return_ok!()) {
                self.data.journaled_state.checkpoint_commit();
            } else {
                self.data.journaled_state.checkpoint_revert(checkpoint);
            }

            (exit_reason, interpreter.gas, interpreter.return_value())
        };

        Ok(if INSPECT {
            self.inspector
                .call_end(&mut self.data, inputs, gas, ret, out, inputs.is_static)
        } else {
            (ret, gas, out)
        })
    }
}

impl<'a, GSPEC: Spec, DB: Database + 'a, const INSPECT: bool> Host
    for EVMImpl<'a, GSPEC, DB, INSPECT>
{
    type DatabaseError = DB::Error;

    fn step(&mut self, interp: &mut Interpreter, is_static: bool) -> Return {
        self.inspector.step(interp, &mut self.data, is_static)
    }

    fn step_end(&mut self, interp: &mut Interpreter, is_static: bool, ret: Return) -> Return {
        self.inspector
            .step_end(interp, &mut self.data, is_static, ret)
    }

    fn env(&mut self) -> &mut Env {
        self.data.env
    }

    fn block_hash(&mut self, number: U256) -> Result<B256, Self::DatabaseError> {
        self.data.db.block_hash(number)
    }

    fn load_account(&mut self, address: B160) -> Result<(bool, bool), Self::DatabaseError> {
        self.data
            .journaled_state
            .load_account_exist(address, self.data.db)
    }

    fn balance(&mut self, address: B160) -> Result<(U256, bool), Self::DatabaseError> {
        let db = &mut self.data.db;
        let journal = &mut self.data.journaled_state;
        journal
            .load_account(address, db)
            .map(|(acc, is_cold)| (acc.info.balance, is_cold))
    }

    fn code(&mut self, address: B160) -> Result<(Bytecode, bool), Self::DatabaseError> {
        let journal = &mut self.data.journaled_state;
        let db = &mut self.data.db;

        journal
            .load_code(address, db)
            .map(|(acc, is_cold)| (acc.info.code.clone().unwrap(), is_cold))
    }

    /// Get code hash of address.
    fn code_hash(&mut self, address: B160) -> Result<(B256, bool), Self::DatabaseError> {
        let journal = &mut self.data.journaled_state;
        let db = &mut self.data.db;

        let (acc, is_cold) = journal.load_code(address, db)?;

        //asume that all precompiles have some balance
        let is_precompile = self.precompiles.contains(&address);
        if is_precompile && self.data.env.cfg.perf_all_precompiles_have_balance {
            return Ok((KECCAK_EMPTY, is_cold));
        }
        if acc.is_empty() {
            // TODO check this for pre tangerine fork
            return Ok((B256::zero(), is_cold));
        }

        Ok((acc.info.code_hash, is_cold))
    }

    fn sload(&mut self, address: B160, index: U256) -> Result<(U256, bool), Self::DatabaseError> {
        // account is always hot. reference on that statement https://eips.ethereum.org/EIPS/eip-2929 see `Note 2:`
        self.data
            .journaled_state
            .sload(address, index, self.data.db)
    }

    fn sstore(
        &mut self,
        address: B160,
        index: U256,
        value: U256,
    ) -> Result<(U256, U256, U256, bool), Self::DatabaseError> {
        self.data
            .journaled_state
            .sstore(address, index, value, self.data.db)
    }

    fn log(&mut self, address: B160, topics: Vec<B256>, data: Bytes) {
        if INSPECT {
            self.inspector.log(&mut self.data, &address, &topics, &data);
        }
        let log = Log {
            address,
            topics,
            data,
        };
        self.data.journaled_state.log(log);
    }

    fn selfdestruct(
        &mut self,
        address: B160,
        target: B160,
    ) -> Result<SelfDestructResult, Self::DatabaseError> {
        if INSPECT {
            self.inspector.selfdestruct();
        }
        self.data
            .journaled_state
            .selfdestruct(address, target, self.data.db)
    }

    fn create(
        &mut self,
        inputs: &mut CreateInputs,
    ) -> EvmResult<CreateOutputs, Self::DatabaseError> {
        self.create_inner(inputs)
    }

    fn call(&mut self, inputs: &mut CallInputs) -> EvmResult<CallOutputs, Self::DatabaseError> {
        self.call_inner(inputs)
    }
}

/// Returns the address for the legacy `CREATE` scheme: [`CreateScheme::Create`]
pub fn create_address(caller: B160, nonce: u64) -> B160 {
    let mut stream = rlp::RlpStream::new_list(2);
    stream.append(&caller.0.as_ref());
    stream.append(&nonce);
    let out = keccak256(&stream.out());
    B160(out[12..].try_into().unwrap())
}

/// Returns the address for the `CREATE2` scheme: [`CreateScheme::Create2`]
pub fn create2_address(caller: B160, code_hash: B256, salt: U256) -> B160 {
    use sha3::{Digest, Keccak256};
    let mut hasher = Keccak256::new();
    hasher.update([0xff]);
    hasher.update(&caller[..]);
    hasher.update(salt.to_be_bytes::<{ U256::BYTES }>());
    hasher.update(&code_hash[..]);

    B160(hasher.finalize().as_slice()[12..].try_into().unwrap())
}

/// EVM context host.
pub trait Host {
    type DatabaseError: Debug;

    fn step(&mut self, interp: &mut Interpreter, is_static: bool) -> Return;
    fn step_end(&mut self, interp: &mut Interpreter, is_static: bool, ret: Return) -> Return;

    fn env(&mut self) -> &mut Env;

    /// load account. Returns (is_cold,is_new_account)
    fn load_account(&mut self, address: B160) -> Result<(bool, bool), Self::DatabaseError>;
    /// Get environmental block hash.
    fn block_hash(&mut self, number: U256) -> Result<B256, Self::DatabaseError>;
    /// Get balance of address.
    fn balance(&mut self, address: B160) -> Result<(U256, bool), Self::DatabaseError>;
    /// Get code of address.
    fn code(&mut self, address: B160) -> Result<(Bytecode, bool), Self::DatabaseError>;
    /// Get code hash of address.
    fn code_hash(&mut self, address: B160) -> Result<(B256, bool), Self::DatabaseError>;
    /// Get storage value of address at index.
    fn sload(&mut self, address: B160, index: U256) -> Result<(U256, bool), Self::DatabaseError>;
    /// Set storage value of address at index. Return if slot is cold/hot access.
    fn sstore(
        &mut self,
        address: B160,
        index: U256,
        value: U256,
    ) -> Result<(U256, U256, U256, bool), Self::DatabaseError>;
    /// Create a log owned by address with given topics and data.
    fn log(&mut self, address: B160, topics: Vec<B256>, data: Bytes);
    /// Mark an address to be deleted, with funds transferred to target.
    fn selfdestruct(
        &mut self,
        address: B160,
        target: B160,
    ) -> Result<SelfDestructResult, Self::DatabaseError>;
    /// Invoke a create operation.
    fn create(
        &mut self,
        inputs: &mut CreateInputs,
    ) -> EvmResult<CreateOutputs, Self::DatabaseError>;
    /// Invoke a call operation.
    fn call(&mut self, input: &mut CallInputs) -> EvmResult<CallOutputs, Self::DatabaseError>;
}
