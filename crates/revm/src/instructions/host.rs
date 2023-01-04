use crate::{
    alloc::vec::Vec,
    bits::{B160, B256},
    evm_impl::{EvmError, EvmResult, ExceptionalHalt},
    gas::{self, COLD_ACCOUNT_ACCESS_COST, WARM_STORAGE_READ_COST},
    interpreter::Interpreter,
    return_ok, return_revert, CallContext, CallInputs, CallOutputs, CallScheme, CreateInputs,
    CreateOutputs, CreateScheme, Host, Return, Spec,
    SpecId::*,
    Transfer, U256,
};
use bytes::Bytes;
use core::cmp::min;

use super::Eval;

pub fn balance<H: Host, SPEC: Spec>(
    interpreter: &mut Interpreter,
    host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    pop_address!(interpreter, address);
    let (balance, is_cold) = host.balance(address).map_err(EvmError::DatabaseFailure)?;
    gas!(
        interpreter,
        if SPEC::enabled(ISTANBUL) {
            // EIP-1884: Repricing for trie-size-dependent opcodes
            gas::account_access_gas::<SPEC>(is_cold)
        } else if SPEC::enabled(TANGERINE) {
            400
        } else {
            20
        }
    );
    push!(interpreter, balance);

    Ok(())
}

pub fn selfbalance<H: Host, SPEC: Spec>(
    interpreter: &mut Interpreter,
    host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    // gas!(interp, gas::LOW);
    // EIP-1884: Repricing for trie-size-dependent opcodes
    check!(interpreter, SPEC::enabled(ISTANBUL));
    let balance = host
        .balance(interpreter.contract.address)
        .map_err(EvmError::DatabaseFailure)?
        .0;
    push!(interpreter, balance);

    Ok(())
}

pub fn extcodesize<H: Host, SPEC: Spec>(
    interpreter: &mut Interpreter,
    host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    pop_address!(interpreter, address);
    let (code, is_cold) = host.code(address).map_err(EvmError::DatabaseFailure)?;
    if SPEC::enabled(BERLIN) && is_cold {
        // WARM_STORAGE_READ_COST is already calculated in gas block
        gas!(
            interpreter,
            COLD_ACCOUNT_ACCESS_COST - WARM_STORAGE_READ_COST
        );
    }

    push!(interpreter, U256::from(code.len()));

    Ok(())
}

pub fn extcodehash<H: Host, SPEC: Spec>(
    interpreter: &mut Interpreter,
    host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    check!(interpreter, SPEC::enabled(CONSTANTINOPLE)); // EIP-1052: EXTCODEHASH opcode
    pop_address!(interpreter, address);
    let (code_hash, is_cold) = host.code_hash(address).map_err(EvmError::DatabaseFailure)?;
    if SPEC::enabled(BERLIN) && is_cold {
        // WARM_STORAGE_READ_COST is already calculated in gas block
        gas!(
            interpreter,
            COLD_ACCOUNT_ACCESS_COST - WARM_STORAGE_READ_COST
        );
    }
    interpreter
        .stack
        .push_b256(code_hash)
        .map_err(EvmError::from)
}

pub fn extcodecopy<H: Host, SPEC: Spec>(
    interpreter: &mut Interpreter,
    host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    pop_address!(interpreter, address);
    pop!(interpreter, memory_offset, code_offset, len_u256);

    let (code, is_cold) = host.code(address).map_err(EvmError::DatabaseFailure)?;

    let len = as_usize_or_fail!(interpreter, len_u256, Return::OutOfGas);
    gas_or_fail!(
        interpreter,
        gas::extcodecopy_cost::<SPEC>(len as u64, is_cold)
    );
    if len == 0 {
        return Ok(());
    }
    let memory_offset = as_usize_or_fail!(interpreter, memory_offset, Return::OutOfGas);
    let code_offset = min(as_usize_saturated!(code_offset), code.len());
    memory_resize!(interpreter, memory_offset, len);

    // Safety: set_data is unsafe function and memory_resize ensures us that it is safe to call it
    interpreter
        .memory
        .set_data(memory_offset, code_offset, len, code.bytes());

    Ok(())
}

pub fn blockhash<H: Host>(
    interpreter: &mut Interpreter,
    host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    // gas!(interp, gas::BLOCKHASH);
    pop_top!(interpreter, number);

    if let Some(diff) = host.env().block.number.checked_sub(*number) {
        let diff = as_usize_saturated!(diff);
        // blockhash should push zero if number is same as current block number.
        if diff <= 256 && diff != 0 {
            let block_hash = host
                .block_hash(*number)
                .map_err(EvmError::DatabaseFailure)?;
            *number = U256::from_be_bytes(*block_hash);
            return Ok(());
        }
    }
    *number = U256::ZERO;

    Ok(())
}

pub fn sload<H: Host, SPEC: Spec>(
    interpreter: &mut Interpreter,
    host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    pop!(interpreter, index);

    let (value, is_cold) = host
        .sload(interpreter.contract.address, index)
        .map_err(EvmError::DatabaseFailure)?;
    gas!(interpreter, gas::sload_cost::<SPEC>(is_cold));
    push!(interpreter, value);

    Ok(())
}

pub fn sstore<H: Host, SPEC: Spec>(
    interpreter: &mut Interpreter,
    host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    check!(interpreter, !interpreter.is_static);

    pop!(interpreter, index, value);
    let (original, old, new, is_cold) = host
        .sstore(interpreter.contract.address, index, value)
        .map_err(EvmError::DatabaseFailure)?;
    gas_or_fail!(interpreter, {
        let remaining_gas = interpreter.gas.remaining();
        gas::sstore_cost::<SPEC>(original, old, new, remaining_gas, is_cold)
    });
    refund!(interpreter, gas::sstore_refund::<SPEC>(original, old, new));
    interpreter.add_next_gas_block(interpreter.program_counter() - 1)?;

    Ok(())
}

pub fn log<const N: u8, H: Host, SPEC: Spec>(
    interpreter: &mut Interpreter,
    host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    check!(interpreter, !interpreter.is_static);

    pop!(interpreter, offset, len);
    let len = as_usize_or_fail!(interpreter, len, Return::OutOfGas);
    gas_or_fail!(interpreter, gas::log_cost(N, len as u64));
    let data = if len == 0 {
        Bytes::new()
    } else {
        let offset = as_usize_or_fail!(interpreter, offset, Return::OutOfGas);
        memory_resize!(interpreter, offset, len);
        Bytes::copy_from_slice(interpreter.memory.get_slice(offset, len))
    };
    let n = N as usize;
    if interpreter.stack.len() < n {
        return Err(EvmError::from(ExceptionalHalt::StackUnderflow));
    }

    let mut topics = Vec::with_capacity(n);
    for _ in 0..(n) {
        // Safety: stack bounds already checked few lines above
        topics.push(B256(unsafe {
            interpreter.stack.pop_unsafe().to_be_bytes()
        }));
    }

    host.log(interpreter.contract.address, topics, data);

    Ok(())
}

pub fn selfdestruct<H: Host, SPEC: Spec>(
    interpreter: &mut Interpreter,
    host: &mut H,
) -> EvmResult<Eval, H::DatabaseError> {
    check!(interpreter, !interpreter.is_static);
    pop_address!(interpreter, target);

    let res = host
        .selfdestruct(interpreter.contract.address, target)
        .map_err(EvmError::DatabaseFailure)?;

    // EIP-3529: Reduction in refunds
    if !SPEC::enabled(LONDON) && !res.previously_destroyed {
        refund!(interpreter, gas::SELFDESTRUCT)
    }
    gas!(interpreter, gas::selfdestruct_cost::<SPEC>(res));

    Ok(Eval::SelfDestruct)
}

pub fn create<const IS_CREATE2: bool, H: Host, SPEC: Spec>(
    interpreter: &mut Interpreter,
    host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    check!(interpreter, !interpreter.is_static);
    if IS_CREATE2 {
        // EIP-1014: Skinny CREATE2
        check!(interpreter, SPEC::enabled(PETERSBURG));
    }

    interpreter.return_data_buffer = Bytes::new();

    pop!(interpreter, value, code_offset, len);
    let len = as_usize_or_fail!(interpreter, len, Return::OutOfGas);

    let code = if len == 0 {
        Bytes::new()
    } else {
        let code_offset = as_usize_or_fail!(interpreter, code_offset, Return::OutOfGas);
        memory_resize!(interpreter, code_offset, len);
        Bytes::copy_from_slice(interpreter.memory.get_slice(code_offset, len))
    };

    let scheme = if IS_CREATE2 {
        pop!(interpreter, salt);
        gas_or_fail!(interpreter, gas::create2_cost(len));
        CreateScheme::Create2 { salt }
    } else {
        gas!(interpreter, gas::CREATE);
        CreateScheme::Create
    };

    let mut gas_limit = interpreter.gas().remaining();

    // EIP-150: Gas cost changes for IO-heavy operations
    if SPEC::enabled(TANGERINE) {
        // take remaining gas and deduce l64 part of it.
        gas_limit -= gas_limit / 64
    }
    gas!(interpreter, gas_limit);

    let mut create_input = CreateInputs {
        caller: interpreter.contract.address,
        scheme,
        value,
        init_code: code,
        gas_limit,
    };

    let CreateOutputs {
        exit_reason: eval,
        address,
        gas,
        return_value: out,
    } = host.create(&mut create_input)?;
    interpreter.return_data_buffer = match eval {
        // Save data to return data buffer if the create reverted
        return_revert!() => out,
        // Otherwise clear it
        _ => Bytes::new(),
    };

    match eval {
        return_ok!() => {
            interpreter
                .stack
                .push_b256(address.unwrap_or_default().into())?;
            interpreter.gas.erase_cost(gas.remaining());
            interpreter.gas.record_refund(gas.refunded());
        }
        return_revert!() => {
            interpreter.stack.push_b256(B256::zero())?;
            interpreter.gas.erase_cost(gas.remaining());
        }
        _ => {
            interpreter.stack.push_b256(B256::zero())?;
        }
    }
    interpreter.add_next_gas_block(interpreter.program_counter() - 1)?;

    Ok(())
}

pub fn call<H: Host, SPEC: Spec>(
    interpreter: &mut Interpreter,
    host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    call_inner::<H, SPEC>(interpreter, CallScheme::Call, host)
}

pub fn call_code<H: Host, SPEC: Spec>(
    interpreter: &mut Interpreter,
    host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    call_inner::<H, SPEC>(interpreter, CallScheme::CallCode, host)
}

pub fn delegate_call<H: Host, SPEC: Spec>(
    interpreter: &mut Interpreter,
    host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    call_inner::<H, SPEC>(interpreter, CallScheme::DelegateCall, host)
}

pub fn static_call<H: Host, SPEC: Spec>(
    interpreter: &mut Interpreter,
    host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    call_inner::<H, SPEC>(interpreter, CallScheme::StaticCall, host)
}

pub fn call_inner<H: Host, SPEC: Spec>(
    interpreter: &mut Interpreter,
    scheme: CallScheme,
    host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    match scheme {
        CallScheme::DelegateCall => check!(interpreter, SPEC::enabled(HOMESTEAD)), // EIP-7: DELEGATECALL
        CallScheme::StaticCall => check!(interpreter, SPEC::enabled(BYZANTIUM)), // EIP-214: New opcode STATICCALL
        _ => (),
    }
    interpreter.return_data_buffer = Bytes::new();

    pop!(interpreter, local_gas_limit);
    pop_address!(interpreter, to);
    let local_gas_limit = u64::try_from(local_gas_limit).unwrap_or(u64::MAX);

    let value = match scheme {
        CallScheme::CallCode => {
            pop!(interpreter, value);
            value
        }
        CallScheme::Call => {
            pop!(interpreter, value);
            if interpreter.is_static && value != U256::ZERO {
                return Err(EvmError::from(ExceptionalHalt::WriteInStaticContext));
            }
            value
        }
        CallScheme::DelegateCall | CallScheme::StaticCall => U256::ZERO,
    };

    pop!(interpreter, in_offset, in_len, out_offset, out_len);

    let in_len = as_usize_or_fail!(interpreter, in_len, Return::OutOfGas);
    let input = if in_len != 0 {
        let in_offset = as_usize_or_fail!(interpreter, in_offset, Return::OutOfGas);
        memory_resize!(interpreter, in_offset, in_len);
        Bytes::copy_from_slice(interpreter.memory.get_slice(in_offset, in_len))
    } else {
        Bytes::new()
    };

    let out_len = as_usize_or_fail!(interpreter, out_len, Return::OutOfGas);
    let out_offset = if out_len != 0 {
        let out_offset = as_usize_or_fail!(interpreter, out_offset, Return::OutOfGas);
        memory_resize!(interpreter, out_offset, out_len);
        out_offset
    } else {
        usize::MAX //unrealistic value so we are sure it is not used
    };

    let context = match scheme {
        CallScheme::Call | CallScheme::StaticCall => CallContext {
            address: to,
            caller: interpreter.contract.address,
            code_address: to,
            apparent_value: value,
            scheme,
        },
        CallScheme::CallCode => CallContext {
            address: interpreter.contract.address,
            caller: interpreter.contract.address,
            code_address: to,
            apparent_value: value,
            scheme,
        },
        CallScheme::DelegateCall => CallContext {
            address: interpreter.contract.address,
            caller: interpreter.contract.caller,
            code_address: to,
            apparent_value: interpreter.contract.value,
            scheme,
        },
    };

    let transfer = if scheme == CallScheme::Call {
        Transfer {
            source: interpreter.contract.address,
            target: to,
            value,
        }
    } else if scheme == CallScheme::CallCode {
        Transfer {
            source: interpreter.contract.address,
            target: interpreter.contract.address,
            value,
        }
    } else {
        //this is dummy send for StaticCall and DelegateCall, it should do nothing and dont touch anything.
        Transfer {
            source: interpreter.contract.address,
            target: interpreter.contract.address,
            value: U256::ZERO,
        }
    };

    // load account and calculate gas cost.
    let (is_cold, exist) = host.load_account(to).map_err(EvmError::DatabaseFailure)?;

    let is_new = !exist;

    gas!(
        interpreter,
        gas::call_cost::<SPEC>(
            value,
            is_new,
            is_cold,
            matches!(scheme, CallScheme::Call | CallScheme::CallCode),
            matches!(scheme, CallScheme::Call | CallScheme::StaticCall),
        )
    );

    // take l64 part of gas_limit
    let mut gas_limit = if SPEC::enabled(TANGERINE) {
        //EIP-150: Gas cost changes for IO-heavy operations
        let gas = interpreter.gas().remaining();
        min(gas - gas / 64, local_gas_limit)
    } else {
        local_gas_limit
    };

    gas!(interpreter, gas_limit);

    // add call stipend if there is value to be transferred.
    if matches!(scheme, CallScheme::Call | CallScheme::CallCode) && transfer.value != U256::ZERO {
        gas_limit = gas_limit.saturating_add(gas::CALL_STIPEND);
    }
    let is_static = matches!(scheme, CallScheme::StaticCall) || interpreter.is_static;

    let mut call_input = CallInputs {
        contract: to,
        transfer,
        input,
        gas_limit,
        context,
        is_static,
    };

    // Call host to interuct with target contract
    let CallOutputs {
        exit_reason: eval,
        gas,
        return_value: out,
    } = host.call(&mut call_input)?;

    interpreter.return_data_buffer = out;

    let target_len = min(out_len, interpreter.return_data_buffer.len());

    match eval {
        return_ok!() => {
            // return unspend gas.
            interpreter.gas.erase_cost(gas.remaining());
            interpreter.gas.record_refund(gas.refunded());
            interpreter
                .memory
                .set(out_offset, &interpreter.return_data_buffer[..target_len]);
            push!(interpreter, U256::from(1));
        }
        return_revert!() => {
            interpreter.gas.erase_cost(gas.remaining());
            interpreter
                .memory
                .set(out_offset, &interpreter.return_data_buffer[..target_len]);
            push!(interpreter, U256::ZERO);
        }
        _ => {
            push!(interpreter, U256::ZERO);
        }
    }
    interpreter.add_next_gas_block(interpreter.program_counter() - 1)?;

    Ok(())
}
