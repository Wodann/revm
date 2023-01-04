use crate::{
    common::keccak256,
    evm_impl::{EvmError, EvmResult, ExceptionalHalt},
    gas,
    interpreter::Interpreter,
    Host, Return, Spec,
    SpecId::*,
    B256, KECCAK_EMPTY, U256,
};
use std::cmp::min;

pub fn sha3<H: Host>(
    interpreter: &mut Interpreter,
    _host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    pop!(interpreter, from, len);
    let len = as_usize_or_fail!(interpreter, len, Return::OutOfGas);
    gas_or_fail!(interpreter, gas::sha3_cost(len as u64));
    let hash = if len == 0 {
        KECCAK_EMPTY
    } else {
        let from = as_usize_or_fail!(interpreter, from, Return::OutOfGas);
        memory_resize!(interpreter, from, len);
        keccak256(interpreter.memory.get_slice(from, len))
    };

    interpreter.stack.push_b256(hash).map_err(EvmError::from)
}

pub fn address<H: Host>(
    interpreter: &mut Interpreter,
    _host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    // gas!(interp, gas::BASE);
    interpreter
        .stack
        .push_b256(B256::from(interpreter.contract.address))
        .map_err(EvmError::from)
}

pub fn caller<H: Host>(
    interpreter: &mut Interpreter,
    _host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    // gas!(interp, gas::BASE);
    interpreter
        .stack
        .push_b256(B256::from(interpreter.contract.caller))
        .map_err(EvmError::from)
}

pub fn codesize<H: Host>(
    interpreter: &mut Interpreter,
    _host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    // gas!(interp, gas::BASE);
    push!(interpreter, U256::from(interpreter.contract.bytecode.len()));

    Ok(())
}

pub fn codecopy<H: Host>(
    interpreter: &mut Interpreter,
    _host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    pop!(interpreter, memory_offset, code_offset, len);
    let len = as_usize_or_fail!(interpreter, len, Return::OutOfGas);
    gas_or_fail!(interpreter, gas::verylowcopy_cost(len as u64));
    if len == 0 {
        return Ok(());
    }
    let memory_offset = as_usize_or_fail!(interpreter, memory_offset, Return::OutOfGas);
    let code_offset = as_usize_saturated!(code_offset);
    memory_resize!(interpreter, memory_offset, len);

    // Safety: set_data is unsafe function and memory_resize ensures us that it is safe to call it
    interpreter.memory.set_data(
        memory_offset,
        code_offset,
        len,
        interpreter.contract.bytecode.original_bytecode_slice(),
    );

    Ok(())
}

pub fn calldataload<H: Host>(
    interpreter: &mut Interpreter,
    _host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    // gas!(interp, gas::VERYLOW);
    pop!(interpreter, index);
    let index = as_usize_saturated!(index);

    let load = if index < interpreter.contract.input.len() {
        let have_bytes = min(interpreter.contract.input.len() - index, 32);
        let mut bytes = [0u8; 32];
        bytes[..have_bytes].copy_from_slice(&interpreter.contract.input[index..index + have_bytes]);
        B256(bytes)
    } else {
        B256::zero()
    };

    interpreter.stack.push_b256(load).map_err(EvmError::from)
}

pub fn calldatasize<H: Host>(
    interpreter: &mut Interpreter,
    _host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    // gas!(interp, gas::BASE);
    push!(interpreter, U256::from(interpreter.contract.input.len()));

    Ok(())
}

pub fn callvalue<H: Host>(
    interpreter: &mut Interpreter,
    _host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    // gas!(interp, gas::BASE);
    push!(interpreter, interpreter.contract.value);

    Ok(())
}

pub fn calldatacopy<H: Host>(
    interpreter: &mut Interpreter,
    _host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    pop!(interpreter, memory_offset, data_offset, len);
    let len = as_usize_or_fail!(interpreter, len, Return::OutOfGas);
    gas_or_fail!(interpreter, gas::verylowcopy_cost(len as u64));
    if len == 0 {
        return Ok(());
    }
    let memory_offset = as_usize_or_fail!(interpreter, memory_offset, Return::OutOfGas);
    let data_offset = as_usize_saturated!(data_offset);
    memory_resize!(interpreter, memory_offset, len);

    // Safety: set_data is unsafe function and memory_resize ensures us that it is safe to call it
    interpreter
        .memory
        .set_data(memory_offset, data_offset, len, &interpreter.contract.input);

    Ok(())
}

pub fn returndatasize<H: Host, SPEC: Spec>(
    interpreter: &mut Interpreter,
    _host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    // gas!(interp, gas::BASE);
    // EIP-211: New opcodes: RETURNDATASIZE and RETURNDATACOPY
    check!(interpreter, SPEC::enabled(BYZANTIUM));
    push!(
        interpreter,
        U256::from(interpreter.return_data_buffer.len())
    );

    Ok(())
}

pub fn returndatacopy<H: Host, SPEC: Spec>(
    interpreter: &mut Interpreter,
    _host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    // EIP-211: New opcodes: RETURNDATASIZE and RETURNDATACOPY
    check!(interpreter, SPEC::enabled(BYZANTIUM));
    pop!(interpreter, memory_offset, offset, len);
    let len = as_usize_or_fail!(interpreter, len, Return::OutOfGas);
    gas_or_fail!(interpreter, gas::verylowcopy_cost(len as u64));
    let data_offset = as_usize_saturated!(offset);
    let (data_end, overflow) = data_offset.overflowing_add(len);
    if overflow || data_end > interpreter.return_data_buffer.len() {
        return Err(EvmError::from(ExceptionalHalt::OutOfBoundsRead));
    }
    if len != 0 {
        let memory_offset = as_usize_or_fail!(interpreter, memory_offset, Return::OutOfGas);
        memory_resize!(interpreter, memory_offset, len);
        interpreter.memory.set(
            memory_offset,
            &interpreter.return_data_buffer[data_offset..data_end],
        );
    }

    Ok(())
}

pub fn gas<H: Host>(
    interpreter: &mut Interpreter,
    _host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    // gas!(interp, gas::BASE);
    push!(interpreter, U256::from(interpreter.gas.remaining()));
    interpreter.add_next_gas_block(interpreter.program_counter() - 1)?;

    Ok(())
}
