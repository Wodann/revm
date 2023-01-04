use crate::{evm_impl::EvmResult, interpreter::Interpreter, Host, Return, U256};

pub fn mload<H: Host>(
    interpreter: &mut Interpreter,
    _host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    // gas!(interp, gas::VERYLOW);
    pop!(interpreter, index);
    let index = as_usize_or_fail!(interpreter, index, Return::OutOfGas);
    memory_resize!(interpreter, index, 32);
    push!(
        interpreter,
        U256::from_be_bytes::<{ U256::BYTES }>(
            interpreter.memory.get_slice(index, 32).try_into().unwrap()
        )
    );

    Ok(())
}

pub fn mstore<H: Host>(
    interpreter: &mut Interpreter,
    _host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    // gas!(interp, gas::VERYLOW);
    pop!(interpreter, index, value);
    let index = as_usize_or_fail!(interpreter, index, Return::OutOfGas);
    memory_resize!(interpreter, index, 32);
    interpreter.memory.set_u256(index, value);

    Ok(())
}

pub fn mstore8<H: Host>(
    interpreter: &mut Interpreter,
    _host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    // gas!(interp, gas::VERYLOW);
    pop!(interpreter, index, value);
    let index = as_usize_or_fail!(interpreter, index, Return::OutOfGas);
    memory_resize!(interpreter, index, 1);
    let value = value.as_le_bytes()[0];
    // Safety: we resized our memory two lines above.
    unsafe { interpreter.memory.set_byte(index, value) }

    Ok(())
}

pub fn msize<H: Host>(
    interpreter: &mut Interpreter,
    _host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    // gas!(interp, gas::BASE);
    push!(interpreter, U256::from(interpreter.memory.effective_len()));

    Ok(())
}
