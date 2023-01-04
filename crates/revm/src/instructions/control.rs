use crate::{
    evm_impl::{EvmError, EvmResult, ExceptionalHalt},
    gas,
    interpreter::Interpreter,
    Host, Return, Spec,
    SpecId::*,
    U256,
};

use super::Eval;

pub fn jump<H: Host>(
    interpreter: &mut Interpreter,
    _host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    // gas!(interp, gas::MID);
    pop!(interpreter, dest);
    let dest = as_usize_or_fail!(interpreter, dest, Return::InvalidJump);
    if interpreter.contract.is_valid_jump(dest) {
        // Safety: In analysis we are checking create our jump table and we do check above to be
        // sure that jump is safe to execute.
        interpreter.instruction_pointer =
            unsafe { interpreter.contract.bytecode.as_ptr().add(dest) };
    } else {
        return Err(EvmError::from(ExceptionalHalt::InvalidJump));
    }

    Ok(())
}

pub fn jumpi<H: Host>(
    interpreter: &mut Interpreter,
    _host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    // gas!(interp, gas::HIGH);
    pop!(interpreter, dest, value);
    if value != U256::ZERO {
        let dest = as_usize_or_fail!(interpreter, dest, Return::InvalidJump);
        if interpreter.contract.is_valid_jump(dest) {
            // Safety: In analysis we are checking if jump is valid destination and
            // this `if` makes this unsafe block safe.
            interpreter.instruction_pointer =
                unsafe { interpreter.contract.bytecode.as_ptr().add(dest) };
        } else {
            return Err(EvmError::from(ExceptionalHalt::InvalidJump));
        }
    } else {
        // if we are not doing jump, add next gas block.
        interpreter.add_next_gas_block(interpreter.program_counter() - 1)?;
    }

    Ok(())
}

pub fn jumpdest<H: Host>(
    interpreter: &mut Interpreter,
    _host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    gas!(interpreter, gas::JUMPDEST);
    interpreter.add_next_gas_block(interpreter.program_counter() - 1)?;

    Ok(())
}

pub fn pc<H: Host>(
    interpreter: &mut Interpreter,
    _host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    // gas!(interp, gas::BASE);
    push!(interpreter, U256::from(interpreter.program_counter() - 1));

    Ok(())
}

pub fn ret<H: Host>(
    interpreter: &mut Interpreter,
    _host: &mut H,
) -> EvmResult<Eval, H::DatabaseError> {
    // zero gas cost gas!(interp,gas::ZERO);
    pop!(interpreter, start, len);
    let len = as_usize_or_fail!(interpreter, len, Return::OutOfGas);
    if len == 0 {
        interpreter.return_range = usize::MAX..usize::MAX;
    } else {
        let offset = as_usize_or_fail!(interpreter, start, Return::OutOfGas);
        memory_resize!(interpreter, offset, len);
        interpreter.return_range = offset..(offset + len);
    }
    Ok(Eval::Return)
}

pub fn revert<H: Host, SPEC: Spec>(
    interpreter: &mut Interpreter,
    _host: &mut H,
) -> EvmResult<Eval, H::DatabaseError> {
    // zero gas cost gas!(interp,gas::ZERO);
    // EIP-140: REVERT instruction
    check!(interpreter, SPEC::enabled(BYZANTIUM));
    pop!(interpreter, start, len);
    let len = as_usize_or_fail!(interpreter, len, Return::OutOfGas);
    if len == 0 {
        interpreter.return_range = usize::MAX..usize::MAX;
    } else {
        let offset = as_usize_or_fail!(interpreter, start, Return::OutOfGas);
        memory_resize!(interpreter, offset, len);
        interpreter.return_range = offset..(offset + len);
    }
    Ok(Eval::Revert)
}
