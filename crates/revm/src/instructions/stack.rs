use crate::{
    evm_impl::{EvmError, EvmResult},
    interpreter::Interpreter,
    Host,
};

pub fn pop<H: Host>(
    interpreter: &mut Interpreter,
    _host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    // gas!(interp, gas::BASE);
    interpreter.stack.reduce_one().map_err(EvmError::from)
}

pub fn push<const N: usize, H: Host>(
    interpreter: &mut Interpreter,
    _host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    // gas!(interp, gas::VERYLOW);
    let start = interpreter.instruction_pointer;
    // Safety: In Analysis we appended needed bytes for bytecode so that we are safe to just add without
    // checking if it is out of bound. This makes both of our unsafes block safe to do.
    interpreter
        .stack
        .push_slice::<N>(unsafe { core::slice::from_raw_parts(start, N) })?;

    interpreter.instruction_pointer = unsafe { interpreter.instruction_pointer.add(N) };
    Ok(())
}

pub fn dup<const N: usize, H: Host>(
    interpreter: &mut Interpreter,
    _host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    // gas!(interp, gas::VERYLOW);
    interpreter.stack.dup::<N>().map_err(EvmError::from)
}

pub fn swap<const N: usize, H: Host>(
    interpreter: &mut Interpreter,
    _host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    // gas!(interp, gas::VERYLOW);
    interpreter.stack.swap::<N>().map_err(EvmError::from)
}
