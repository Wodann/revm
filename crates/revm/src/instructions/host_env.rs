use crate::{
    evm_impl::{EvmError, EvmResult},
    interpreter::Interpreter,
    Host, Return, Spec,
    SpecId::*,
};

pub fn chainid<H: Host, SPEC: Spec>(
    interpreter: &mut Interpreter,
    host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    // gas!(interp, gas::BASE);
    // EIP-1344: ChainID opcode
    check!(interpreter, SPEC::enabled(ISTANBUL));
    push!(interpreter, host.env().cfg.chain_id);

    Ok(())
}

pub fn coinbase<H: Host>(
    interpreter: &mut Interpreter,
    host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    // gas!(interp, gas::BASE);
    interpreter
        .stack
        .push_b256(host.env().block.coinbase.into())
        .map_err(EvmError::from)
}

pub fn timestamp<H: Host>(
    interpreter: &mut Interpreter,
    host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    // gas!(interp, gas::BASE);
    push!(interpreter, host.env().block.timestamp);

    Ok(())
}

pub fn number<H: Host>(
    interpreter: &mut Interpreter,
    host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    // gas!(interp, gas::BASE);
    push!(interpreter, host.env().block.number);

    Ok(())
}

pub fn difficulty<H: Host, SPEC: Spec>(
    interpreter: &mut Interpreter,
    host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    // gas!(interp, gas::BASE);
    if SPEC::enabled(MERGE) {
        interpreter
            .stack
            .push_b256(host.env().block.prevrandao.unwrap())?;
    } else {
        push!(interpreter, host.env().block.difficulty);
    }

    Ok(())
}

pub fn gaslimit<H: Host>(
    interpreter: &mut Interpreter,
    host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    // gas!(interp, gas::BASE);
    push!(interpreter, host.env().block.gas_limit);

    Ok(())
}

pub fn gasprice<H: Host>(
    interpreter: &mut Interpreter,
    host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    // gas!(interp, gas::BASE);
    push!(interpreter, host.env().effective_gas_price());

    Ok(())
}

pub fn basefee<H: Host, SPEC: Spec>(
    interpreter: &mut Interpreter,
    host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    // gas!(interp, gas::BASE);
    // EIP-3198: BASEFEE opcode
    check!(interpreter, SPEC::enabled(LONDON));
    push!(interpreter, host.env().block.basefee);

    Ok(())
}

pub fn origin<H: Host>(
    interpreter: &mut Interpreter,
    host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    // gas!(interp, gas::BASE);
    interpreter
        .stack
        .push_b256(host.env().tx.caller.into())
        .map_err(EvmError::from)
}
