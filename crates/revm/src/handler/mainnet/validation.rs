use revm_interpreter::gas;

use crate::{
    primitives::{EVMError, Env, InvalidTransaction, Spec},
    EvmContext,
};

/// Validate environment for the mainnet.
pub fn validate_env<SPEC: Spec, DBError>(env: &Env) -> Result<(), EVMError<DBError>> {
    // Important: validate block before tx.
    env.validate_block_env::<SPEC>()?;
    env.validate_tx::<SPEC>()?;
    Ok(())
}

/// Validates transaction against the state.
pub fn validate_tx_against_state<SPEC: Spec, EXT, DBError>(
    evm: &mut dyn EvmContext<DBError>,
    ext: &mut EXT,
) -> Result<(), EVMError<DBError>> {
    // load acc
    let tx_caller = evm.env_mut().tx.caller;
    let (caller_account, _) = evm
        .journaled_state_mut()
        .load_account(tx_caller, &mut evm.db_mut())?;

    evm.env_mut()
        .validate_tx_against_state::<SPEC>(caller_account)
        .map_err(EVMError::Transaction)?;

    Ok(())
}

/// Validate initial transaction gas.
pub fn validate_initial_tx_gas<SPEC: Spec, DBError>(env: &Env) -> Result<u64, EVMError<DBError>> {
    let input = &env.tx.data;
    let is_create = env.tx.transact_to.is_create();
    let access_list = &env.tx.access_list;

    let initial_gas_spend = gas::validate_initial_tx_gas::<SPEC>(input, is_create, access_list);

    // Additional check to see if limit is big enough to cover initial gas.
    if initial_gas_spend > env.tx.gas_limit {
        return Err(InvalidTransaction::CallGasCostMoreThanGasLimit.into());
    }
    Ok(initial_gas_spend)
}
