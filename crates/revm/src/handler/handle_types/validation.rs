use crate::{
    handler::mainnet,
    primitives::{EVMError, Env, Spec},
    Context, EvmContext,
};
use std::sync::Arc;

/// Handle that validates env.
pub type ValidateEnvHandle<'a, DBError> = Arc<dyn Fn(&Env) -> Result<(), EVMError<DBError>> + 'a>;

/// Handle that validates transaction environment against the state.
/// Second parametar is initial gas.
pub type ValidateTxEnvAgainstState<'a, EXT, DBError> =
    Arc<dyn Fn(&mut dyn EvmContext<DBError>, &mut EXT) -> Result<(), EVMError<DBError>> + 'a>;

/// Initial gas calculation handle
pub type ValidateInitialTxGasHandle<'a, DBError> =
    Arc<dyn Fn(&Env) -> Result<u64, EVMError<DBError>> + 'a>;

/// Handles related to validation.
pub struct ValidationHandler<'a, EXT, DBError> {
    /// Validate and calculate initial transaction gas.
    pub initial_tx_gas: ValidateInitialTxGasHandle<'a, DBError>,
    /// Validate transactions against state data.
    pub tx_against_state: ValidateTxEnvAgainstState<'a, EXT, DBError>,
    /// Validate Env.
    pub env: ValidateEnvHandle<'a, DBError>,
}

impl<'a, EXT: 'a, DBError: 'a> ValidationHandler<'a, EXT, DBError> {
    /// Create new ValidationHandles
    pub fn new<SPEC: Spec + 'a>() -> Self {
        Self {
            initial_tx_gas: Arc::new(mainnet::validate_initial_tx_gas::<SPEC, DBError>),
            env: Arc::new(mainnet::validate_env::<SPEC, DBError>),
            tx_against_state: Arc::new(mainnet::validate_tx_against_state::<SPEC, EXT, DBError>),
        }
    }
}

impl<'a, EXT, DBError> ValidationHandler<'a, EXT, DBError> {
    /// Validate env.
    pub fn env(&self, env: &Env) -> Result<(), EVMError<DBError>> {
        (self.env)(env)
    }

    /// Initial gas
    pub fn initial_tx_gas(&self, env: &Env) -> Result<u64, EVMError<DBError>> {
        (self.initial_tx_gas)(env)
    }

    /// Validate ttansaction against the state.
    pub fn tx_against_state(
        &self,
        evm: &mut dyn EvmContext<DBError>,
        ext: &mut EXT,
    ) -> Result<(), EVMError<DBError>> {
        (self.tx_against_state)(evm, ext)
    }
}
