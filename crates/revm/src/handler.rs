pub mod mainnet;
#[cfg(feature = "optimism")]
pub mod optimism;

use crate::{
    interpreter::{Gas, InstructionResult},
    primitives::{EVMError, EVMResultGeneric, Env, Output, ResultAndState, Spec},
    EvmContext,
};

/// Handle call return and return final gas value.
type CallReturnHandle = fn(&Env, InstructionResult, Gas) -> Gas;

/// Reimburse the caller with ethereum it didn't spent.
type ReimburseCallerHandle<DatabaseError> =
    fn(&mut EvmContext<'_, DatabaseError>, &Gas) -> EVMResultGeneric<(), DatabaseError>;

/// Reward beneficiary with transaction rewards.
type RewardBeneficiaryHandle<DatabaseError> = ReimburseCallerHandle<DatabaseError>;

/// Calculate gas refund for transaction.
type CalculateGasRefundHandle = fn(&Env, &Gas) -> u64;

/// Main return handle, takes state from journal and transforms internal result to external.
type MainReturnHandle<DatabaseError> = fn(
    &mut EvmContext<'_, DatabaseError>,
    InstructionResult,
    Output,
    &Gas,
) -> Result<ResultAndState, EVMError<DatabaseError>>;

/// End handle, takes result and state and returns final result.
/// This will be called after all the other handlers.
///
/// It is useful for catching errors and returning them in a different way.
type EndHandle<DatabaseError> = fn(
    &mut EvmContext<'_, DatabaseError>,
    evm_output: Result<ResultAndState, EVMError<DatabaseError>>,
) -> Result<ResultAndState, EVMError<DatabaseError>>;

/// Handler acts as a proxy and allow to define different behavior for different
/// sections of the code. This allows nice integration of different chains or
/// to disable some mainnet behavior.
pub struct Handler<DatabaseError> {
    // Uses env, call result and returned gas from the call to determine the gas
    // that is returned from transaction execution..
    pub call_return: CallReturnHandle,
    /// Reimburse the caller with ethereum it didn't spent.
    pub reimburse_caller: ReimburseCallerHandle<DatabaseError>,
    /// Reward the beneficiary with caller fee.
    pub reward_beneficiary: RewardBeneficiaryHandle<DatabaseError>,
    /// Calculate gas refund for transaction.
    /// Some chains have it disabled.
    pub calculate_gas_refund: CalculateGasRefundHandle,
    /// Main return handle, returns the output of the transact.
    pub main_return: MainReturnHandle<DatabaseError>,
    /// End handle.
    pub end: EndHandle<DatabaseError>,
}

impl<DatabaseError> Handler<DatabaseError> {
    /// Handler for the mainnet
    pub fn mainnet<SPEC: Spec>() -> Self {
        Self {
            call_return: mainnet::handle_call_return::<SPEC>,
            calculate_gas_refund: mainnet::calculate_gas_refund::<SPEC>,
            reimburse_caller: mainnet::handle_reimburse_caller::<SPEC, DatabaseError>,
            reward_beneficiary: mainnet::reward_beneficiary::<SPEC, DatabaseError>,
            main_return: mainnet::main_return::<DatabaseError>,
            end: mainnet::end_handle::<DatabaseError>,
        }
    }

    /// Handler for the optimism
    #[cfg(feature = "optimism")]
    pub fn optimism<SPEC: Spec>() -> Self {
        Self {
            call_return: optimism::handle_call_return::<SPEC>,
            // we reinburse caller the same was as in mainnet.
            // Refund is calculated differently then mainnet.
            reimburse_caller: mainnet::handle_reimburse_caller::<SPEC, DatabaseError>,
            calculate_gas_refund: optimism::calculate_gas_refund::<SPEC>,
            reward_beneficiary: optimism::reward_beneficiary::<SPEC, DatabaseError>,
            // In case of halt of deposit transaction return Error.
            main_return: optimism::main_return::<SPEC, DatabaseError>,
            end: optimism::end_handle::<SPEC, DatabaseError>,
        }
    }

    /// Handle call return, depending on instruction result gas will be reimbursed or not.
    pub fn call_return(&self, env: &Env, call_result: InstructionResult, returned_gas: Gas) -> Gas {
        (self.call_return)(env, call_result, returned_gas)
    }

    /// Reimburse the caller with gas that were not spend.
    pub fn reimburse_caller(
        &self,
        context: &mut EvmContext<'_, DatabaseError>,
        gas: &Gas,
    ) -> Result<(), EVMError<DatabaseError>> {
        (self.reimburse_caller)(context, gas)
    }

    /// Calculate gas refund for transaction. Some chains have it disabled.
    pub fn calculate_gas_refund(&self, env: &Env, gas: &Gas) -> u64 {
        (self.calculate_gas_refund)(env, gas)
    }

    /// Reward beneficiary
    pub fn reward_beneficiary(
        &self,
        context: &mut EvmContext<'_, DatabaseError>,
        gas: &Gas,
    ) -> Result<(), EVMError<DatabaseError>> {
        (self.reward_beneficiary)(context, gas)
    }

    /// Main return.
    pub fn main_return(
        &self,
        context: &mut EvmContext<'_, DatabaseError>,
        call_result: InstructionResult,
        output: Output,
        gas: &Gas,
    ) -> Result<ResultAndState, EVMError<DatabaseError>> {
        (self.main_return)(context, call_result, output, gas)
    }

    /// End handler.
    pub fn end(
        &self,
        context: &mut EvmContext<'_, DatabaseError>,
        end_output: Result<ResultAndState, EVMError<DatabaseError>>,
    ) -> Result<ResultAndState, EVMError<DatabaseError>> {
        (self.end)(context, end_output)
    }
}
