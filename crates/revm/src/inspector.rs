use crate::{
    bits::{B160, B256},
    evm_impl::EVMData,
    instructions::{Eval, Reason},
    CallInputs, CallOutputs, CreateInputs, CreateOutputs, Database, Interpreter,
};
use auto_impl::auto_impl;
use bytes::Bytes;

#[cfg(feature = "std")]
pub mod customprinter;
pub mod gas;
pub mod noop;

/// All Inspectors implementations that revm has.
pub mod inspectors {
    pub use super::customprinter::CustomPrintTracer;
    pub use super::gas::GasInspector;
    pub use super::noop::NoOpInspector;
}

#[auto_impl(&mut, Box)]
pub trait Inspector<DB: Database> {
    /// Called Before the interpreter is initialized.
    ///
    /// If anything other than [Return::Continue] is returned then execution of the interpreter is
    /// skipped.
    fn initialize_interp(
        &mut self,
        _interp: &mut Interpreter,
        _data: &mut EVMData<'_, DB>,
        _is_static: bool,
    ) -> Eval {
        Eval::Continue
    }

    /// Called on each step of the interpreter.
    ///
    /// Information about the current execution, including the memory, stack and more is available
    /// on `interp` (see [Interpreter]).
    ///
    /// # Example
    ///
    /// To get the current opcode, use `interp.current_opcode()`.
    fn step(
        &mut self,
        _interp: &mut Interpreter,
        _data: &mut EVMData<'_, DB>,
        _is_static: bool,
    ) -> Eval {
        Eval::Continue
    }

    /// Called when a log is emitted.
    fn log(
        &mut self,
        _evm_data: &mut EVMData<'_, DB>,
        _address: &B160,
        _topics: &[B256],
        _data: &Bytes,
    ) {
    }

    /// Called after `step` when the instruction has been executed.
    ///
    /// Returning anything other than [Return::Continue] alters the execution of the interpreter.
    fn step_end(
        &mut self,
        _interp: &mut Interpreter,
        _data: &mut EVMData<'_, DB>,
        _is_static: bool,
        _eval: Eval,
    ) -> Eval {
        Eval::Continue
    }

    /// Called whenever a call to a contract is about to start.
    ///
    /// Returning anything other than [Return::Continue] overrides the result of the call.
    fn call(
        &mut self,
        _data: &mut EVMData<'_, DB>,
        _inputs: &mut CallInputs,
        _is_static: bool,
    ) -> CallOutputs<Reason> {
        CallOutputs::default()
    }

    /// Called when a call to a contract has concluded.
    ///
    /// Returning anything other than the values passed to this function (`(ret, remaining_gas,
    /// out)`) will alter the result of the call.
    fn call_end(
        &mut self,
        _data: &mut EVMData<'_, DB>,
        _inputs: &CallInputs,
        outputs: CallOutputs<Reason>,
        _is_static: bool,
    ) -> CallOutputs<Reason> {
        outputs
    }

    /// Called when a contract is about to be created.
    ///
    /// Returning anything other than [Return::Continue] overrides the result of the creation.
    fn create(
        &mut self,
        _data: &mut EVMData<'_, DB>,
        _inputs: &mut CreateInputs,
    ) -> CreateOutputs<Eval> {
        CreateOutputs::default()
    }

    /// Called when a contract has been created.
    ///
    /// Returning anything other than the values passed to this function (`(ret, remaining_gas,
    /// address, out)`) will alter the result of the create.
    fn create_end(
        &mut self,
        _data: &mut EVMData<'_, DB>,
        _inputs: &CreateInputs,
        outputs: CreateOutputs<Reason>,
    ) -> CreateOutputs<Reason> {
        outputs
    }

    /// Called when a contract has been self-destructed.
    fn selfdestruct(&mut self) {}
}
