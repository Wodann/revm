#[macro_use]
mod macros;
mod arithmetic;
mod bitwise;
mod control;
mod host;
mod host_env;
mod i256;
mod memory;
pub mod opcode;
mod stack;
mod system;

use crate::{
    evm_impl::{EthereumError, EvmResult, ExceptionalHalt},
    interpreter::Interpreter,
    Host, Spec,
};
pub use opcode::{OpCode, OPCODE_JUMPMAP};

#[macro_export]
macro_rules! return_ok {
    () => {
        Eval::Continue | Eval::Stop | Eval::Return | Eval::SelfDestruct
    };
}

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Eval {
    Continue = 0x00,
    Stop = 0x01,
    Return = 0x02,
    SelfDestruct = 0x03,
    /// Raised by the `REVERT` opcode.
    ///
    /// Unlike other EVM exceptions this does not result in the consumption of all gas.
    Revert = 0x20,
}

impl Default for Eval {
    fn default() -> Self {
        Eval::Continue
    }
}

#[derive(Debug)]
pub enum Reason {
    Success(Eval),
    Failure(EthereumError),
}

impl From<Eval> for Reason {
    fn from(eval: Eval) -> Self {
        Reason::Success(eval)
    }
}

impl From<ExceptionalHalt> for Reason {
    fn from(exceptional_halt: ExceptionalHalt) -> Self {
        Self::Failure(EthereumError::from(exceptional_halt))
    }
}

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Return {
    //success codes
    Continue = 0x00,
    Stop = 0x01,
    Return = 0x02,
    SelfDestruct = 0x03,

    // revert code
    Revert = 0x20, // revert opcode
    CallTooDeep = 0x21,
    OutOfFund = 0x22,

    // error codes
    OutOfGas = 0x50,
    OpcodeNotFound,
    CallNotAllowedInsideStatic,
    InvalidOpcode,
    InvalidJump,
    InvalidMemoryRange,
    NotActivated,
    StackUnderflow,
    StackOverflow,
    OutOfOffset,
    CreateCollision = 0x60,
    PrecompileError = 0x62,
    /// Create init code exceeds limit (runtime).
    CreateContractLimit = 0x64,
    /// Error on created contract that begins with EF
    CreateContractWithEF,
}

pub fn return_stop<H: Host>(
    interpreter: &mut Interpreter,
    _host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    interpreter.instruction_result = Return::Stop;

    Ok(())
}
pub fn return_invalid<H: Host>(
    interpreter: &mut Interpreter,
    _host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    interpreter.instruction_result = Return::InvalidOpcode;

    Ok(())
}

pub fn return_not_found<H: Host>(
    interpreter: &mut Interpreter,
    _host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    interpreter.instruction_result = Return::OpcodeNotFound;

    Ok(())
}

#[inline(always)]
pub fn eval<H: Host, S: Spec>(
    opcode: u8,
    interp: &mut Interpreter,
    host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    match opcode {
        opcode::STOP => return_stop(interp, host),
        opcode::ADD => arithmetic::wrapped_add(interp, host),
        opcode::MUL => arithmetic::wrapping_mul(interp, host),
        opcode::SUB => arithmetic::wrapping_sub(interp, host),
        opcode::DIV => arithmetic::div(interp, host),
        opcode::SDIV => arithmetic::sdiv(interp, host),
        opcode::MOD => arithmetic::rem(interp, host),
        opcode::SMOD => arithmetic::smod(interp, host),
        opcode::ADDMOD => arithmetic::addmod(interp, host),
        opcode::MULMOD => arithmetic::mulmod(interp, host),
        opcode::EXP => arithmetic::eval_exp::<H, S>(interp, host),
        opcode::SIGNEXTEND => arithmetic::signextend(interp, host),
        opcode::LT => bitwise::lt(interp, host),
        opcode::GT => bitwise::gt(interp, host),
        opcode::SLT => bitwise::slt(interp, host),
        opcode::SGT => bitwise::sgt(interp, host),
        opcode::EQ => bitwise::eq(interp, host),
        opcode::ISZERO => bitwise::iszero(interp, host),
        opcode::AND => bitwise::bitand(interp, host),
        opcode::OR => bitwise::bitor(interp, host),
        opcode::XOR => bitwise::bitxor(interp, host),
        opcode::NOT => bitwise::not(interp, host),
        opcode::BYTE => bitwise::byte(interp, host),
        opcode::SHL => bitwise::shl::<H, S>(interp, host),
        opcode::SHR => bitwise::shr::<H, S>(interp, host),
        opcode::SAR => bitwise::sar::<H, S>(interp, host),
        opcode::SHA3 => system::sha3(interp, host),
        opcode::ADDRESS => system::address(interp, host),
        opcode::BALANCE => host::balance::<H, S>(interp, host),
        opcode::SELFBALANCE => host::selfbalance::<H, S>(interp, host),
        opcode::CODESIZE => system::codesize(interp, host),
        opcode::CODECOPY => system::codecopy(interp, host),
        opcode::CALLDATALOAD => system::calldataload(interp, host),
        opcode::CALLDATASIZE => system::calldatasize(interp, host),
        opcode::CALLDATACOPY => system::calldatacopy(interp, host),
        opcode::POP => stack::pop(interp, host),
        opcode::MLOAD => memory::mload(interp, host),
        opcode::MSTORE => memory::mstore(interp, host),
        opcode::MSTORE8 => memory::mstore8(interp, host),
        opcode::JUMP => control::jump(interp, host),
        opcode::JUMPI => control::jumpi(interp, host),
        opcode::PC => control::pc(interp, host),
        opcode::MSIZE => memory::msize(interp, host),
        opcode::JUMPDEST => control::jumpdest(interp, host),
        opcode::PUSH1 => stack::push::<1, H>(interp, host),
        opcode::PUSH2 => stack::push::<2, H>(interp, host),
        opcode::PUSH3 => stack::push::<3, H>(interp, host),
        opcode::PUSH4 => stack::push::<4, H>(interp, host),
        opcode::PUSH5 => stack::push::<5, H>(interp, host),
        opcode::PUSH6 => stack::push::<6, H>(interp, host),
        opcode::PUSH7 => stack::push::<7, H>(interp, host),
        opcode::PUSH8 => stack::push::<8, H>(interp, host),
        opcode::PUSH9 => stack::push::<9, H>(interp, host),
        opcode::PUSH10 => stack::push::<10, H>(interp, host),
        opcode::PUSH11 => stack::push::<11, H>(interp, host),
        opcode::PUSH12 => stack::push::<12, H>(interp, host),
        opcode::PUSH13 => stack::push::<13, H>(interp, host),
        opcode::PUSH14 => stack::push::<14, H>(interp, host),
        opcode::PUSH15 => stack::push::<15, H>(interp, host),
        opcode::PUSH16 => stack::push::<16, H>(interp, host),
        opcode::PUSH17 => stack::push::<17, H>(interp, host),
        opcode::PUSH18 => stack::push::<18, H>(interp, host),
        opcode::PUSH19 => stack::push::<19, H>(interp, host),
        opcode::PUSH20 => stack::push::<20, H>(interp, host),
        opcode::PUSH21 => stack::push::<21, H>(interp, host),
        opcode::PUSH22 => stack::push::<22, H>(interp, host),
        opcode::PUSH23 => stack::push::<23, H>(interp, host),
        opcode::PUSH24 => stack::push::<24, H>(interp, host),
        opcode::PUSH25 => stack::push::<25, H>(interp, host),
        opcode::PUSH26 => stack::push::<26, H>(interp, host),
        opcode::PUSH27 => stack::push::<27, H>(interp, host),
        opcode::PUSH28 => stack::push::<28, H>(interp, host),
        opcode::PUSH29 => stack::push::<29, H>(interp, host),
        opcode::PUSH30 => stack::push::<30, H>(interp, host),
        opcode::PUSH31 => stack::push::<31, H>(interp, host),
        opcode::PUSH32 => stack::push::<32, H>(interp, host),
        opcode::DUP1 => stack::dup::<1, H>(interp, host),
        opcode::DUP2 => stack::dup::<2, H>(interp, host),
        opcode::DUP3 => stack::dup::<3, H>(interp, host),
        opcode::DUP4 => stack::dup::<4, H>(interp, host),
        opcode::DUP5 => stack::dup::<5, H>(interp, host),
        opcode::DUP6 => stack::dup::<6, H>(interp, host),
        opcode::DUP7 => stack::dup::<7, H>(interp, host),
        opcode::DUP8 => stack::dup::<8, H>(interp, host),
        opcode::DUP9 => stack::dup::<9, H>(interp, host),
        opcode::DUP10 => stack::dup::<10, H>(interp, host),
        opcode::DUP11 => stack::dup::<11, H>(interp, host),
        opcode::DUP12 => stack::dup::<12, H>(interp, host),
        opcode::DUP13 => stack::dup::<13, H>(interp, host),
        opcode::DUP14 => stack::dup::<14, H>(interp, host),
        opcode::DUP15 => stack::dup::<15, H>(interp, host),
        opcode::DUP16 => stack::dup::<16, H>(interp, host),

        opcode::SWAP1 => stack::swap::<1, H>(interp, host),
        opcode::SWAP2 => stack::swap::<2, H>(interp, host),
        opcode::SWAP3 => stack::swap::<3, H>(interp, host),
        opcode::SWAP4 => stack::swap::<4, H>(interp, host),
        opcode::SWAP5 => stack::swap::<5, H>(interp, host),
        opcode::SWAP6 => stack::swap::<6, H>(interp, host),
        opcode::SWAP7 => stack::swap::<7, H>(interp, host),
        opcode::SWAP8 => stack::swap::<8, H>(interp, host),
        opcode::SWAP9 => stack::swap::<9, H>(interp, host),
        opcode::SWAP10 => stack::swap::<10, H>(interp, host),
        opcode::SWAP11 => stack::swap::<11, H>(interp, host),
        opcode::SWAP12 => stack::swap::<12, H>(interp, host),
        opcode::SWAP13 => stack::swap::<13, H>(interp, host),
        opcode::SWAP14 => stack::swap::<14, H>(interp, host),
        opcode::SWAP15 => stack::swap::<15, H>(interp, host),
        opcode::SWAP16 => stack::swap::<16, H>(interp, host),

        opcode::RETURN => control::ret(interp, host),
        opcode::REVERT => control::revert::<H, S>(interp, host),
        opcode::INVALID => return_invalid(interp, host),
        opcode::BASEFEE => host_env::basefee::<H, S>(interp, host),
        opcode::ORIGIN => host_env::origin(interp, host),
        opcode::CALLER => system::caller(interp, host),
        opcode::CALLVALUE => system::callvalue(interp, host),
        opcode::GASPRICE => host_env::gasprice(interp, host),
        opcode::EXTCODESIZE => host::extcodesize::<H, S>(interp, host),
        opcode::EXTCODEHASH => host::extcodehash::<H, S>(interp, host),
        opcode::EXTCODECOPY => host::extcodecopy::<H, S>(interp, host),
        opcode::RETURNDATASIZE => system::returndatasize::<H, S>(interp, host),
        opcode::RETURNDATACOPY => system::returndatacopy::<H, S>(interp, host),
        opcode::BLOCKHASH => host::blockhash(interp, host),
        opcode::COINBASE => host_env::coinbase(interp, host),
        opcode::TIMESTAMP => host_env::timestamp(interp, host),
        opcode::NUMBER => host_env::number(interp, host),
        opcode::DIFFICULTY => host_env::difficulty::<H, S>(interp, host),
        opcode::GASLIMIT => host_env::gaslimit(interp, host),
        opcode::SLOAD => host::sload::<H, S>(interp, host),
        opcode::SSTORE => host::sstore::<H, S>(interp, host),
        opcode::GAS => system::gas(interp, host),
        opcode::LOG0 => host::log::<0, H, S>(interp, host),
        opcode::LOG1 => host::log::<1, H, S>(interp, host),
        opcode::LOG2 => host::log::<2, H, S>(interp, host),
        opcode::LOG3 => host::log::<3, H, S>(interp, host),
        opcode::LOG4 => host::log::<4, H, S>(interp, host),
        opcode::SELFDESTRUCT => host::selfdestruct::<H, S>(interp, host),
        opcode::CREATE => host::create::<false, H, S>(interp, host), //check
        opcode::CREATE2 => host::create::<true, H, S>(interp, host), //check
        opcode::CALL => host::call::<H, S>(interp, host),            //check
        opcode::CALLCODE => host::call_code::<H, S>(interp, host),   //check
        opcode::DELEGATECALL => host::delegate_call::<H, S>(interp, host), //check
        opcode::STATICCALL => host::static_call::<H, S>(interp, host), //check
        opcode::CHAINID => host_env::chainid::<H, S>(interp, host),
        _ => return_not_found(interp, host),
    }
}
