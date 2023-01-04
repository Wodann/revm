use super::i256::{i256_cmp, i256_sign, two_compl, Sign};
use crate::{evm_impl::EvmResult, Host, Interpreter, Return, Spec, SpecId::CONSTANTINOPLE, U256};
use core::cmp::Ordering;
use std::ops::{BitAnd, BitOr, BitXor};

pub fn lt<H: Host>(
    interpreter: &mut Interpreter,
    _host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    pop_top!(interpreter, op1, op2);
    *op2 = if op1.lt(op2) {
        U256::from(1)
    } else {
        U256::ZERO
    };

    Ok(())
}

pub fn gt<H: Host>(
    interpreter: &mut Interpreter,
    _host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    pop_top!(interpreter, op1, op2);
    *op2 = if op1.gt(op2) {
        U256::from(1)
    } else {
        U256::ZERO
    };

    Ok(())
}

pub fn slt<H: Host>(
    interpreter: &mut Interpreter,
    _host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    pop_top!(interpreter, op1, op2);
    *op2 = if i256_cmp(op1, *op2) == Ordering::Less {
        U256::from(1)
    } else {
        U256::ZERO
    };

    Ok(())
}

pub fn sgt<H: Host>(
    interpreter: &mut Interpreter,
    _host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    pop_top!(interpreter, op1, op2);
    *op2 = if i256_cmp(op1, *op2) == Ordering::Greater {
        U256::from(1)
    } else {
        U256::ZERO
    };

    Ok(())
}

pub fn eq<H: Host>(
    interpreter: &mut Interpreter,
    _host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    pop_top!(interpreter, op1, op2);
    *op2 = if op1.eq(op2) {
        U256::from(1)
    } else {
        U256::ZERO
    };

    Ok(())
}

pub fn iszero<H: Host>(
    interpreter: &mut Interpreter,
    _host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    pop_top!(interpreter, op1);
    *op1 = if *op1 == U256::ZERO {
        U256::from(1)
    } else {
        U256::ZERO
    };

    Ok(())
}
pub fn bitand<H: Host>(
    interpreter: &mut Interpreter,
    _host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    pop_top!(interpreter, op1, op2);
    *op2 = op1.bitand(*op2);

    Ok(())
}
pub fn bitor<H: Host>(
    interpreter: &mut Interpreter,
    _host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    pop_top!(interpreter, op1, op2);
    *op2 = op1.bitor(*op2);

    Ok(())
}
pub fn bitxor<H: Host>(
    interpreter: &mut Interpreter,
    _host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    pop_top!(interpreter, op1, op2);
    *op2 = op1.bitxor(*op2);

    Ok(())
}

pub fn not<H: Host>(
    interpreter: &mut Interpreter,
    _host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    pop_top!(interpreter, op1);
    *op1 = !*op1;

    Ok(())
}

pub fn byte<H: Host>(
    interpreter: &mut Interpreter,
    _host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    pop_top!(interpreter, op1, op2);
    let mut ret = U256::ZERO;

    for i in 0..256 {
        if i < 8 && op1 < U256::from(32) {
            let o = as_usize_saturated!(op1);
            let t = 255 - (7 - i + 8 * o);
            let bit_mask = U256::from(1) << t;
            let value = (*op2 & bit_mask) >> t;
            ret = ret.overflowing_add(value << i).0;
        }
    }

    *op2 = ret;

    Ok(())
}

pub fn shl<H: Host, SPEC: Spec>(
    interpreter: &mut Interpreter,
    _host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    // EIP-145: Bitwise shifting instructions in EVM
    check!(interpreter, SPEC::enabled(CONSTANTINOPLE));
    pop_top!(interpreter, op1, op2);
    *op2 <<= as_usize_saturated!(op1);

    Ok(())
}

pub fn shr<H: Host, SPEC: Spec>(
    interpreter: &mut Interpreter,
    _host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    // EIP-145: Bitwise shifting instructions in EVM
    check!(interpreter, SPEC::enabled(CONSTANTINOPLE));
    pop_top!(interpreter, op1, op2);
    *op2 >>= as_usize_saturated!(op1);

    Ok(())
}

pub fn sar<H: Host, SPEC: Spec>(
    interpreter: &mut Interpreter,
    _host: &mut H,
) -> EvmResult<(), H::DatabaseError> {
    // EIP-145: Bitwise shifting instructions in EVM
    check!(interpreter, SPEC::enabled(CONSTANTINOPLE));
    pop_top!(interpreter, op1, op2);

    let value_sign = i256_sign::<true>(op2);

    *op2 = if *op2 == U256::ZERO || op1 >= U256::from(256) {
        match value_sign {
            // value is 0 or >=1, pushing 0
            Sign::Plus | Sign::Zero => U256::ZERO,
            // value is <0, pushing -1
            Sign::Minus => two_compl(U256::from(1)),
        }
    } else {
        let shift = usize::try_from(op1).unwrap();

        match value_sign {
            Sign::Plus | Sign::Zero => *op2 >> shift,
            Sign::Minus => {
                let shifted = ((op2.overflowing_sub(U256::from(1)).0) >> shift)
                    .overflowing_add(U256::from(1))
                    .0;
                two_compl(shifted)
            }
        }
    };

    Ok(())
}
