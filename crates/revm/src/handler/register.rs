use crate::{
    db::Database,
    handler::{Handler, HandlerCfg},
    interpreter::opcode::InstructionTables,
    EvmImpl,
};
use std::boxed::Box;

/// EVM Handler
pub trait EvmHandler<'a, EXT, DBError> {
    fn cfg(&self) -> &HandlerCfg;

    fn instruction_table_mut(
        &mut self,
    ) -> &mut Option<InstructionTables<'a, EvmImpl<'a, EXT, DBError>>>;
}

// pub type EvmHandler<'a, EXT, DB> = Handler<'a, EvmImpl<'a, EXT, DB>, EXT, DB>;

/// EVM Instruction Tables
pub type EvmInstructionTables<'a, EXT, DB> = InstructionTables<'a, EvmImpl<'a, EXT, DB>>;

// Handle register
pub type HandleRegister<EXT, DB> = for<'a> fn(&mut EvmHandler<'a, EXT, DB>);

// Boxed handle register
pub type HandleRegisterBox<EXT, DB> = Box<dyn for<'a> Fn(&mut EvmHandler<'a, EXT, DB>)>;

pub enum HandleRegisters<EXT, DB: Database> {
    /// Plain function register
    Plain(HandleRegister<EXT, DB>),
    /// Boxed function register.
    Box(HandleRegisterBox<EXT, DB>),
}

impl<EXT, DB: Database> HandleRegisters<EXT, DB> {
    /// Call register function to modify EvmHandler.
    pub fn register(&self, handler: &mut EvmHandler<'_, EXT, DB>) {
        match self {
            HandleRegisters::Plain(f) => f(handler),
            HandleRegisters::Box(f) => f(handler),
        }
    }
}
