//! Dummy NoOp Inspector, helpful as standalone replacement.

use crate::Inspector;

#[derive(Clone, Copy)]
pub struct NoOpInspector;

impl<DatabaseErrorT> Inspector<DatabaseErrorT> for NoOpInspector {}
