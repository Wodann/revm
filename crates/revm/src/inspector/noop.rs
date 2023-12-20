use core::fmt::Debug;

use crate::Inspector;

/// Dummy [Inspector], helpful as standalone replacement.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NoOpInspector;

impl<DatabaseError> Inspector<DatabaseError> for NoOpInspector {}
