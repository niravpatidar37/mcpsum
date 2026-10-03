//! mcpsum: a reference monitor for the Model Context Protocol.
//!
//! The enforcement core (`monitor`) is a pure state machine with no I/O so that
//! every security invariant can be tested deterministically and property-tested.
//! The I/O shell (`proxy`, `probe`) is kept thin.

pub mod audit;
pub mod canon;
pub mod framing;
pub mod lock;
pub mod monitor;
pub mod probe;
pub mod process;
pub mod render;
pub mod report;
