//! The compiler side of the bytecode boundary: everything that produces a
//! runnable [`Program`] from Scarlet source. The ISA, [`Program`], the NaN-boxed
//! `value` and the heap live in `scarlet_vm` and are re-exported here, so
//! `scarlet_core::bytecode::*` is the one import for both halves of the contract.

mod analysis;
pub mod binop;
pub mod compiler;
mod peephole;
mod prelude;
pub mod prelude_bindings;
mod session;

pub(crate) use binop::{BinopKind, ShortCircuitOp, ValueBinop, specialize_binop};
pub use compiler::*;
pub use prelude_bindings::{CtorRef, PreludeBindings, TypeRef};
pub use scarlet_vm::bytecode::*;
pub use session::{HoverFact, IncrementalSession, Watermark};

/// Resolve an `@vm(name)` intrinsic key to its VM opcode. The only
/// string→Op mapping; analysis calls it while registering the stdlib so an
/// unknown key errors at the annotation, not during codegen.
fn builtin_op(name: &str) -> Option<Op> {
    Some(match name {
        "println" => Op::Print,
        "string__inspect" => Op::ToString,
        "internal__stack_depth" => Op::StackDepth,
        "io__read_file" => Op::FileRead,
        "io__write_file" => Op::FileWrite,
        "net__listen" => Op::TcpListen,
        "net__accept" => Op::TcpAccept,
        "net__connect" => Op::TcpConnect,
        "net__close" => Op::TcpCloseServer,
        "net__give" => Op::TcpGive,
        "net__local_addr" => Op::TcpLocalAddr,
        "net__resolve" => Op::DnsResolve,
        "address__parse" => Op::IpParse,
        "socket__read" => Op::TcpRead,
        "socket__read_until" => Op::TcpReadUntil,
        "socket__write" => Op::TcpWrite,
        "socket__write_parts" => Op::TcpWriteParts,
        "socket__close" => Op::TcpClose,
        "port__spawn" => Op::PortSpawn,
        "port__read" => Op::TcpRead,
        "port__read_until" => Op::TcpReadUntil,
        "port__write" => Op::TcpWrite,
        "port__write_parts" => Op::TcpWriteParts,
        "port__close" => Op::PortClose,
        "string__split" => Op::StrSplit,
        "string__length" => Op::StrLen,
        "string__contains" => Op::StrContains,
        "string__trim" => Op::StrTrim,
        "int__to_string" => Op::IntToString,
        "int__bitwise_and" => Op::BitAnd,
        "int__bitwise_or" => Op::BitOr,
        "int__bitwise_xor" => Op::BitXor,
        "int__bitwise_not" => Op::BitNot,
        "int__bitwise_shift_left" => Op::BitShl,
        "int__bitwise_shift_right" => Op::BitShr,
        "array__length" => Op::ArrayLen,
        "binary__from_string" => Op::BinFromString,
        "binary__to_string" => Op::BinToString,
        "binary__bit_size" => Op::BinBitSize,
        "binary__byte_size" => Op::BinByteSize,
        "binary__slice" => Op::BinSlice,
        "binary__append" => Op::BinAppend,
        "binary__index_of" => Op::BinIndexOf,
        "binary__byte_at" => Op::BinByteAt,
        "binary__parse_int" => Op::BinParseInt,
        "binary__eq_ignore_ascii_case" => Op::BinEqIgnoreAsciiCase,
        "binary__to_ascii_lower" => Op::BinToAsciiLower,
        "binary__from_int_ascii" => Op::BinFromIntAscii,
        "http__parse_head" => Op::HttpParseHead,
        "http__framing" => Op::HttpFraming,
        "http__chunk_decode" => Op::HttpChunkDecode,
        "http__header_get" => Op::HttpHeaderGet,
        "http__header_has" => Op::HttpHeaderHas,
        "http__headers_valid" => Op::HttpHeadersValid,
        "http__serialize_head" => Op::HttpSerializeHead,
        "float__floor" => Op::FloatFloor,
        "float__ceil" => Op::FloatCeil,
        "float__round" => Op::FloatRound,
        "float__truncate" => Op::FloatTruncate,
        "float__from_int" => Op::FloatFromInt,
        "float__to_string" => Op::FloatToString,
        "process__spawn" => Op::ProcessSpawn,
        "process__spawn_unlinked" => Op::ProcessSpawnUnlinked,
        "process__kill" => Op::ProcessKill,
        "process__self" => Op::ProcessSelf,
        "process__monitor" => Op::ProcessMonitor,
        "process__demonitor" => Op::ProcessDemonitor,
        "net__spawn_per_core" => Op::SpawnOnEach,
        "process__sleep" => Op::Sleep,
        "process__subject" => Op::SubjectNew,
        "process__send" => Op::SubjectSend,
        "process__receive" => Op::SubjectReceive,
        "process__receive_until" => Op::SubjectReceiveUntil,
        "time__monotonic" => Op::Monotonic,
        "os__argv" => Op::Argv,
        "os__env" => Op::EnvMap,
        "map__get" => Op::MapGet,
        "map__has" => Op::MapHas,
        "map__keys" => Op::MapKeys,
        "map__values" => Op::MapValues,
        "map__size" => Op::MapSize,
        "map__new" => Op::MapNew,
        "map__set" => Op::MapSet,
        "map__delete" => Op::MapDelete,
        "map__to_list" => Op::MapToList,
        _ => return None,
    })
}
