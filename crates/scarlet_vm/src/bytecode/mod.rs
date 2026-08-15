//! The compiled program: the instruction set, its 8-byte encoding, and the
//! [`Program`] container the VM executes. This is the whole contract between
//! a front-end compiler (Scarlet's lives in `scarlet_core`) and the VM.
//!
//! Three facts the rest of the crate leans on:
//!
//! 1. An [`Instruction`] is one aligned 8-byte word, so the dispatch loop's
//!    fetch is a single load via [`fetch`]. `a`/`b` reclaim padding bytes for
//!    superinstructions needing a second and third operand.
//! 2. [`Program::constants`] point into [`Program::frozen`], so they are
//!    stable raw pointers for the program's whole life, readable from every
//!    scheduler thread, and skipped by every per-process GC.
//! 3. `Program` is `Send + Sync` (asserted below), so a worker scheduler
//!    thread takes a plain `clone()` of the shared program.
//!
//! Adding an opcode touches seven places: [`Op::has_jump_target`],
//! [`Op::pushes_extra`], `native::op_coverage` and `crate::abi::slots_for`
//! (all exhaustive, so they fail to compile until you classify the new op),
//! emission in `scarlet_core`'s compiler, dispatch in [`crate::vm::exec`], and
//! `scarlet_core::bytecode::builtin_op` if it is exposed as a `@vm` intrinsic.
//!
//! `slots_for` states the ABI slots an op constructs, and `&[]` is a claim that
//! it constructs none — the compiler checks a program's bindings against it, so
//! an op whose slots are understated fails at runtime, when it first tries to
//! build a value, rather than at build time.

pub(crate) mod bits;
pub(crate) mod hamt;
pub mod native;
pub(crate) mod scratch;
pub mod seq;
pub mod value;
use std::sync::Arc;

pub use native::{
    NativeCtx, NativeEntry, NativeStatus, NativeTable, is_native_bridge_op, is_native_park_op,
    is_native_try_op,
};
pub use value::{
    Arena, BinaryRef, ClosureRef, EnumRef, HeapTag, MapRef, SeqRef, SocketKind, SocketValue,
    SubjectCloser, Value, ValueView, enum_name_prefix_hash, take_freed_objects,
};
pub(crate) use value::{MapBacking, freed_objects_pending, hash_value, values_equal};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Op {
    // Stack manipulation
    PushConst,
    PushLocal,
    PushGlobal,
    StoreLocal,
    PushNil,
    PushTrue,
    PushFalse,
    Pop,
    Dup,

    // Arithmetic
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Neg,

    // Typed arithmetic, emitted when the operand type resolves to a concrete
    // prim. The generic ops above are the polymorphic fallback.
    AddInt,
    SubInt,
    MulInt,
    DivInt,
    ModInt,
    NegInt,
    AddFloat,
    SubFloat,
    MulFloat,
    DivFloat,
    NegFloat,
    AddStr,

    // Comparison
    Eq,
    Neq,
    Lt,
    Gt,
    Lte,
    Gte,

    // Typed comparison
    LtInt,
    GtInt,
    LteInt,
    GteInt,
    EqInt,
    NeqInt,
    LtFloat,
    GtFloat,
    LteFloat,
    GteFloat,

    // Logic
    Not,

    // Control flow
    Jump,
    JumpIfFalse,
    Call,
    TailCall,
    /// Self-recursive call: `func_idx` comes from the live frame. operand = argc.
    CallSelf,
    TailCallSelf,
    /// Known-target call: the callee is a capture-free top-level fn whose
    /// `func_idx` is a compile-time immediate, so the callee value is never
    /// pushed and `Call`'s tag/arity checks are elided. b = argc,
    /// operand = func_idx.
    CallKnown,
    TailCallKnown,
    Ret,

    // Superinstructions fused by the peephole pass. Packed operands live in
    // `Instruction.{a,b}`; jump targets stay in `operand`.
    /// `stack[base+a] - constants[b]` → push. (PushLocal;PushConst;SubInt)
    SubIntLC,
    /// `stack[base+a] + constants[b]` → push. (PushLocal;PushConst;AddInt)
    AddIntLC,
    /// `if stack[base+a] >= constants[b] { ip = operand }`.
    /// (PushLocal;PushConst;LtInt;JumpIfFalse)
    JumpGeIntLC,
    /// `if stack[base+a] != constants[b] { ip = operand }`.
    /// (PushLocal;PushConst;EqInt;JumpIfFalse)
    JumpNeIntLC,
    /// Peephole padding so absolute jump targets stay valid after fusion.
    Nop,

    // Data structures
    MakeArray,
    /// `[e0, .., e_{n-1}] -> tuple`. `operand` = n. No reuse variant: `lower`
    /// pairs `Drop`/`Reuse` tokens only for user-declared constructors.
    MakeTuple,
    TupleIndex,
    MakeRange,
    Index,
    /// `[arr, idx, default] -> elem|default`. Skips the `Some` box `Index`
    /// must build and an immediately-following `or` then throws away. Only
    /// fused when the default is a pure atom, so eager evaluation is free;
    /// `or { <expression> }` is left alone.
    IndexOr,
    /// `[arr] -> arr[operand]` — unchecked fetch, no `Option` wrapper.
    /// Emitted by array-destructuring patterns only after a length check has
    /// proven the index in bounds.
    ElemAt,
    ArrayLen,
    ArraySlice,
    ArrayConcat,
    /// `[e0, .., e_{k-1}, ..seq]` — prepend k stack elements onto `seq`
    /// (`operand` = k). Sublinear front-cons.
    Prepend,
    /// `[seq, n] -> seq[n..]` — structure-shared tail. Replaces `ArraySlice`
    /// in `[h, ..rest]` patterns.
    SeqDrop,
    /// `[seq, e] -> seq` with `e` pushed on the back. No stdlib use today.
    Append,
    GetField,
    /// `[enum] -> payload[operand]` — as `GetField` but without the tag and
    /// bounds checks. Emitted when the scrutinee type is a resolved `Con`.
    GetFieldUnchecked,

    // Tagged values (enums / custom types)
    /// `[packed, enum_name, variant_name, labels, p0, .., p_{b-1}, reuse?] ->
    /// enum`. `packed` is `pack_variant(type_id, variant_idx)`. `b` = payload
    /// arity, `operand` = prehash constant idx. `a` = 1 when a Perceus reuse
    /// token sits on top of the payloads.
    MakeEnumPayload,
    /// `[enum, tag] -> bool` — `tag` is a [`value::pack_variant`] constant.
    /// Tests payload word 0, the key the native ladder compares, so the two
    /// engines cannot resolve one arm differently.
    MatchEnum,
    UnwrapEnum,
    /// `[enum] -> ` — computed jump by variant index. `a` = variant count,
    /// `operand` = base of a contiguous table of `a` `Jump` instructions, one
    /// per variant. Emitted for an exhaustive match on a resolved enum.
    SwitchTag,

    // Closures
    /// `[cap0, .., cap_{cc-1}, reuse?] -> closure`. `operand` = func_idx.
    /// `a` = 1 when a Perceus reuse token sits on top of the captures.
    MakeClosure,
    PushCapture,
    PushSelf,

    // Perceus drop-guided reuse (frame-limited, ICFP'22). `core_ir::perceus`
    // is authoritative.
    /// `[]` — operand = local slot. Last use of `stack[base+slot]`: release
    /// the frame's reference. If the value is uniquely owned (rc==1) the cell
    /// stays in the slot for a following same-shape `Reuse` instead of being
    /// freed; the slot is the per-frame reuse table. Pushes nothing.
    Drop,
    /// `[] -> cell|nil` — operand = local slot. Pushes the cell a preceding
    /// `Drop` parked there, or nil so the constructor allocates fresh.
    /// `MakeEnumPayload` is the only consumer.
    ///
    /// A token survives an intervening `Call`. "Frame-limited" means the
    /// callee never sees the parked cell, not that a call clears the token —
    /// clearing at calls would delete every reuse in
    /// `map xs f = match xs { Cons(h, t) -> Cons(f h, map t f) }`.
    Reuse,

    // String operations
    ToString,
    StrConcatN,
    StrSplit,
    StrLen,
    StrContains,
    StrTrim,
    IntToString,

    // Binary operations
    BinFromString,
    BinToString,
    BinBitSize,
    BinByteSize,
    BinSlice,
    BinAppend,
    /// `[b1, .., bn] -> Binary` — N-ary concatenation (operand = n). Emitted
    /// for multi-segment `<<>>` literals; a `BinAppend` chain would re-copy
    /// the accumulated prefix per segment. The binary mirror of `StrConcatN`.
    BinConcatN,
    BinFromInt,
    BinReadInt,
    BinTake,
    BinReadUtf8,
    /// `[bin, at_bits, prefix] -> Bool` — whether `bin`'s logical bits from
    /// `at_bits` begin with `prefix`'s. Out-of-range is `false`, never an
    /// error. Emitted by `<<>>` pattern codegen for literal segments.
    BinMatchPrefix,
    /// `[bin, at_bits, len_bits] -> Binary` — O(1) sub-view sharing the
    /// backing, no `Option` wrapper. Emitted by `<<>>` pattern codegen after
    /// its own bounds check; `BinSlice` is the checked public builtin.
    BinView,
    /// `[haystack, needle, from] -> Option(Int)` — byte-substring search.
    BinIndexOf,
    /// `[bin, i] -> Option(Int)` — byte at index `i`, or `None` when out of range.
    BinByteAt,
    /// `[bin, radix] -> Option(Int)` — ASCII integer parse (radix 10/16),
    /// overflow-checked (returns `None` rather than wrapping).
    BinParseInt,
    /// `[a, b] -> Bool` — ASCII-case-insensitive byte equality.
    BinEqIgnoreAsciiCase,
    /// `[bin] -> Binary` — ASCII-lowercased copy.
    BinToAsciiLower,
    /// `[n, radix] -> Binary` — render an Int as ASCII (radix 10/16).
    BinFromIntAscii,

    // HTTP/1.1 protocol ops (scarlet/http/h1, scarlet/http/headers). Byte scanning and
    // value assembly are native; every protocol decision (framing precedence,
    // keep-alive, 100-continue) stays in Scarlet.
    /// `[buf, off] -> Parsed` — parse one request head from `buf` at byte
    /// offset `off`. Pushes `Done(method, target, version, headers,
    /// consumed)` / `NeedMore` / `Bad(status)`, with method, target and header
    /// names/values as zero-copy views into `buf`'s backing.
    HttpParseHead,
    /// `[buf, off] -> ParsedResponse` — parse one response head from `buf` at
    /// byte offset `off`. Pushes `ResponseDone(version, code, reason, headers,
    /// flags, consumed)` / `ResponseNeedMore` / `ResponseBad(err)`, with
    /// `reason` and header names/values as zero-copy views into `buf`'s
    /// backing. Shares `parse_header_block` with [`Op::HttpParseHead`], so the
    /// field grammar and its smuggling rejects have one implementation.
    HttpParseResponseHead,
    /// `[headers] -> Framing` — RFC 7230 §3.3.3 body framing over an
    /// `Array(Header)`: `NoBody` / `Length(n)` / `Chunked` / `Invalid(status)`.
    HttpFraming,
    /// `[buf, off, max] -> ChunkBody` — decode a chunked body from `buf` at
    /// byte offset `off`, refusing to decode more than `max` bytes. Pushes
    /// `ChunkedDone(body, trailers, consumed)` / `ChunkedNeedMore` /
    /// `ChunkedBad(status)`; trailer names/values are zero-copy views.
    HttpChunkDecode,
    /// `[headers, name] -> Option(Binary)` — value of the first header whose
    /// name matches `name` ASCII-case-insensitively.
    HttpHeaderGet,
    /// `[headers, name] -> Bool` — whether any header name matches `name`
    /// ASCII-case-insensitively.
    HttpHeaderHas,
    HttpHeadersValid,
    /// `[code, reason, headers] -> Binary` — serialize a response head (status
    /// line, header block, terminating blank line) as one contiguous buffer.
    HttpSerializeHead,

    // Float operations
    FloatFloor,
    FloatCeil,
    FloatRound,
    FloatTruncate,
    FloatFromInt,
    FloatToString,

    // Misc
    Print,
    StackDepth,
    /// `[] -> Int` — mailboxes open program-wide right now. Introspection for
    /// pinning that subjects are reclaimed when their owners let go of them.
    /// (scarlet/internal.live_subjects)
    LiveSubjects,
    /// `[] -> Int` — blocking-pool worker threads alive right now, busy plus
    /// parked. Introspection for pinning that the pool grows on demand, and
    /// the only reading of its depth from inside a program. Reports `total`,
    /// not `idle`: a worker increments `idle` before parking and decrements it
    /// only once `cond.wait` has returned, so `idle` counts a notified worker
    /// as parked until it re-acquires the queue lock.
    /// (scarlet/internal.blocking_threads)
    BlockingThreads,
    Halt,

    // I/O operations
    FileRead,
    FileWrite,
    TcpListen,
    TcpAccept,
    TcpConnect,
    /// `[addr, deadline_ms] -> Result(Socket, NetError)` — parks until the
    /// connect completes or the absolute monotonic-ms deadline passes (then
    /// `Err(TimedOut)`, with the half-open socket dropped).
    TcpConnectUntil,
    TcpRead,
    /// `[sock, max, deadline_ms] -> Result(Binary, NetError)` — parks until
    /// data arrives, the peer closes, or the absolute monotonic-ms deadline
    /// passes (then `Err`).
    TcpReadUntil,
    TcpWrite,
    /// `[sock, Array(Binary)] -> Result(Nil, NetError)` in one writev syscall.
    TcpWriteParts,
    TcpClose,
    /// `[socket, pid] -> Nil` — make `pid` the connection's controlling
    /// process, so the connection closes when *it* ends. `net.serve` hands
    /// each accepted connection to the handler process it just spawned; a
    /// pid that has already ended, or that is not on this scheduler, closes
    /// the connection instead, so it can never be left with no live owner
    /// here. Not part of the public socket API. (scarlet/net's accept loop)
    TcpGive,
    TcpCloseServer,
    TcpLocalAddr,
    /// `[host] -> Result(IpAddress, NetError)`. IP literals return
    /// immediately; hostnames offload to the blocking pool so the syscall
    /// never stalls the scheduler. (scarlet/net.resolve)
    DnsResolve,
    /// `[host, deadline_ms] -> Result(IpAddress, NetError)` — as `DnsResolve`,
    /// but giving up at the absolute monotonic-ms deadline with
    /// `Err(TimedOut)`. The offloaded lookup is abandoned, not cancelled: it
    /// runs to completion on its pool thread and its result is discarded.
    /// (scarlet/net.resolve_within)
    DnsResolveUntil,
    /// `[String] -> Option(IpAddress)` — the only constructor for
    /// `IpAddress`. (scarlet/net/address.parse)
    IpParse,
    /// `[program, args, env] -> Result(Port, IoError)` — start a child
    /// process with piped stdio, parking on the blocking pool while it is
    /// spawned. Its stdio is then a connection: the `Tcp*` stream ops serve
    /// `port.read`/`write` too. (scarlet/os/port.spawn)
    PortSpawn,
    /// `[port] -> Result(ExitStatus, NetError)` — close the child's pipes and
    /// park until it has been collected. (scarlet/os/port.close)
    PortClose,

    /// `[socket, server_name] -> Result(TlsSocket, TlsError)` — take a
    /// connected cleartext socket over, verify the peer against `server_name`
    /// and complete the handshake, parking while it is in flight. The
    /// connection is re-keyed under a new id, so the `Socket` handed in is
    /// stale afterwards. (scarlet/net/tls.handshake)
    TlsHandshake,
    /// `[socket, server_name, deadline_ms] -> Result(TlsSocket, TlsError)` — as
    /// `TlsHandshake`, but gives up with `Err(Transport(TimedOut))` once the
    /// absolute monotonic-ms deadline passes. A peer that accepts the TCP
    /// connection and then never answers the ClientHello is otherwise a park
    /// with no wake. (scarlet/net/tls.handshake_until)
    TlsHandshakeUntil,
    /// `[tls_socket, max] -> Result(Read, TlsError)` — decrypting read. Split
    /// from `TcpRead` because its failures are `TlsError` values, not
    /// `NetError` ones. (scarlet/net/tls.read)
    TlsRead,
    /// `[tls_socket, max, deadline_ms] -> Result(Read, TlsError)` — parks until
    /// plaintext decrypts, the peer closes, or the absolute monotonic-ms
    /// deadline passes (then `Err(Transport(TimedOut))`). Split from
    /// `TcpReadUntil` for the same reason `TlsRead` is split from `TcpRead`.
    /// (scarlet/net/tls.read_until)
    TlsReadUntil,
    /// `[tls_socket, data] -> Result(Nil, TlsError)` — encrypting write, which
    /// returns only once the ciphertext has reached the kernel rather than the
    /// session's own buffer. (scarlet/net/tls.write)
    TlsWrite,
    /// `[tls_socket] -> Result(Nil, TlsError)` — send `close_notify`, then
    /// close. (scarlet/net/tls.close)
    TlsClose,

    // Concurrency (scarlet/process)
    /// `[closure] -> Pid` — spawn a lightweight process running the closure,
    /// linked to the spawner, and push the child's pid. (scarlet/process.spawn)
    ProcessSpawn,
    /// As `ProcessSpawn`, with no link. (scarlet/process.spawn_unlinked)
    ProcessSpawnUnlinked,
    /// `[pid] -> Nil` — ask for a process to be ended. (scarlet/process.kill)
    ProcessKill,
    /// Push the running process's own `Pid`. (scarlet/process.self)
    ProcessSelf,
    /// `[pid, notice fn(Down) Nil] -> Monitor` — copy the closure and park it
    /// on the process; when that process ends it is started as a process of
    /// its own with the `Down`. A pid that has already ended starts it at
    /// once. (scarlet/process.monitor)
    ProcessMonitor,
    /// `[Monitor] -> Nil` — cancel a monitor. (scarlet/process.demonitor)
    ProcessDemonitor,

    // Supervision (`crate::vm::supervision`). Handles are entry ids as Ints;
    // the stdlib wraps them in its own opaque types, and policies and
    // strategies cross as small integer codes, so the VM constructs none of
    // `scarlet/process`'s supervision types except through `SupervisedInfo`'s
    // raw tuple.
    /// `[strategy_code, restarts, within_ms, parent] -> Int` — a supervisor,
    /// nested under `parent` (an Int) or owned by the calling process (any
    /// non-Int). (scarlet/process.supervisor)
    SupervisorNew,
    /// `[supervisor, policy_code, stopper, start fn(Subject) Nil] -> Subject`
    /// — declare a worker slot and start its first incarnation; `stopper` is
    /// a `fn(Subject, Pid) Nil` or a non-closure for plain kill.
    /// (scarlet/process.worker)
    SupervisorWorker,
    /// `[supervisor, restarts, within_ms, template fn(Subject, key) Nil] ->
    /// Int` — a factory; `restarts < 0` for disposable members.
    /// (scarlet/process.factory)
    FactoryNew,
    /// `[factory, key] -> Subject` — the member for `key`, started if new.
    /// (scarlet/process.lookup_or_start)
    FactoryLookupOrStart,
    /// `[factory, key] -> Option(Subject)`. (scarlet/process.lookup)
    FactoryLookup,
    /// `[subject] -> Int` — the tree id behind an address.
    /// (scarlet/process.supervised)
    SupervisedOf,
    /// `[id] -> Int`. (scarlet/process.parent)
    SupervisedParent,
    /// `[id] -> Array(Int)`. (scarlet/process.children)
    SupervisedChildren,
    /// `[id] -> Int`. (scarlet/process.count)
    SupervisedCount,
    /// `[id] -> (Int, Int, Int, Int, Int, Int, Option(Pid))`.
    /// (scarlet/process.info)
    SupervisedInfo,
    /// `[entry, notice fn(description) Nil] -> Int` — be told each time the
    /// occupant of a tree entry exits, and when the entry goes; survives
    /// restarts. Nothing there: the notice starts at once. (scarlet/process.watch)
    WatchNew,
    /// `[entry, watch_id] -> Nil`. (scarlet/process.unwatch)
    WatchCancel,
    /// `[supervisor, policy_code, start] -> Nil` — declare one worker per
    /// scheduler, each pinned to its scheduler for every incarnation.
    /// `net.serve`'s acceptors: with per-scheduler fd tables, an acceptor per
    /// scheduler keeps each accepted connection on the scheduler that will
    /// serve it, and a restarted acceptor must come back on the same one.
    /// Not part of the public process API. (scarlet/net)
    SupervisorWorkerOnEach,
    /// `[factory, arg] -> Subject` — an unkeyed member: `template(inbox,
    /// arg)` in a new process, findable only through `children`. What a
    /// server's connections are. (scarlet/process.start_in)
    FactorySpawn,
    /// Park the current process for `ms` milliseconds.
    Sleep,
    /// Push a fresh `Subject` owned by the current process.
    /// (scarlet/process.subject)
    SubjectNew,
    /// `[subject, msg] -> Nil` — deep-copy `msg` into the subject's mailbox
    /// and wake a parked receiver. Never blocks; a dead subject drops the
    /// message. (scarlet/process.send)
    SubjectSend,
    /// As `SubjectSend`, but the message goes to the front of the queue: what
    /// a supervisor's `Ask` shutdown sends, so a stop request is not stuck
    /// behind a backlog for its whole grace period — OTP's shutdown is a
    /// signal for the same reason. Not part of the public API. (scarlet/process)
    SubjectSendUrgent,
    /// `[subject] -> msg` — pop the mailbox's oldest message, parking until
    /// one arrives. Only the owning process may receive.
    /// (scarlet/process.receive)
    SubjectReceive,
    /// `[subject, deadline_ms] -> Result(msg, Nil)` — as `SubjectReceive`,
    /// but `Err(Nil)` once the absolute monotonic-ms deadline passes.
    /// (scarlet/process.receive_until)
    SubjectReceiveUntil,
    /// Push milliseconds elapsed since a process-global monotonic epoch (Int).
    Monotonic,
    /// Push milliseconds since the Unix epoch on the system's wall clock
    /// (Int), negative before 1970. A separate opcode from `Monotonic`
    /// because it is a different clock and not a rebased one: it is settable,
    /// so it can step in either direction, and no deadline is computed from
    /// it. (scarlet/time.epoch_ms)
    WallClock,
    /// `[n Int] -> Result(Binary, Nil)` — `n` bytes from the OS CSPRNG.
    /// `Err(Nil)` if `n` is negative or the OS source fails. Never a
    /// userspace PRNG, and never silent stand-in bytes.
    /// (scarlet/crypto.random_bytes)
    RandomBytes,

    /// Push an `Array(String)` of the entrypoint path followed by every
    /// argument after it on the command line. (scarlet/os.argv)
    Argv,

    // Maps (scarlet/map). A `Map(k, v)` is an opaque heap value with a pluggable
    // backing; read ops dispatch on the backing.
    /// Push a `Map(String, String)` reading through to the process
    /// environment, copying nothing. (scarlet/os.env)
    EnvMap,
    /// `[map, key] -> Option(v)` — look up a key. (scarlet/map.get)
    MapGet,
    /// `[map, key] -> Bool` — membership test. (scarlet/map.has)
    MapHas,
    /// `[map] -> Array(k)` — every key, in the backing's iteration order.
    /// (scarlet/map.keys)
    MapKeys,
    /// `[map] -> Array(v)` — every value, parallel to `MapKeys`. (scarlet/map.values)
    MapValues,
    /// `[map] -> Int` — number of entries. (scarlet/map.size)
    MapSize,
    /// `[] -> Map(k, v)` — a fresh empty in-memory (HAMT) map. (scarlet/map.new)
    MapNew,
    /// `[map, key, value] -> Map(k, v)` — `map` with `key` bound to `value`,
    /// as a new map sharing untouched subtrees. (scarlet/map.set)
    MapSet,
    /// `[map, key] -> Map(k, v)` — `map` without `key`. (scarlet/map.delete)
    MapDelete,
    /// `[map] -> Array((k, v))` — every entry as a `(key, value)` tuple.
    /// (scarlet/map.to_list)
    MapToList,

    // Integer bitwise ops. `Int` is exactly `i64`, so these are the i64
    // two's-complement operations and there is no width to choose. Like
    // `+ - * / %` they are TOTAL: no input traps, and the shifts in
    // particular define every count rather than masking it — see
    // `shift_left_i64` in `vm::exec` for the count rules.
    /// `[a, b] -> Int` — bitwise AND. (scarlet/int.bitwise_and)
    BitAnd,
    /// `[a, b] -> Int` — bitwise OR. (scarlet/int.bitwise_or)
    BitOr,
    /// `[a, b] -> Int` — bitwise XOR. (scarlet/int.bitwise_xor)
    BitXor,
    /// `[a] -> Int` — two's-complement complement, equal to `-a - 1`.
    /// (scarlet/int.bitwise_not)
    BitNot,
    /// `[x, n] -> Int` — shift left, discarding bits shifted off the top.
    /// (scarlet/int.bitwise_shift_left)
    BitShl,
    /// `[x, n] -> Int` — *arithmetic* shift right: the sign bit propagates,
    /// so a negative `x` stays negative. (scarlet/int.bitwise_shift_right)
    BitShr,
    /// `[src Binary] -> Result(Doc, ParseError)` — SIMD parse to a compact
    /// tape. (scarlet/json.parse_binary)
    JsonParse,
    /// `[d Doc] -> Int` — the `Kind` ordinal, -1 for an undecodable tape.
    JsonKind,
    /// `[d Doc] -> Int` — array/object element count, -1 for a scalar.
    JsonLen,
    /// `[d Doc, name String] -> Option(Doc)` — the first member so named.
    JsonField,
    /// `[d Doc, i Int] -> Option(Doc)` — the `i`th array element.
    JsonIndex,
    /// `[d Doc] -> Array((String, Doc))` — an object's members in order.
    JsonEntries,
    /// `[d Doc] -> Array(Doc)` — an array's elements in order, in one walk.
    /// `JsonIndex` per element is O(n²) and the length is the sender's to
    /// choose.
    JsonElements,
    /// `[d Doc] -> Option(String)`
    JsonString,
    /// `[d Doc] -> Option(Int)` — `None` for a float or an out-of-range
    /// integer, never a truncation.
    JsonInt,
    /// `[d Doc] -> Option(String)` — the integer at `d` in decimal, including
    /// the ones `JsonInt` refuses because they do not fit an `Int`.
    JsonIntText,
    /// `[d Doc] -> Option(Float)`
    JsonFloat,
    /// `[d Doc] -> Option(Bool)`
    JsonBool,
    /// `[j Json] -> String` — encode the constructible tree.
    JsonEncode,

    /// `[value] -> Binary` — the value's bytes under the descriptor of the
    /// type the call site was inferred at. (scarlet/wire.encode)
    ///
    /// Declared ahead of its body: reachable, and traps until the encoder and
    /// its descriptor operand land together.
    WireEncode,
    /// `[bytes Binary] -> Result(a, DecodeError)` — the value those bytes
    /// hold, checked against the same descriptor. (scarlet/wire.decode)
    ///
    /// Declared ahead of its body, as [`Op::WireEncode`].
    WireDecode,

    /// Not an opcode: one past the last real variant, so [`Op::from_u8`] can
    /// bound its check without a hand-maintained count. Never emitted, never
    /// executed; every consumer of real ops rejects it.
    #[doc(hidden)]
    Count,
}

impl Op {
    /// The opcode with discriminant `b`, or `None` for a byte no variant
    /// carries. The bound comes from the enum itself ([`Op::Count`]), so it
    /// cannot drift when variants are added.
    pub fn from_u8(b: u8) -> Option<Op> {
        if b >= Op::Count as u8 {
            return None;
        }
        // SAFETY: `Op` is `repr(u8)` with default discriminants `0..Count`,
        // and `b < Count` was just checked.
        #[allow(unsafe_code)]
        Some(unsafe { std::mem::transmute::<u8, Op>(b) })
    }
}

impl Op {
    /// True when this op's `operand` is an instruction index rather than a
    /// constant id, slot, count, or function index. Jump patching, peephole
    /// fusion and `core_ir::emit::relocate` all key off this, so it is the
    /// single authority on which operands are addresses. The match is
    /// exhaustive so a new opcode cannot default to "not an address" and
    /// silently survive relocation unshifted.
    pub const fn has_jump_target(self) -> bool {
        match self {
            // Not an opcode ([`Op::Count`]); no program contains it.
            Op::Count => false,
            // `SwitchTag`'s operand is the jump-table base; the table's own
            // entries are ordinary `Jump`s.
            Op::Jump | Op::JumpIfFalse | Op::JumpGeIntLC | Op::JumpNeIntLC | Op::SwitchTag => true,

            Op::PushConst
            | Op::PushLocal
            | Op::PushGlobal
            | Op::StoreLocal
            | Op::PushNil
            | Op::PushTrue
            | Op::PushFalse
            | Op::Pop
            | Op::Dup
            | Op::Add
            | Op::Sub
            | Op::Mul
            | Op::Div
            | Op::Mod
            | Op::Neg
            | Op::AddInt
            | Op::SubInt
            | Op::MulInt
            | Op::DivInt
            | Op::ModInt
            | Op::NegInt
            | Op::AddFloat
            | Op::SubFloat
            | Op::MulFloat
            | Op::DivFloat
            | Op::NegFloat
            | Op::AddStr
            | Op::Eq
            | Op::Neq
            | Op::Lt
            | Op::Gt
            | Op::Lte
            | Op::Gte
            | Op::LtInt
            | Op::GtInt
            | Op::LteInt
            | Op::GteInt
            | Op::EqInt
            | Op::NeqInt
            | Op::LtFloat
            | Op::GtFloat
            | Op::LteFloat
            | Op::GteFloat
            | Op::Not
            | Op::Call
            | Op::TailCall
            | Op::CallSelf
            | Op::TailCallSelf
            | Op::CallKnown
            | Op::TailCallKnown
            | Op::Ret
            | Op::SubIntLC
            | Op::AddIntLC
            | Op::Nop
            | Op::MakeArray
            | Op::MakeTuple
            | Op::TupleIndex
            | Op::MakeRange
            | Op::Index
            | Op::IndexOr
            | Op::ElemAt
            | Op::ArrayLen
            | Op::ArraySlice
            | Op::ArrayConcat
            | Op::Prepend
            | Op::SeqDrop
            | Op::Append
            | Op::GetField
            | Op::GetFieldUnchecked
            | Op::MakeEnumPayload
            | Op::MatchEnum
            | Op::UnwrapEnum
            | Op::MakeClosure
            | Op::PushCapture
            | Op::PushSelf
            | Op::Drop
            | Op::Reuse
            | Op::ToString
            | Op::StrConcatN
            | Op::StrSplit
            | Op::StrLen
            | Op::StrContains
            | Op::StrTrim
            | Op::IntToString
            | Op::BinFromString
            | Op::BinToString
            | Op::BinBitSize
            | Op::BinByteSize
            | Op::BinSlice
            | Op::BinAppend
            | Op::BinConcatN
            | Op::BinFromInt
            | Op::BinReadInt
            | Op::BinTake
            | Op::BinReadUtf8
            | Op::BinMatchPrefix
            | Op::BinView
            | Op::BinIndexOf
            | Op::BinByteAt
            | Op::BinParseInt
            | Op::BinEqIgnoreAsciiCase
            | Op::BinToAsciiLower
            | Op::BinFromIntAscii
            | Op::HttpParseHead
            | Op::HttpParseResponseHead
            | Op::HttpFraming
            | Op::HttpChunkDecode
            | Op::HttpHeaderGet
            | Op::HttpHeaderHas
            | Op::HttpHeadersValid
            | Op::HttpSerializeHead
            | Op::FloatFloor
            | Op::FloatCeil
            | Op::FloatRound
            | Op::FloatTruncate
            | Op::FloatFromInt
            | Op::FloatToString
            | Op::Print
            | Op::StackDepth
            | Op::LiveSubjects
            | Op::BlockingThreads
            | Op::Halt
            | Op::FileRead
            | Op::FileWrite
            | Op::TcpListen
            | Op::TcpAccept
            | Op::TcpConnect
            | Op::TcpConnectUntil
            | Op::TcpRead
            | Op::TcpReadUntil
            | Op::TcpWrite
            | Op::TcpWriteParts
            | Op::TcpClose
            | Op::TcpGive
            | Op::TcpCloseServer
            | Op::TcpLocalAddr
            | Op::DnsResolve
            | Op::DnsResolveUntil
            | Op::IpParse
            | Op::PortSpawn
            | Op::PortClose
            | Op::TlsHandshake
            | Op::TlsHandshakeUntil
            | Op::TlsRead
            | Op::TlsReadUntil
            | Op::TlsWrite
            | Op::TlsClose
            | Op::ProcessSpawn
            | Op::ProcessSpawnUnlinked
            | Op::ProcessKill
            | Op::ProcessSelf
            | Op::ProcessMonitor
            | Op::ProcessDemonitor
            | Op::SupervisorNew
            | Op::SupervisorWorker
            | Op::FactoryNew
            | Op::FactoryLookupOrStart
            | Op::FactoryLookup
            | Op::SupervisedOf
            | Op::SupervisedParent
            | Op::SupervisedChildren
            | Op::SupervisedCount
            | Op::SupervisedInfo
            | Op::WatchNew
            | Op::WatchCancel
            | Op::SupervisorWorkerOnEach
            | Op::FactorySpawn
            | Op::Sleep
            | Op::SubjectNew
            | Op::SubjectSend
            | Op::SubjectSendUrgent
            | Op::SubjectReceive
            | Op::SubjectReceiveUntil
            | Op::Monotonic
            | Op::WallClock
            | Op::RandomBytes
            | Op::Argv
            | Op::EnvMap
            | Op::MapGet
            | Op::MapHas
            | Op::MapKeys
            | Op::MapValues
            | Op::MapSize
            | Op::MapNew
            | Op::MapSet
            | Op::MapDelete
            | Op::MapToList
            | Op::BitAnd
            | Op::BitOr
            | Op::BitXor
            | Op::BitNot
            | Op::BitShl
            | Op::BitShr
            | Op::JsonParse
            | Op::JsonKind
            | Op::JsonLen
            | Op::JsonField
            | Op::JsonIndex
            | Op::JsonEntries
            | Op::JsonElements
            | Op::JsonString
            | Op::JsonInt
            | Op::JsonIntText
            | Op::JsonFloat
            | Op::JsonBool
            | Op::JsonEncode
            | Op::WireEncode
            | Op::WireDecode => false,
        }
    }

    /// True when this op does not leave exactly one value on the stack:
    /// `Print` leaves none, `BinReadUtf8` leaves two. `core_ir::emit`'s
    /// operand hoisting and if-condition fusion treat a primop as a
    /// single-value expression, so they key off this. The match is exhaustive
    /// so a new opcode cannot default to "one value" and silently miscompile
    /// around hoisting and fusion.
    pub const fn pushes_extra(self) -> bool {
        match self {
            // Not an opcode ([`Op::Count`]); no program contains it.
            Op::Count => false,
            Op::Print | Op::BinReadUtf8 => true,

            Op::PushConst
            | Op::PushLocal
            | Op::PushGlobal
            | Op::StoreLocal
            | Op::PushNil
            | Op::PushTrue
            | Op::PushFalse
            | Op::Pop
            | Op::Dup
            | Op::Add
            | Op::Sub
            | Op::Mul
            | Op::Div
            | Op::Mod
            | Op::Neg
            | Op::AddInt
            | Op::SubInt
            | Op::MulInt
            | Op::DivInt
            | Op::ModInt
            | Op::NegInt
            | Op::AddFloat
            | Op::SubFloat
            | Op::MulFloat
            | Op::DivFloat
            | Op::NegFloat
            | Op::AddStr
            | Op::Eq
            | Op::Neq
            | Op::Lt
            | Op::Gt
            | Op::Lte
            | Op::Gte
            | Op::LtInt
            | Op::GtInt
            | Op::LteInt
            | Op::GteInt
            | Op::EqInt
            | Op::NeqInt
            | Op::LtFloat
            | Op::GtFloat
            | Op::LteFloat
            | Op::GteFloat
            | Op::Not
            | Op::Jump
            | Op::JumpIfFalse
            | Op::Call
            | Op::TailCall
            | Op::CallSelf
            | Op::TailCallSelf
            | Op::CallKnown
            | Op::TailCallKnown
            | Op::Ret
            | Op::SubIntLC
            | Op::AddIntLC
            | Op::JumpGeIntLC
            | Op::JumpNeIntLC
            | Op::Nop
            | Op::MakeArray
            | Op::MakeTuple
            | Op::TupleIndex
            | Op::MakeRange
            | Op::Index
            | Op::IndexOr
            | Op::ElemAt
            | Op::ArrayLen
            | Op::ArraySlice
            | Op::ArrayConcat
            | Op::Prepend
            | Op::SeqDrop
            | Op::Append
            | Op::GetField
            | Op::GetFieldUnchecked
            | Op::MakeEnumPayload
            | Op::MatchEnum
            | Op::UnwrapEnum
            | Op::SwitchTag
            | Op::MakeClosure
            | Op::PushCapture
            | Op::PushSelf
            | Op::Drop
            | Op::Reuse
            | Op::ToString
            | Op::StrConcatN
            | Op::StrSplit
            | Op::StrLen
            | Op::StrContains
            | Op::StrTrim
            | Op::IntToString
            | Op::BinFromString
            | Op::BinToString
            | Op::BinBitSize
            | Op::BinByteSize
            | Op::BinSlice
            | Op::BinAppend
            | Op::BinConcatN
            | Op::BinFromInt
            | Op::BinReadInt
            | Op::BinTake
            | Op::BinMatchPrefix
            | Op::BinView
            | Op::BinIndexOf
            | Op::BinByteAt
            | Op::BinParseInt
            | Op::BinEqIgnoreAsciiCase
            | Op::BinToAsciiLower
            | Op::BinFromIntAscii
            | Op::HttpParseHead
            | Op::HttpParseResponseHead
            | Op::HttpFraming
            | Op::HttpChunkDecode
            | Op::HttpHeaderGet
            | Op::HttpHeaderHas
            | Op::HttpHeadersValid
            | Op::HttpSerializeHead
            | Op::FloatFloor
            | Op::FloatCeil
            | Op::FloatRound
            | Op::FloatTruncate
            | Op::FloatFromInt
            | Op::FloatToString
            | Op::StackDepth
            | Op::LiveSubjects
            | Op::BlockingThreads
            | Op::Halt
            | Op::FileRead
            | Op::FileWrite
            | Op::TcpListen
            | Op::TcpAccept
            | Op::TcpConnect
            | Op::TcpConnectUntil
            | Op::TcpRead
            | Op::TcpReadUntil
            | Op::TcpWrite
            | Op::TcpWriteParts
            | Op::TcpClose
            | Op::TcpGive
            | Op::TcpCloseServer
            | Op::TcpLocalAddr
            | Op::DnsResolve
            | Op::DnsResolveUntil
            | Op::IpParse
            | Op::PortSpawn
            | Op::PortClose
            | Op::TlsHandshake
            | Op::TlsHandshakeUntil
            | Op::TlsRead
            | Op::TlsReadUntil
            | Op::TlsWrite
            | Op::TlsClose
            | Op::ProcessSpawn
            | Op::ProcessSpawnUnlinked
            | Op::ProcessKill
            | Op::ProcessSelf
            | Op::ProcessMonitor
            | Op::ProcessDemonitor
            | Op::SupervisorNew
            | Op::SupervisorWorker
            | Op::FactoryNew
            | Op::FactoryLookupOrStart
            | Op::FactoryLookup
            | Op::SupervisedOf
            | Op::SupervisedParent
            | Op::SupervisedChildren
            | Op::SupervisedCount
            | Op::SupervisedInfo
            | Op::WatchNew
            | Op::WatchCancel
            | Op::SupervisorWorkerOnEach
            | Op::FactorySpawn
            | Op::Sleep
            | Op::SubjectNew
            | Op::SubjectSend
            | Op::SubjectSendUrgent
            | Op::SubjectReceive
            | Op::SubjectReceiveUntil
            | Op::Monotonic
            | Op::WallClock
            | Op::RandomBytes
            | Op::Argv
            | Op::EnvMap
            | Op::MapGet
            | Op::MapHas
            | Op::MapKeys
            | Op::MapValues
            | Op::MapSize
            | Op::MapNew
            | Op::MapSet
            | Op::MapDelete
            | Op::MapToList
            | Op::BitAnd
            | Op::BitOr
            | Op::BitXor
            | Op::BitNot
            | Op::BitShl
            | Op::BitShr
            | Op::JsonParse
            | Op::JsonKind
            | Op::JsonLen
            | Op::JsonField
            | Op::JsonIndex
            | Op::JsonEntries
            | Op::JsonElements
            | Op::JsonString
            | Op::JsonInt
            | Op::JsonIntText
            | Op::JsonFloat
            | Op::JsonBool
            | Op::JsonEncode
            | Op::WireEncode
            | Op::WireDecode => false,
        }
    }
}
/// A single bytecode instruction: 1B op + 1B a + 2B b + 4B operand = 8B.
/// `a`/`b` are packed sub-operands reclaiming padding; single-operand ops
/// leave them zero.
///
/// `repr(C)` pins the field order so the u64 round-trip in [`fetch`] is
/// sound. The dispatch loop must fetch through that path: across a crate
/// boundary LLVM's load-combine misses the struct read, costing ~30% on
/// `bench_heavy.scrl`.
#[derive(Debug, Clone, Copy)]
#[repr(C, align(8))]
pub struct Instruction {
    pub op: Op,
    pub a: u8,
    pub b: u16,
    pub operand: i32,
}

const _: () = assert!(std::mem::size_of::<Instruction>() == 8);
const _: () = assert!(std::mem::align_of::<Instruction>() == 8);

/// Fetch one instruction with a single 8-byte load. See the `Instruction` doc
/// for why the dispatch loop must go through this rather than `code[i]`.
///
/// Returns `None` when `i` is out of bounds.
// Safe alternatives were measured and rejected on bench_heavy.scrl:
// `code.get(i).copied()` +19%, a `repr(transparent)` u64 newtype with shift
// accessors +8-11% (+18% fully safe). LLVM schedules the dispatch loop worse
// against shift extraction than against SROA'd struct fields.
#[allow(unsafe_code)]
#[inline(always)]
pub(crate) fn fetch(code: &[Instruction], i: usize) -> Option<Instruction> {
    if i >= code.len() {
        return None;
    }
    // SAFETY: `i < code.len()` is checked above. `repr(C, align(8))` plus the
    // size/align asserts pin `Instruction` to a fully-initialized 8-byte POD,
    // so reading it as u64 and transmuting back recovers the same value; the
    // `Op` byte is valid because it came from `code`. Going through u64
    // forces one load where SROA would emit four field loads.
    unsafe {
        let raw = *code.as_ptr().cast::<u64>().add(i);
        Some(std::mem::transmute::<u64, Instruction>(raw))
    }
}

#[derive(Debug, Clone)]
pub struct Function {
    pub name: Arc<str>,
    pub arity: i32,
    pub locals: i32,
    pub capture_count: i32,
    pub code_start: i32,
    /// The body's whole extent, terminator included:
    /// `[code_start, code_start + code_len)` ends with the `Ret` that closes
    /// the frame, or the `Halt` that closes the entry frame. A `Function`
    /// nothing has been emitted for is the only one with a zero here.
    ///
    /// Jump operands are frame-relative, so a legal target is `0..code_len`,
    /// and `code_len - 1` — the terminator — is where `emit` aims the merge of
    /// an `if` whose arms both return.
    pub code_len: i32,
}

#[derive(Debug, Clone, Default)]
pub struct Program {
    pub constants: Vec<Value>,
    pub functions: Vec<Function>,
    pub code: Vec<Instruction>,
    pub entry: i32,
    /// The frozen area `constants` point into. `Arc`-held so it outlives
    /// every scheduler's clone of the program.
    pub frozen: Arc<crate::frozen::FrozenArea>,
    /// Compiled-function entry points, one slot per `functions` entry under
    /// the same `FuncIdx` numbering. An empty table means interpret
    /// everything. See [`native`].
    pub native: NativeTable,
    /// Constructors the VM may instantiate, interned into `frozen` by the
    /// front end. Indexed by the `abi` table below, and past that fixed
    /// prefix by `wire_templates`.
    pub templates: crate::tivec::TiVec<crate::abi::TemplateIdx, crate::template::EnumTemplate>,
    /// Which template answers each [`AbiSlot`](crate::abi::AbiSlot) — the
    /// runtime's only knowledge of a front end's stdlib.
    pub abi: crate::template::AbiTable,
    /// Which template answers a `wire` constructor, keyed by the identity a
    /// descriptor's `WireVariant` carries — `(type_id, variant_idx)`, never a
    /// name: renaming a type, or two programs declaring the same shape under
    /// different names, must still resolve to the same template. Unlike
    /// `abi`, this is not a fixed slot enum — an unbounded set of user types
    /// can cross the wire — so it is a map rather than an array. Minted past
    /// `templates`'s ABI prefix, and exactly as session-scoped: a rewind
    /// clears this the same call that truncates `templates`
    /// (`IncrementalSession::reset_to`).
    pub wire_templates: std::collections::HashMap<(crate::TypeId, u16), crate::abi::TemplateIdx>,
}

impl Program {
    /// The pre-built value bound to a nullary ABI slot: an immortal word the
    /// native backend may bake into an instruction, exactly as the
    /// interpreter pushes it. `None` when the slot is unbound or bound to a
    /// constructor with fields.
    pub fn abi_nullary(&self, slot: crate::abi::AbiSlot) -> Option<&Value> {
        self.templates.get(self.abi.get(slot)?)?.nullary()
    }
}

// Worker scheduler threads clone the shared program, so it must stay
// thread-shareable.
const _: () = crate::assert_send_sync::<Program>();

pub fn op(o: Op) -> Instruction {
    Instruction {
        op: o,
        a: 0,
        b: 0,
        operand: 0,
    }
}

pub fn op_arg(o: Op, operand: i32) -> Instruction {
    Instruction {
        op: o,
        a: 0,
        b: 0,
        operand,
    }
}

pub fn op_ab(o: Op, a: u8, b: u16, operand: i32) -> Instruction {
    Instruction {
        op: o,
        a,
        b,
        operand,
    }
}
