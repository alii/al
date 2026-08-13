//! The value ABI: outcomes the VM constructs on its own, plus the errno
//! classification that picks between them.
//!
//! A slot names an outcome, not a constructor. The front end binds one template
//! per slot ([`Program::abi`](crate::bytecode::Program)) and the VM instantiates
//! `abi[slot]`.
//!
//! Payload order is normative: the VM reads and writes payload fields by
//! position, so the order noted on each slot is binding. Field names are free.

use crate::bytecode::Op;
use crate::newtype_index;

newtype_index!(
    /// Index into [`Program::templates`](crate::bytecode::Program::templates).
    pub struct TemplateIdx("tpl#")
);

/// One outcome the VM may construct. Discriminants must stay dense from zero:
/// the slot table is `[Option<TemplateIdx>; COUNT]` indexed by discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum AbiSlot {
    /// `[value]`
    ResultOk,
    /// `[error]`
    ResultErr,
    /// `[value]`
    OptionSome,
    OptionNone,
    Unit,

    /// `ENOENT` — `[path Str]`
    FsEnoent,
    /// `EACCES` — `[path Str]`
    FsEacces,
    /// `EEXIST` — `[path Str]`
    FsEexist,
    /// `ENOTDIR` — `[path Str]`
    FsEnotdir,
    /// `EISDIR` — `[path Str]`
    FsEisdir,
    /// `EROFS` — `[path Str]`
    FsErofs,
    /// `ELOOP` — `[path Str]`
    FsEloop,
    /// `EFBIG` — `[path Str]`
    FsEfbig,
    /// `ENOSPC`
    FsEnospc,
    /// `EDQUOT`
    FsEdquot,
    /// A write of a binary that is not a whole number of bytes. Not an errno.
    FsUnalignedBinary,
    /// Any errno with no class above — `[code Int]`
    FsErrnoOther,

    /// `ETIMEDOUT`. Also `TcpReadUntil` passing its deadline.
    NetEtimedout,
    /// `ECONNREFUSED`
    NetEconnrefused,
    /// `ECONNRESET`
    NetEconnreset,
    /// `ECONNABORTED`. Also the poller on a lost connection.
    NetEconnaborted,
    /// `ENOTCONN`
    NetEnotconn,
    /// `EPIPE`
    NetEpipe,
    /// `EADDRINUSE`
    NetEaddrinuse,
    /// `EADDRNOTAVAIL`
    NetEaddrnotavail,
    /// `ENETDOWN`
    NetEnetdown,
    /// `ENETUNREACH`
    NetEnetunreach,
    /// `EHOSTUNREACH`
    NetEhostunreach,
    /// `EACCES`
    NetEacces,
    /// A port outside 1..=65535. VM precondition.
    NetInvalidPort,
    /// VM precondition, as [`AbiSlot::FsUnalignedBinary`].
    NetUnalignedBinary,
    /// Any errno with no class above — `[code Int]`
    NetErrnoOther,

    /// `[addr Str]`
    IpV4,
    /// `[addr Str]`
    IpV6,
    /// `[ip, port Int]`
    SocketAddr,
    /// `[conn, peer]`
    Socket,
    /// `[bytes Binary]`
    ReadData,
    ReadClosed,

    /// A monitor registration — `[target Pid, id Int]`
    Monitor,
    /// A death notice — `[pid Pid, reason]`
    Down,
    /// The exit reason of a process that returned.
    ExitNormal,
    /// The exit reason reported by a monitor placed on a process that had
    /// already ended: how it ended is no longer known.
    ExitNoProcess,
    /// The process was killed — explicitly, or through a link.
    ExitKilled,
    /// The process's own code failed — `[crash]`
    ExitCrashed,
    /// `[index Int, length Int]`
    CrashIndexOutOfBounds,
    /// `[from Int, to Int, length Int]`
    CrashSliceOutOfBounds,
    CrashForeignReceive,
    /// `[op Str, expected Str, got Str]`
    CrashTypeMismatch,
    /// `[why Str]`
    CrashSupervision,

    /// A port record — `[conn, os_pid Int]`
    Port,
    /// A closed port's child exited — `[code Int]`
    PortExited,
    /// A closed port's child was ended by a signal — `[signal Int]`
    PortSignaled,

    /// `[name Binary, value Binary]`
    H1Header,
    H1Http10,
    H1Http11,
    /// `[conn_close Bool, conn_keep_alive Bool, expect_100_continue Bool]`
    H1HeadFlags,
    /// `[method Binary, target Binary, version, headers, flags, consumed Int]`
    H1ParsedDone,
    H1ParsedNeedMore,
    /// `[status Int]`
    H1ParsedBad,
    H1FramingNoBody,
    /// `[n Int]`
    H1FramingLength,
    H1FramingChunked,
    /// `[status Int]`
    H1FramingInvalid,
    /// `[body Binary, trailers, consumed Int]`
    H1ChunkedDone,
    H1ChunkedNeedMore,
    /// `[status Int]`
    H1ChunkedBad,
    /// `[version, code Int, reason Binary, headers, flags, consumed Int]`
    H1RespDone,
    H1RespNeedMore,
    /// `[err BadResponse]`
    H1RespBad,
    H1BadStatusLine,
    H1BadVersion,
    H1BadField,
    H1BadHeadTooLarge,

    /// A parsed JSON document cursor — `[arena Binary, tape Binary, idx Int]`
    JsonDoc,
    /// `[offset Int, message String]`
    JsonParseError,

    /// A TLS connection record — `[conn, peer SocketAddress, server_name Str]`
    TlsSocket,
    /// The chain did not end at a trusted root.
    TlsCertUnknownIssuer,
    TlsCertExpired,
    TlsCertNotYetValid,
    TlsCertRevoked,
    /// The chain verified but was not issued for the name asked for.
    TlsHostnameMismatch,
    TlsBadCertificate,
    /// The peer is not speaking TLS, or not a version/suite we accept.
    TlsProtocolError,
    TlsHandshakeFailed,
    /// The requested name is not one a certificate can be issued for.
    TlsInvalidServerName,
    /// The transport under TLS failed — `[cause NetError]`
    TlsTransport,

    /// Fewer bytes than the value needs.
    WireTruncated,
    /// Bad magic, or a format version this runtime does not read.
    WireNotWire,
    /// Encoded from a type of a different shape — `[expected Int, found Int]`
    WireSchemaMismatch,
    /// Well-framed bytes that hold no value of the type — `[offset Int, what Str]`
    WireMalformed,
    /// A complete value followed by more bytes — `[count Int]`
    WireTrailingBytes,
}

impl AbiSlot {
    pub(crate) const COUNT: usize = AbiSlot::WireTrailingBytes as usize + 1;

    pub(crate) const ALL: [AbiSlot; AbiSlot::COUNT] = {
        use AbiSlot::*;
        [
            ResultOk,
            ResultErr,
            OptionSome,
            OptionNone,
            Unit,
            FsEnoent,
            FsEacces,
            FsEexist,
            FsEnotdir,
            FsEisdir,
            FsErofs,
            FsEloop,
            FsEfbig,
            FsEnospc,
            FsEdquot,
            FsUnalignedBinary,
            FsErrnoOther,
            NetEtimedout,
            NetEconnrefused,
            NetEconnreset,
            NetEconnaborted,
            NetEnotconn,
            NetEpipe,
            NetEaddrinuse,
            NetEaddrnotavail,
            NetEnetdown,
            NetEnetunreach,
            NetEhostunreach,
            NetEacces,
            NetInvalidPort,
            NetUnalignedBinary,
            NetErrnoOther,
            IpV4,
            IpV6,
            SocketAddr,
            Socket,
            ReadData,
            ReadClosed,
            Monitor,
            Down,
            ExitNormal,
            ExitNoProcess,
            ExitKilled,
            ExitCrashed,
            CrashIndexOutOfBounds,
            CrashSliceOutOfBounds,
            CrashForeignReceive,
            CrashTypeMismatch,
            CrashSupervision,
            Port,
            PortExited,
            PortSignaled,
            H1Header,
            H1Http10,
            H1Http11,
            H1HeadFlags,
            H1ParsedDone,
            H1ParsedNeedMore,
            H1ParsedBad,
            H1FramingNoBody,
            H1FramingLength,
            H1FramingChunked,
            H1FramingInvalid,
            H1ChunkedDone,
            H1ChunkedNeedMore,
            H1ChunkedBad,
            H1RespDone,
            H1RespNeedMore,
            H1RespBad,
            H1BadStatusLine,
            H1BadVersion,
            H1BadField,
            H1BadHeadTooLarge,
            JsonDoc,
            JsonParseError,
            TlsSocket,
            TlsCertUnknownIssuer,
            TlsCertExpired,
            TlsCertNotYetValid,
            TlsCertRevoked,
            TlsHostnameMismatch,
            TlsBadCertificate,
            TlsProtocolError,
            TlsHandshakeFailed,
            TlsInvalidServerName,
            TlsTransport,
            WireTruncated,
            WireNotWire,
            WireSchemaMismatch,
            WireMalformed,
            WireTrailingBytes,
        ]
    };

    pub const fn name(self) -> &'static str {
        use AbiSlot::*;
        match self {
            ResultOk => "ResultOk",
            ResultErr => "ResultErr",
            OptionSome => "OptionSome",
            OptionNone => "OptionNone",
            Unit => "Unit",
            FsEnoent => "FsEnoent",
            FsEacces => "FsEacces",
            FsEexist => "FsEexist",
            FsEnotdir => "FsEnotdir",
            FsEisdir => "FsEisdir",
            FsErofs => "FsErofs",
            FsEloop => "FsEloop",
            FsEfbig => "FsEfbig",
            FsEnospc => "FsEnospc",
            FsEdquot => "FsEdquot",
            FsUnalignedBinary => "FsUnalignedBinary",
            FsErrnoOther => "FsErrnoOther",
            NetEtimedout => "NetEtimedout",
            NetEconnrefused => "NetEconnrefused",
            NetEconnreset => "NetEconnreset",
            NetEconnaborted => "NetEconnaborted",
            NetEnotconn => "NetEnotconn",
            NetEpipe => "NetEpipe",
            NetEaddrinuse => "NetEaddrinuse",
            NetEaddrnotavail => "NetEaddrnotavail",
            NetEnetdown => "NetEnetdown",
            NetEnetunreach => "NetEnetunreach",
            NetEhostunreach => "NetEhostunreach",
            NetEacces => "NetEacces",
            NetInvalidPort => "NetInvalidPort",
            NetUnalignedBinary => "NetUnalignedBinary",
            NetErrnoOther => "NetErrnoOther",
            IpV4 => "IpV4",
            IpV6 => "IpV6",
            SocketAddr => "SocketAddr",
            Socket => "Socket",
            ReadData => "ReadData",
            ReadClosed => "ReadClosed",
            Monitor => "Monitor",
            Down => "Down",
            ExitNormal => "ExitNormal",
            ExitNoProcess => "ExitNoProcess",
            ExitKilled => "ExitKilled",
            ExitCrashed => "ExitCrashed",
            CrashIndexOutOfBounds => "CrashIndexOutOfBounds",
            CrashSliceOutOfBounds => "CrashSliceOutOfBounds",
            CrashForeignReceive => "CrashForeignReceive",
            CrashTypeMismatch => "CrashTypeMismatch",
            CrashSupervision => "CrashSupervision",
            Port => "Port",
            PortExited => "PortExited",
            PortSignaled => "PortSignaled",
            H1Header => "H1Header",
            H1Http10 => "H1Http10",
            H1Http11 => "H1Http11",
            H1HeadFlags => "H1HeadFlags",
            H1ParsedDone => "H1ParsedDone",
            H1ParsedNeedMore => "H1ParsedNeedMore",
            H1ParsedBad => "H1ParsedBad",
            H1FramingNoBody => "H1FramingNoBody",
            H1FramingLength => "H1FramingLength",
            H1FramingChunked => "H1FramingChunked",
            H1FramingInvalid => "H1FramingInvalid",
            H1ChunkedDone => "H1ChunkedDone",
            H1ChunkedNeedMore => "H1ChunkedNeedMore",
            H1ChunkedBad => "H1ChunkedBad",
            H1RespDone => "H1RespDone",
            H1RespNeedMore => "H1RespNeedMore",
            H1RespBad => "H1RespBad",
            H1BadStatusLine => "H1BadStatusLine",
            H1BadVersion => "H1BadVersion",
            H1BadField => "H1BadField",
            H1BadHeadTooLarge => "H1BadHeadTooLarge",
            JsonDoc => "JsonDoc",
            JsonParseError => "JsonParseError",
            TlsSocket => "TlsSocket",
            TlsCertUnknownIssuer => "TlsCertUnknownIssuer",
            TlsCertExpired => "TlsCertExpired",
            TlsCertNotYetValid => "TlsCertNotYetValid",
            TlsCertRevoked => "TlsCertRevoked",
            TlsHostnameMismatch => "TlsHostnameMismatch",
            TlsBadCertificate => "TlsBadCertificate",
            TlsProtocolError => "TlsProtocolError",
            TlsHandshakeFailed => "TlsHandshakeFailed",
            TlsInvalidServerName => "TlsInvalidServerName",
            TlsTransport => "TlsTransport",
            WireTruncated => "WireTruncated",
            WireNotWire => "WireNotWire",
            WireSchemaMismatch => "WireSchemaMismatch",
            WireMalformed => "WireMalformed",
            WireTrailingBytes => "WireTrailingBytes",
        }
    }

    #[inline]
    pub(crate) const fn index(self) -> usize {
        self as usize
    }

    /// The payload arity the slot's documented order fixes. A binding whose
    /// constructor disagrees is rejected at load ([`crate::template::AbiTable`]).
    pub const fn arity(self) -> usize {
        use AbiSlot::*;
        match self {
            OptionNone | Unit | FsEnospc | FsEdquot | FsUnalignedBinary | NetEtimedout
            | NetEconnrefused | NetEconnreset | NetEconnaborted | NetEnotconn | NetEpipe
            | NetEaddrinuse | NetEaddrnotavail | NetEnetdown | NetEnetunreach | NetEhostunreach
            | NetEacces | NetInvalidPort | NetUnalignedBinary | ReadClosed | ExitNormal
            | ExitNoProcess | ExitKilled | CrashForeignReceive | H1Http10 | H1Http11
            | H1ParsedNeedMore | H1FramingNoBody | H1FramingChunked | H1ChunkedNeedMore
            | TlsCertUnknownIssuer | TlsCertExpired | TlsCertNotYetValid | TlsCertRevoked
            | TlsHostnameMismatch | TlsBadCertificate | TlsProtocolError | TlsHandshakeFailed
            | TlsInvalidServerName | H1RespNeedMore | H1BadStatusLine | H1BadVersion
            | H1BadField | H1BadHeadTooLarge | WireTruncated | WireNotWire => 0,
            ResultOk | ResultErr | OptionSome | FsEnoent | FsEacces | FsEexist | FsEnotdir
            | FsEisdir | FsErofs | FsEloop | FsEfbig | FsErrnoOther | NetErrnoOther | IpV4
            | IpV6 | ReadData | ExitCrashed | CrashSupervision | PortExited | PortSignaled
            | H1ParsedBad | H1FramingLength | H1FramingInvalid | H1ChunkedBad | TlsTransport
            | H1RespBad | WireTrailingBytes => 1,
            JsonParseError => 2,
            JsonDoc => 3,
            SocketAddr
            | Socket
            | Monitor
            | Down
            | CrashIndexOutOfBounds
            | Port
            | H1Header
            | WireSchemaMismatch
            | WireMalformed => 2,
            H1HeadFlags | H1ChunkedDone | CrashSliceOutOfBounds | CrashTypeMismatch | TlsSocket => {
                3
            }
            H1ParsedDone | H1RespDone => 6,
        }
    }
}

/// Every slot `op` may construct. A front end need only bind the slots for the
/// ops it actually emits.
pub(crate) fn slots_for(op: Op) -> &'static [AbiSlot] {
    use AbiSlot as S;
    match op {
        Op::FileRead | Op::FileWrite => &[
            S::ResultOk,
            S::ResultErr,
            S::Unit,
            S::FsEnoent,
            S::FsEacces,
            S::FsEexist,
            S::FsEnotdir,
            S::FsEisdir,
            S::FsErofs,
            S::FsEloop,
            S::FsEfbig,
            S::FsEnospc,
            S::FsEdquot,
            S::FsUnalignedBinary,
            S::FsErrnoOther,
        ],
        Op::TcpListen | Op::TcpConnect | Op::TcpCloseServer | Op::TcpClose => &[
            S::ResultOk,
            S::ResultErr,
            S::Unit,
            S::Socket,
            S::SocketAddr,
            S::IpV4,
            S::IpV6,
            S::NetEtimedout,
            S::NetEconnrefused,
            S::NetEconnreset,
            S::NetEconnaborted,
            S::NetEnotconn,
            S::NetEpipe,
            S::NetEaddrinuse,
            S::NetEaddrnotavail,
            S::NetEnetdown,
            S::NetEnetunreach,
            S::NetEhostunreach,
            S::NetEacces,
            S::NetInvalidPort,
            S::NetUnalignedBinary,
            S::NetErrnoOther,
        ],
        Op::TcpAccept => &[
            S::ResultOk,
            S::ResultErr,
            S::OptionSome,
            S::OptionNone,
            S::Socket,
            S::SocketAddr,
            S::IpV4,
            S::IpV6,
            S::NetEtimedout,
            S::NetEconnrefused,
            S::NetEconnreset,
            S::NetEconnaborted,
            S::NetEnotconn,
            S::NetEpipe,
            S::NetEaddrinuse,
            S::NetEaddrnotavail,
            S::NetEnetdown,
            S::NetEnetunreach,
            S::NetEhostunreach,
            S::NetEacces,
            S::NetErrnoOther,
        ],
        Op::TcpRead | Op::TcpReadUntil => &[
            S::ResultOk,
            S::ResultErr,
            S::ReadData,
            S::ReadClosed,
            S::NetEtimedout,
            S::NetEconnreset,
            S::NetEconnaborted,
            S::NetEnotconn,
            S::NetEpipe,
            S::NetErrnoOther,
        ],
        Op::TcpWrite | Op::TcpWriteParts => &[
            S::ResultOk,
            S::ResultErr,
            S::Unit,
            S::NetEconnreset,
            S::NetEpipe,
            S::NetEnotconn,
            S::NetUnalignedBinary,
            S::NetErrnoOther,
        ],
        // Every TLS op can report a transport cause, so each carries the
        // `NetError` slots that `TlsTransport` wraps as well as its own.
        Op::TlsHandshake => &[
            S::ResultOk,
            S::ResultErr,
            S::TlsSocket,
            S::SocketAddr,
            S::IpV4,
            S::IpV6,
            S::TlsCertUnknownIssuer,
            S::TlsCertExpired,
            S::TlsCertNotYetValid,
            S::TlsCertRevoked,
            S::TlsHostnameMismatch,
            S::TlsBadCertificate,
            S::TlsProtocolError,
            S::TlsHandshakeFailed,
            S::TlsInvalidServerName,
            S::TlsTransport,
            S::NetEtimedout,
            S::NetEconnrefused,
            S::NetEconnreset,
            S::NetEconnaborted,
            S::NetEnotconn,
            S::NetEpipe,
            S::NetEhostunreach,
            S::NetErrnoOther,
        ],
        Op::TlsRead => &[
            S::ResultOk,
            S::ResultErr,
            S::ReadData,
            S::ReadClosed,
            S::TlsProtocolError,
            S::TlsTransport,
            S::NetEtimedout,
            S::NetEconnreset,
            S::NetEconnaborted,
            S::NetEnotconn,
            S::NetEpipe,
            S::NetErrnoOther,
        ],
        Op::TlsWrite => &[
            S::ResultOk,
            S::ResultErr,
            S::Unit,
            S::TlsProtocolError,
            S::TlsTransport,
            S::NetEconnreset,
            S::NetEpipe,
            S::NetEnotconn,
            S::NetUnalignedBinary,
            S::NetErrnoOther,
        ],
        Op::TlsClose => &[S::ResultOk, S::ResultErr, S::Unit],
        Op::PortSpawn => &[
            S::ResultOk,
            S::ResultErr,
            S::Port,
            S::FsEnoent,
            S::FsEacces,
            S::FsEexist,
            S::FsEnotdir,
            S::FsEisdir,
            S::FsErofs,
            S::FsEloop,
            S::FsEfbig,
            S::FsEnospc,
            S::FsEdquot,
            S::FsErrnoOther,
        ],
        Op::PortClose => &[
            S::ResultOk,
            S::ResultErr,
            S::PortExited,
            S::PortSignaled,
            S::NetEnotconn,
            S::NetErrnoOther,
        ],
        Op::TcpLocalAddr => &[
            S::ResultOk,
            S::ResultErr,
            S::SocketAddr,
            S::IpV4,
            S::IpV6,
            S::NetErrnoOther,
        ],
        Op::DnsResolve => &[
            S::ResultOk,
            S::ResultErr,
            S::IpV4,
            S::IpV6,
            S::NetEtimedout,
            S::NetEhostunreach,
            S::NetErrnoOther,
        ],
        Op::IpParse => &[S::OptionSome, S::OptionNone, S::IpV4, S::IpV6],
        Op::HttpParseHead => &[
            S::H1ParsedDone,
            S::H1ParsedNeedMore,
            S::H1ParsedBad,
            S::H1Header,
            S::H1Http10,
            S::H1Http11,
            S::H1HeadFlags,
        ],
        Op::HttpParseResponseHead => &[
            S::H1RespDone,
            S::H1RespNeedMore,
            S::H1RespBad,
            S::H1BadStatusLine,
            S::H1BadVersion,
            S::H1BadField,
            S::H1BadHeadTooLarge,
            S::H1Header,
            S::H1Http10,
            S::H1Http11,
            S::H1HeadFlags,
        ],
        Op::HttpFraming => &[
            S::H1FramingNoBody,
            S::H1FramingLength,
            S::H1FramingChunked,
            S::H1FramingInvalid,
        ],
        Op::HttpChunkDecode => &[
            S::H1ChunkedDone,
            S::H1ChunkedNeedMore,
            S::H1ChunkedBad,
            S::H1Header,
        ],
        Op::HttpHeaderGet | Op::MapGet | Op::FactoryLookup | Op::SupervisedInfo => {
            &[S::OptionSome, S::OptionNone]
        }
        Op::JsonParse => &[S::ResultOk, S::ResultErr, S::JsonDoc, S::JsonParseError],
        Op::JsonField | Op::JsonIndex => &[S::OptionSome, S::OptionNone, S::JsonDoc],
        Op::JsonEntries | Op::JsonElements => &[S::JsonDoc],
        Op::JsonString | Op::JsonInt | Op::JsonIntText | Op::JsonFloat | Op::JsonBool => {
            &[S::OptionSome, S::OptionNone]
        }
        // `PushNil` is the value of a block that ends in a statement, and
        // `Print` pushes nothing so the emitter follows it with one.
        Op::PushNil | Op::Sleep | Op::SupervisorWorkerOnEach => &[S::Unit],
        Op::SubjectSend
        | Op::SubjectSendUrgent
        | Op::ProcessDemonitor
        | Op::ProcessKill
        | Op::TcpGive
        | Op::WatchCancel => &[S::Unit],
        // The op itself builds a `Down` only for a target that has already
        // ended; every other reason is built when a monitored process ends,
        // which only a program that emitted this op can arrange.
        // A watch's notices carry the same reasons a monitor's do; `Killed`
        // and `NoProcess` also stand in for a removed entry and an absent one.
        Op::ProcessMonitor | Op::WatchNew => &[
            S::Monitor,
            S::Down,
            S::ExitNormal,
            S::ExitNoProcess,
            S::ExitKilled,
            S::ExitCrashed,
            S::CrashIndexOutOfBounds,
            S::CrashSliceOutOfBounds,
            S::CrashForeignReceive,
            S::CrashTypeMismatch,
            S::CrashSupervision,
        ],
        Op::SubjectReceiveUntil => &[S::ResultOk, S::ResultErr, S::Unit],
        // `WireEncode` builds a plain `Binary`, so it needs no slot at all;
        // every refusal it could otherwise report is a compile error at the
        // call. `WireDecode` wraps its outcome and can build any `DecodeError`.
        Op::WireDecode => &[
            S::ResultOk,
            S::ResultErr,
            S::WireTruncated,
            S::WireNotWire,
            S::WireSchemaMismatch,
            S::WireMalformed,
            S::WireTrailingBytes,
        ],
        _ => &[],
    }
}

/// A filesystem failure. The variant says what payload the caller owes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsFailure {
    Path(AbiSlot),
    Bare(AbiSlot),
    Errno(i32),
}

/// A socket failure, as [`FsFailure`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetFailure {
    Bare(AbiSlot),
    Errno(i32),
}

pub(crate) fn classify_fs(e: &std::io::Error) -> FsFailure {
    match e.raw_os_error() {
        Some(libc::ENOENT) => FsFailure::Path(AbiSlot::FsEnoent),
        Some(libc::EACCES) => FsFailure::Path(AbiSlot::FsEacces),
        Some(libc::EEXIST) => FsFailure::Path(AbiSlot::FsEexist),
        Some(libc::ENOTDIR) => FsFailure::Path(AbiSlot::FsEnotdir),
        Some(libc::EISDIR) => FsFailure::Path(AbiSlot::FsEisdir),
        Some(libc::EROFS) => FsFailure::Path(AbiSlot::FsErofs),
        Some(libc::ELOOP) => FsFailure::Path(AbiSlot::FsEloop),
        Some(libc::EFBIG) => FsFailure::Path(AbiSlot::FsEfbig),
        Some(libc::ENOSPC) => FsFailure::Bare(AbiSlot::FsEnospc),
        Some(libc::EDQUOT) => FsFailure::Bare(AbiSlot::FsEdquot),
        _ => FsFailure::Errno(errno_of(e)),
    }
}

pub(crate) fn classify_net(e: &std::io::Error) -> NetFailure {
    match e.raw_os_error() {
        Some(libc::ETIMEDOUT) => NetFailure::Bare(AbiSlot::NetEtimedout),
        Some(libc::ECONNREFUSED) => NetFailure::Bare(AbiSlot::NetEconnrefused),
        Some(libc::ECONNRESET) => NetFailure::Bare(AbiSlot::NetEconnreset),
        Some(libc::ECONNABORTED) => NetFailure::Bare(AbiSlot::NetEconnaborted),
        Some(libc::ENOTCONN) => NetFailure::Bare(AbiSlot::NetEnotconn),
        Some(libc::EPIPE) => NetFailure::Bare(AbiSlot::NetEpipe),
        Some(libc::EADDRINUSE) => NetFailure::Bare(AbiSlot::NetEaddrinuse),
        Some(libc::EADDRNOTAVAIL) => NetFailure::Bare(AbiSlot::NetEaddrnotavail),
        Some(libc::ENETDOWN) => NetFailure::Bare(AbiSlot::NetEnetdown),
        Some(libc::ENETUNREACH) => NetFailure::Bare(AbiSlot::NetEnetunreach),
        Some(libc::EHOSTUNREACH) => NetFailure::Bare(AbiSlot::NetEhostunreach),
        Some(libc::EACCES) => NetFailure::Bare(AbiSlot::NetEacces),
        _ => NetFailure::Errno(errno_of(e)),
    }
}

/// The raw errno, or `-1` for a synthesised error with no OS origin.
fn errno_of(e: &std::io::Error) -> i32 {
    e.raw_os_error().unwrap_or(-1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_are_dense_and_ordered() {
        for (i, slot) in AbiSlot::ALL.iter().enumerate() {
            assert_eq!(slot.index(), i, "{} out of order", slot.name());
        }
        assert_eq!(AbiSlot::ALL.len(), AbiSlot::COUNT);
    }

    #[test]
    fn slot_names_are_unique() {
        let mut names: Vec<&str> = AbiSlot::ALL.iter().map(|s| s.name()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before);
    }

    #[test]
    fn fs_classification_matches_posix() {
        let e = std::io::Error::from_raw_os_error(libc::ENOENT);
        assert_eq!(classify_fs(&e), FsFailure::Path(AbiSlot::FsEnoent));
        let e = std::io::Error::from_raw_os_error(libc::ENOSPC);
        assert_eq!(classify_fs(&e), FsFailure::Bare(AbiSlot::FsEnospc));
        let e = std::io::Error::from_raw_os_error(libc::EIO);
        assert_eq!(classify_fs(&e), FsFailure::Errno(libc::EIO));
    }

    #[test]
    fn net_classification_matches_posix() {
        let e = std::io::Error::from_raw_os_error(libc::ECONNREFUSED);
        assert_eq!(classify_net(&e), NetFailure::Bare(AbiSlot::NetEconnrefused));
        let e = std::io::Error::from_raw_os_error(libc::EIO);
        assert_eq!(classify_net(&e), NetFailure::Errno(libc::EIO));
    }

    #[test]
    fn errorless_io_error_gets_the_residual() {
        let e = std::io::Error::other("no os origin");
        assert_eq!(classify_fs(&e), FsFailure::Errno(-1));
        assert_eq!(classify_net(&e), NetFailure::Errno(-1));
    }

    #[test]
    fn fallible_ops_declare_their_result_wrappers() {
        for op in [Op::FileRead, Op::TcpConnect, Op::DnsResolve] {
            let slots = slots_for(op);
            assert!(slots.contains(&AbiSlot::ResultOk), "{op:?}");
            assert!(slots.contains(&AbiSlot::ResultErr), "{op:?}");
        }
        assert!(slots_for(Op::Add).is_empty());
    }
}
