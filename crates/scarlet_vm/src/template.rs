//! Constructor templates: the constant part of one tagged value, precomputed
//! by the front end into the program's frozen area. Instantiating allocates
//! exactly one enum cell; a nullary constructor is pre-built whole, so pushing
//! it allocates nothing.

use crate::TypeId;
use crate::abi::{AbiSlot, TemplateIdx};
use crate::bytecode::{Arena, EnumRef, Op, Value};
use crate::frozen::FrozenBuilder;

/// One constructor, ready to instantiate.
#[derive(Debug, Clone)]
pub struct EnumTemplate {
    type_id: TypeId,
    variant_idx: u16,
    /// Frozen `Str` of the enum type name.
    enum_name: Value,
    /// Frozen `Str` of the variant name.
    variant_name: Value,
    /// Frozen `Tuple`-of-`Str` of the field labels.
    labels: Value,
    /// For a nullary constructor, the whole value pre-built in the frozen area.
    nullary: Option<Value>,
}

impl EnumTemplate {
    /// Intern the names and labels into `fb`.
    pub fn build(
        fb: &mut FrozenBuilder,
        type_id: TypeId,
        variant_idx: u16,
        type_name: &str,
        variant_name: &str,
        labels: &[&str],
    ) -> Self {
        let label_consts = labels.iter().map(|l| fb.str(l)).collect();
        let mut t = EnumTemplate {
            type_id,
            variant_idx,
            enum_name: fb.str(type_name).into_value(),
            variant_name: fb.str(variant_name).into_value(),
            labels: fb.tuple(label_consts).into_value(),
            nullary: None,
        };
        if labels.is_empty() {
            t.nullary = Some(t.instantiate(fb, &[]));
        }
        t
    }

    /// Build an instance carrying `payload` in `a`.
    #[inline]
    pub(crate) fn instantiate<A: Arena + ?Sized>(&self, a: &mut A, payload: &[Value]) -> Value {
        // Lazy: see `EnumRef::hash` — 0 means "computed on first use".
        Value::enum_in(
            a,
            self.type_id,
            self.variant_idx,
            0u64,
            self.enum_name.clone(),
            self.variant_name.clone(),
            self.labels.clone(),
            payload,
        )
    }

    /// The pre-built value, for a nullary constructor.
    #[inline]
    pub(crate) fn nullary(&self) -> Option<&Value> {
        self.nullary.as_ref()
    }

    /// Whether `e` was built from this template. The constructor's identity is
    /// `(type_id, variant_idx)`, not its name: names are a front end's to
    /// choose and two of its types may share one.
    #[inline]
    pub(crate) fn is_instance(&self, e: &EnumRef<'_>) -> bool {
        e.type_id() == self.type_id && e.variant_idx() == self.variant_idx
    }

    fn arity(&self) -> usize {
        self.labels.as_tuple().map_or(0, |t| t.len())
    }
}

/// Which template answers each [`AbiSlot`]. A `None` slot is unbound, which
/// is safe only if no emitted op reaches it (see [`crate::abi::slots_for`]).
#[derive(Debug, Clone)]
pub struct AbiTable {
    slots: [Option<TemplateIdx>; AbiSlot::COUNT],
}

impl Default for AbiTable {
    fn default() -> Self {
        AbiTable {
            slots: [None; AbiSlot::COUNT],
        }
    }
}

impl AbiTable {
    #[inline]
    pub(crate) fn get(&self, slot: AbiSlot) -> Option<TemplateIdx> {
        self.slots[slot.index()]
    }

    pub fn bind(&mut self, slot: AbiSlot, idx: TemplateIdx) {
        self.slots[slot.index()] = Some(idx);
    }

    /// Slots reachable from `ops` that nothing bound. Empty means the program
    /// can run.
    pub fn unbound_for<I: IntoIterator<Item = Op>>(&self, ops: I) -> Vec<AbiSlot> {
        let mut missing = Vec::new();
        for op in ops {
            for &slot in crate::abi::slots_for(op) {
                if self.slots[slot.index()].is_none() && !missing.contains(&slot) {
                    missing.push(slot);
                }
            }
        }
        missing
    }

    /// Check every binding names a real template of the slot's arity. Run once
    /// at load; construction sites rely on it thereafter.
    pub(crate) fn validate(
        &self,
        templates: &crate::tivec::TiVec<TemplateIdx, EnumTemplate>,
    ) -> Result<(), String> {
        for slot in AbiSlot::ALL {
            let Some(idx) = self.slots[slot.index()] else {
                continue;
            };
            let Some(t) = templates.get(idx) else {
                return Err(format!("ABI slot {} binds missing {idx}", slot.name()));
            };
            if t.arity() != slot.arity() {
                return Err(format!(
                    "ABI slot {} needs arity {}, bound constructor has {}",
                    slot.name(),
                    slot.arity(),
                    t.arity()
                ));
            }
        }
        Ok(())
    }
}

/// The Scarlet stdlib's ids and names, written out by hand so the runtime's tests
/// need no compiler.
#[cfg(test)]
pub(crate) mod test_fixture {
    use super::*;
    use crate::tivec::TiVec;
    use AbiSlot as S;

    /// `(slot, type_id, variant_idx, type_name, variant_name, labels)`.
    type Row = (
        S,
        i32,
        u16,
        &'static str,
        &'static str,
        &'static [&'static str],
    );

    const PATH: &[&str] = &["path"];
    const CODE: &[&str] = &["code"];
    const STATUS: &[&str] = &["status"];
    const NONE_: &[&str] = &[];
    const CAUSE: &[&str] = &["cause"];
    const ERR: &[&str] = &["err"];

    const ROWS: &[Row] = &[
        (S::Unit, 262, 0, "Nil", "Nil", NONE_),
        (S::OptionSome, 263, 0, "Option", "Some", &["value"]),
        (S::OptionNone, 263, 1, "Option", "None", NONE_),
        (S::ResultOk, 264, 0, "Result", "Ok", &["value"]),
        (S::ResultErr, 264, 1, "Result", "Err", &["error"]),
        (S::FsEnoent, 5632, 0, "IoError", "NotFound", PATH),
        (S::FsEacces, 5632, 1, "IoError", "PermissionDenied", PATH),
        (S::FsEexist, 5632, 2, "IoError", "AlreadyExists", PATH),
        (S::FsEnotdir, 5632, 3, "IoError", "NotADirectory", PATH),
        (S::FsEisdir, 5632, 4, "IoError", "IsADirectory", PATH),
        (S::FsErofs, 5632, 5, "IoError", "ReadOnlyFilesystem", PATH),
        (S::FsEloop, 5632, 6, "IoError", "FilesystemLoop", PATH),
        (S::FsEnospc, 5632, 8, "IoError", "StorageFull", NONE_),
        (S::FsEdquot, 5632, 9, "IoError", "QuotaExceeded", NONE_),
        (S::FsEfbig, 5632, 10, "IoError", "FileTooLarge", PATH),
        (
            S::FsUnalignedBinary,
            5632,
            11,
            "IoError",
            "UnalignedBinary",
            NONE_,
        ),
        (S::FsErrnoOther, 5632, 12, "IoError", "Errno", CODE),
        (S::IpV4, 3328, 0, "IpAddress", "V4", &["addr"]),
        (S::IpV6, 3328, 1, "IpAddress", "V6", &["addr"]),
        (
            S::SocketAddr,
            3329,
            0,
            "SocketAddress",
            "SocketAddress",
            &["ip", "port"],
        ),
        (S::Socket, 4097, 0, "Socket", "Socket", &["conn", "peer"]),
        (S::ReadData, 4098, 0, "Read", "Data", &["bytes"]),
        (S::ReadClosed, 4098, 1, "Read", "Closed", NONE_),
        (S::Monitor, 4352, 0, "Monitor", "Monitor", &["target", "id"]),
        (S::Down, 4353, 0, "Down", "Down", &["pid", "reason"]),
        (S::ExitNormal, 4354, 0, "ExitReason", "Normal", NONE_),
        (S::ExitNoProcess, 4354, 1, "ExitReason", "NoProcess", NONE_),
        (S::ExitKilled, 4354, 2, "ExitReason", "Killed", NONE_),
        (S::ExitCrashed, 4354, 3, "ExitReason", "Crashed", &["crash"]),
        (
            S::CrashIndexOutOfBounds,
            4355,
            0,
            "Crash",
            "IndexOutOfBounds",
            &["index", "length"],
        ),
        (
            S::CrashSliceOutOfBounds,
            4355,
            1,
            "Crash",
            "SliceOutOfBounds",
            &["from", "to", "length"],
        ),
        (
            S::CrashForeignReceive,
            4355,
            2,
            "Crash",
            "ForeignReceive",
            NONE_,
        ),
        (
            S::CrashTypeMismatch,
            4355,
            3,
            "Crash",
            "TypeMismatch",
            &["op", "expected", "got"],
        ),
        (
            S::CrashSupervision,
            4355,
            4,
            "Crash",
            "Supervision",
            &["why"],
        ),
        (S::Port, 4608, 0, "Port", "Port", &["conn", "os_pid"]),
        (S::PortExited, 4609, 0, "ExitStatus", "Exited", CODE),
        (
            S::PortSignaled,
            4609,
            1,
            "ExitStatus",
            "Signaled",
            &["signal"],
        ),
        (S::NetEtimedout, 3584, 0, "NetError", "TimedOut", NONE_),
        (
            S::NetEconnrefused,
            3584,
            1,
            "NetError",
            "ConnectionRefused",
            NONE_,
        ),
        (
            S::NetEconnreset,
            3584,
            2,
            "NetError",
            "ConnectionReset",
            NONE_,
        ),
        (
            S::NetEconnaborted,
            3584,
            3,
            "NetError",
            "ConnectionAborted",
            NONE_,
        ),
        (S::NetEnotconn, 3584, 4, "NetError", "NotConnected", NONE_),
        (S::NetEpipe, 3584, 5, "NetError", "BrokenPipe", NONE_),
        (S::NetEaddrinuse, 3584, 6, "NetError", "AddrInUse", NONE_),
        (
            S::NetEaddrnotavail,
            3584,
            7,
            "NetError",
            "AddrNotAvailable",
            NONE_,
        ),
        (S::NetEnetdown, 3584, 8, "NetError", "NetworkDown", NONE_),
        (
            S::NetEnetunreach,
            3584,
            9,
            "NetError",
            "NetworkUnreachable",
            NONE_,
        ),
        (
            S::NetEhostunreach,
            3584,
            10,
            "NetError",
            "HostUnreachable",
            NONE_,
        ),
        (
            S::NetEacces,
            3584,
            11,
            "NetError",
            "PermissionDenied",
            NONE_,
        ),
        (
            S::NetUnalignedBinary,
            3584,
            14,
            "NetError",
            "UnalignedBinary",
            NONE_,
        ),
        (
            S::NetInvalidPort,
            3584,
            15,
            "NetError",
            "InvalidPort",
            NONE_,
        ),
        (S::NetErrnoOther, 3584, 16, "NetError", "Errno", CODE),
        (S::H1Header, 2560, 0, "Header", "Header", &["name", "value"]),
        (S::H1Http10, 3072, 0, "Version", "Http10", NONE_),
        (S::H1Http11, 3072, 1, "Version", "Http11", NONE_),
        (
            S::H1ConnNeither,
            3079,
            0,
            "ConnTokens",
            "ConnNeither",
            NONE_,
        ),
        (S::H1ConnClose, 3079, 1, "ConnTokens", "ConnClose", NONE_),
        (
            S::H1ConnKeepAlive,
            3079,
            2,
            "ConnTokens",
            "ConnKeepAlive",
            NONE_,
        ),
        (S::H1ConnBoth, 3079, 3, "ConnTokens", "ConnBoth", NONE_),
        (
            S::H1HeadFlags,
            3073,
            0,
            "HeadFlags",
            "HeadFlags",
            &["conn", "expect_100_continue"],
        ),
        (
            S::H1ParsedDone,
            3074,
            0,
            "Parsed",
            "Done",
            &[
                "method", "target", "version", "headers", "flags", "consumed",
            ],
        ),
        (S::H1ParsedNeedMore, 3074, 1, "Parsed", "NeedMore", NONE_),
        (S::H1ParsedBad, 3074, 2, "Parsed", "Bad", STATUS),
        (S::H1FramingNoBody, 3075, 0, "Framing", "NoBody", NONE_),
        (S::H1FramingLength, 3075, 1, "Framing", "Length", &["n"]),
        (S::H1FramingChunked, 3075, 2, "Framing", "Chunked", NONE_),
        (S::H1FramingInvalid, 3075, 3, "Framing", "Invalid", STATUS),
        (
            S::H1ChunkedDone,
            3076,
            0,
            "ChunkBody",
            "ChunkedDone",
            &["body", "trailers", "consumed"],
        ),
        (
            S::H1ChunkedNeedMore,
            3076,
            1,
            "ChunkBody",
            "ChunkedNeedMore",
            NONE_,
        ),
        (S::H1ChunkedBad, 3076, 2, "ChunkBody", "ChunkedBad", STATUS),
        (
            S::H1RespDone,
            3077,
            0,
            "ParsedResponse",
            "ResponseDone",
            &["version", "code", "reason", "headers", "flags", "consumed"],
        ),
        (
            S::H1RespNeedMore,
            3077,
            1,
            "ParsedResponse",
            "ResponseNeedMore",
            NONE_,
        ),
        (S::H1RespBad, 3077, 2, "ParsedResponse", "ResponseBad", ERR),
        (
            S::H1BadStatusLine,
            3078,
            0,
            "BadResponse",
            "BadStatusLine",
            NONE_,
        ),
        (S::H1BadVersion, 3078, 1, "BadResponse", "BadVersion", NONE_),
        (S::H1BadField, 3078, 2, "BadResponse", "BadField", NONE_),
        (
            S::H1BadHeadTooLarge,
            3078,
            3,
            "BadResponse",
            "HeadTooLarge",
            NONE_,
        ),
        (S::JsonDoc, 7168, 0, "Doc", "Doc", &["arena", "tape", "idx"]),
        (
            S::JsonParseError,
            7169,
            0,
            "ParseError",
            "ParseError",
            &["offset", "message"],
        ),
        (
            S::TlsSocket,
            4098,
            0,
            "TlsSocket",
            "TlsSocket",
            &["conn", "peer", "server_name"],
        ),
        (
            S::TlsCertUnknownIssuer,
            3585,
            0,
            "TlsError",
            "CertificateUnknownIssuer",
            NONE_,
        ),
        (
            S::TlsCertExpired,
            3585,
            1,
            "TlsError",
            "CertificateExpired",
            NONE_,
        ),
        (
            S::TlsCertNotYetValid,
            3585,
            2,
            "TlsError",
            "CertificateNotYetValid",
            NONE_,
        ),
        (
            S::TlsCertRevoked,
            3585,
            3,
            "TlsError",
            "CertificateRevoked",
            NONE_,
        ),
        (
            S::TlsHostnameMismatch,
            3585,
            4,
            "TlsError",
            "HostnameMismatch",
            NONE_,
        ),
        (
            S::TlsBadCertificate,
            3585,
            5,
            "TlsError",
            "BadCertificate",
            NONE_,
        ),
        (
            S::TlsProtocolError,
            3585,
            6,
            "TlsError",
            "ProtocolError",
            NONE_,
        ),
        (
            S::TlsHandshakeFailed,
            3585,
            7,
            "TlsError",
            "HandshakeFailed",
            NONE_,
        ),
        (
            S::TlsInvalidServerName,
            3585,
            8,
            "TlsError",
            "InvalidServerName",
            NONE_,
        ),
        (S::TlsTransport, 3585, 9, "TlsError", "Transport", CAUSE),
        (S::WireTruncated, 7424, 0, "DecodeError", "Truncated", NONE_),
        (S::WireNotWire, 7424, 1, "DecodeError", "NotWire", NONE_),
        (
            S::WireSchemaMismatch,
            7424,
            2,
            "DecodeError",
            "SchemaMismatch",
            &["expected", "found"],
        ),
        (
            S::WireMalformed,
            7424,
            3,
            "DecodeError",
            "Malformed",
            &["offset", "what"],
        ),
        (
            S::WireTrailingBytes,
            7424,
            4,
            "DecodeError",
            "TrailingBytes",
            &["count"],
        ),
        (
            S::WireOtherRun,
            7424,
            5,
            "DecodeError",
            "OtherRun",
            &["expected", "found"],
        ),
    ];

    /// Intern every fixture constructor into `fb` and bind its slot.
    pub(crate) fn build(fb: &mut FrozenBuilder) -> (TiVec<TemplateIdx, EnumTemplate>, AbiTable) {
        let mut templates = TiVec::new();
        let mut table = AbiTable::default();
        for &(slot, tid, vidx, ty, variant, labels) in ROWS {
            let t = EnumTemplate::build(fb, TypeId(tid), vidx, ty, variant, labels);
            table.bind(slot, templates.push(t));
        }
        (templates, table)
    }

    #[test]
    fn fixture_binds_every_slot() {
        let area = std::sync::Arc::new(crate::frozen::FrozenArea::new());
        let mut fb = area.builder();
        let (_, table) = build(&mut fb);
        let unbound: Vec<&str> = AbiSlot::ALL
            .iter()
            .filter(|s| table.get(**s).is_none())
            .map(|s| s.name())
            .collect();
        assert!(unbound.is_empty(), "unbound: {unbound:?}");
    }
}
