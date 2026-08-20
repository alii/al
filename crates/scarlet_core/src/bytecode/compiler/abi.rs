//! Binds the VM's [`AbiSlot`]s to Scarlet stdlib constructors at the end of a
//! compile: for each slot whose module this program loaded, intern an
//! [`EnumTemplate`] into the program's frozen area and record it in
//! `program.abi`. This table is the whole of what the runtime knows about
//! Scarlet's stdlib; a slot for a module the program never imported stays unbound,
//! which is fine exactly because the ops that construct it were never emitted
//! (checked below).
//!
//! The `(module, type, constructor)` names here are the ONE compiler-side
//! registry of runtime-constructed stdlib values. A renamed or deleted
//! constructor surfaces as a compile diagnostic naming the slot, not as a
//! silently mis-built value.

use scarlet_vm::abi::AbiSlot;
use scarlet_vm::template::EnumTemplate;
use scarlet_vm::tivec::TiVec;

use crate::module::ModuleKey;
use crate::span::Span;

const ZERO_SPAN: Span = Span {
    start_line: 0,
    start_column: 0,
    end_line: 0,
    end_column: 0,
};

use super::Compiler;

/// `(slot, module path, type name, constructor name)`.
type Binding = (AbiSlot, &'static [&'static str], &'static str, &'static str);

const SCARLET: &[&str] = &["scarlet"];
const IO: &[&str] = &["scarlet", "io"];
const ADDR: &[&str] = &["scarlet", "net", "address"];
const SOCK: &[&str] = &["scarlet", "net", "socket"];
const NET: &[&str] = &["scarlet", "net", "error"];
const PROCESS: &[&str] = &["scarlet", "process"];
const PORT: &[&str] = &["scarlet", "os", "port"];
const HDRS: &[&str] = &["scarlet", "http", "headers"];
const H1: &[&str] = &["scarlet", "http", "h1"];
const JSON: &[&str] = &["scarlet", "json"];
const TLS: &[&str] = &["scarlet", "net", "tls"];
const WIRE: &[&str] = &["scarlet", "wire"];

#[rustfmt::skip]
const BINDINGS: &[Binding] = &[
    (AbiSlot::Unit,               SCARLET,   "Nil",           "Nil"),
    (AbiSlot::OptionSome,         SCARLET,   "Option",        "Some"),
    (AbiSlot::OptionNone,         SCARLET,   "Option",        "None"),
    (AbiSlot::ResultOk,           SCARLET,   "Result",        "Ok"),
    (AbiSlot::ResultErr,          SCARLET,   "Result",        "Err"),
    (AbiSlot::FsEnoent,           IO,   "IoError",       "NotFound"),
    (AbiSlot::FsEacces,           IO,   "IoError",       "PermissionDenied"),
    (AbiSlot::FsEexist,           IO,   "IoError",       "AlreadyExists"),
    (AbiSlot::FsEnotdir,          IO,   "IoError",       "NotADirectory"),
    (AbiSlot::FsEisdir,           IO,   "IoError",       "IsADirectory"),
    (AbiSlot::FsErofs,            IO,   "IoError",       "ReadOnlyFilesystem"),
    (AbiSlot::FsEloop,            IO,   "IoError",       "FilesystemLoop"),
    (AbiSlot::FsEnospc,           IO,   "IoError",       "StorageFull"),
    (AbiSlot::FsEdquot,           IO,   "IoError",       "QuotaExceeded"),
    (AbiSlot::FsEfbig,            IO,   "IoError",       "FileTooLarge"),
    (AbiSlot::FsUnalignedBinary,  IO,   "IoError",       "UnalignedBinary"),
    (AbiSlot::FsErrnoOther,       IO,   "IoError",       "Errno"),
    (AbiSlot::IpV4,               ADDR, "IpAddress",     "V4"),
    (AbiSlot::IpV6,               ADDR, "IpAddress",     "V6"),
    (AbiSlot::SocketAddr,         ADDR, "SocketAddress", "SocketAddress"),
    (AbiSlot::Socket,             SOCK, "Socket",        "Socket"),
    (AbiSlot::ReadData,           SOCK, "Read",          "Data"),
    (AbiSlot::ReadClosed,         SOCK, "Read",          "Closed"),
    (AbiSlot::NetEtimedout,       NET,  "NetError",      "TimedOut"),
    (AbiSlot::NetEconnrefused,    NET,  "NetError",      "ConnectionRefused"),
    (AbiSlot::NetEconnreset,      NET,  "NetError",      "ConnectionReset"),
    (AbiSlot::NetEconnaborted,    NET,  "NetError",      "ConnectionAborted"),
    (AbiSlot::NetEnotconn,        NET,  "NetError",      "NotConnected"),
    (AbiSlot::NetEpipe,           NET,  "NetError",      "BrokenPipe"),
    (AbiSlot::NetEaddrinuse,      NET,  "NetError",      "AddrInUse"),
    (AbiSlot::NetEaddrnotavail,   NET,  "NetError",      "AddrNotAvailable"),
    (AbiSlot::NetEnetdown,        NET,  "NetError",      "NetworkDown"),
    (AbiSlot::NetEnetunreach,     NET,  "NetError",      "NetworkUnreachable"),
    (AbiSlot::NetEhostunreach,    NET,  "NetError",      "HostUnreachable"),
    (AbiSlot::NetEacces,          NET,  "NetError",      "PermissionDenied"),
    (AbiSlot::NetInvalidPort,     NET,  "NetError",      "InvalidPort"),
    (AbiSlot::NetUnalignedBinary, NET,  "NetError",      "UnalignedBinary"),
    (AbiSlot::NetErrnoOther,      NET,  "NetError",      "Errno"),
    (AbiSlot::Monitor,            PROCESS, "Monitor",    "Monitor"),
    (AbiSlot::Down,               PROCESS, "Down",       "Down"),
    (AbiSlot::ExitNormal,         PROCESS, "ExitReason", "Normal"),
    (AbiSlot::ExitNoProcess,      PROCESS, "ExitReason", "NoProcess"),
    (AbiSlot::ExitKilled,         PROCESS, "ExitReason", "Killed"),
    (AbiSlot::ExitCrashed,        PROCESS, "ExitReason", "Crashed"),
    (AbiSlot::CrashIndexOutOfBounds, PROCESS, "Crash",   "IndexOutOfBounds"),
    (AbiSlot::CrashSliceOutOfBounds, PROCESS, "Crash",   "SliceOutOfBounds"),
    (AbiSlot::CrashForeignReceive,   PROCESS, "Crash",   "ForeignReceive"),
    (AbiSlot::CrashTypeMismatch,     PROCESS, "Crash",   "TypeMismatch"),
    (AbiSlot::CrashSupervision,      PROCESS, "Crash",   "Supervision"),
    (AbiSlot::Port,               PORT,    "Port",       "Port"),
    (AbiSlot::PortExited,         PORT,    "ExitStatus", "Exited"),
    (AbiSlot::PortSignaled,       PORT,    "ExitStatus", "Signaled"),
    (AbiSlot::H1Header,           HDRS, "Header",        "Header"),
    (AbiSlot::H1Http10,           H1,   "Version",       "Http10"),
    (AbiSlot::H1Http11,           H1,   "Version",       "Http11"),
    (AbiSlot::H1ConnNeither,      H1,   "ConnTokens",    "ConnNeither"),
    (AbiSlot::H1ConnClose,        H1,   "ConnTokens",    "ConnClose"),
    (AbiSlot::H1ConnKeepAlive,    H1,   "ConnTokens",    "ConnKeepAlive"),
    (AbiSlot::H1ConnBoth,         H1,   "ConnTokens",    "ConnBoth"),
    (AbiSlot::H1HeadFlags,        H1,   "HeadFlags",     "HeadFlags"),
    (AbiSlot::H1ParsedDone,       H1,   "Parsed",        "Done"),
    (AbiSlot::H1ParsedNeedMore,   H1,   "Parsed",        "NeedMore"),
    (AbiSlot::H1ParsedBad,        H1,   "Parsed",        "Bad"),
    (AbiSlot::H1FramingNoBody,    H1,   "Framing",       "NoBody"),
    (AbiSlot::H1FramingLength,    H1,   "Framing",       "Length"),
    (AbiSlot::H1FramingChunked,   H1,   "Framing",       "Chunked"),
    (AbiSlot::H1FramingInvalid,   H1,   "Framing",       "Invalid"),
    (AbiSlot::H1ChunkedDone,      H1,   "ChunkBody",     "ChunkedDone"),
    (AbiSlot::H1ChunkedNeedMore,  H1,   "ChunkBody",     "ChunkedNeedMore"),
    (AbiSlot::H1ChunkedBad,       H1,   "ChunkBody",     "ChunkedBad"),
    (AbiSlot::H1RespDone,         H1,   "ParsedResponse", "ResponseDone"),
    (AbiSlot::H1RespNeedMore,     H1,   "ParsedResponse", "ResponseNeedMore"),
    (AbiSlot::H1RespBad,          H1,   "ParsedResponse", "ResponseBad"),
    (AbiSlot::H1BadStatusLine,    H1,   "BadResponse",   "BadStatusLine"),
    (AbiSlot::H1BadVersion,       H1,   "BadResponse",   "BadVersion"),
    (AbiSlot::H1BadField,         H1,   "BadResponse",   "BadField"),
    (AbiSlot::H1BadHeadTooLarge,  H1,   "BadResponse",   "HeadTooLarge"),
    (AbiSlot::JsonDoc,            JSON, "Doc",           "Doc"),
    (AbiSlot::JsonParseError,     JSON, "ParseError",    "ParseError"),
    (AbiSlot::TlsSocket,          TLS,  "TlsSocket",     "TlsSocket"),
    (AbiSlot::TlsCertUnknownIssuer, TLS, "TlsError",     "CertificateUnknownIssuer"),
    (AbiSlot::TlsCertExpired,     TLS,  "TlsError",      "CertificateExpired"),
    (AbiSlot::TlsCertNotYetValid, TLS,  "TlsError",      "CertificateNotYetValid"),
    (AbiSlot::TlsCertRevoked,     TLS,  "TlsError",      "CertificateRevoked"),
    (AbiSlot::TlsHostnameMismatch, TLS, "TlsError",      "HostnameMismatch"),
    (AbiSlot::TlsBadCertificate,  TLS,  "TlsError",      "BadCertificate"),
    (AbiSlot::TlsProtocolError,   TLS,  "TlsError",      "ProtocolError"),
    (AbiSlot::TlsHandshakeFailed, TLS,  "TlsError",      "HandshakeFailed"),
    (AbiSlot::TlsInvalidServerName, TLS, "TlsError",     "InvalidServerName"),
    (AbiSlot::TlsTransport,       TLS,  "TlsError",      "Transport"),
    (AbiSlot::WireTruncated,      WIRE, "DecodeError",   "Truncated"),
    (AbiSlot::WireNotWire,        WIRE, "DecodeError",   "NotWire"),
    (AbiSlot::WireSchemaMismatch, WIRE, "DecodeError",   "SchemaMismatch"),
    (AbiSlot::WireMalformed,      WIRE, "DecodeError",   "Malformed"),
    (AbiSlot::WireTrailingBytes,  WIRE, "DecodeError",   "TrailingBytes"),
];

impl Compiler {
    /// The type constructors whose parameters must stay monomorphic when a
    /// binding's type is generalized — the relaxed value restriction. A
    /// `Subject`'s argument names what a live mailbox carries, so
    /// quantifying it would let one queue be sent one type and received as
    /// another. Resolved by module identity, never by name alone, so a user
    /// type called `Subject` is unaffected. An unresolvable module yields an
    /// empty set, which is sound: no value of the type can occur in a
    /// program that never loaded it.
    pub(crate) fn restricted_generalization_cons(
        &mut self,
    ) -> std::collections::HashSet<crate::type_def::TypeId> {
        if let Some(memo) = &self.restricted_gen_cons {
            return memo.clone();
        }
        let process: Vec<String> = ["scarlet", "process"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let key = ModuleKey::of(&process);
        let found = self
            .module_table
            .get_or_hydrate(&key)
            .and_then(|iface| iface.types.get("Subject").map(|et| et.info.id));
        match found {
            Some(id) => {
                let set = std::collections::HashSet::from([id]);
                // Memoize only a hit: a module unresolvable now (a
                // from-source compile that has not loaded process yet) may
                // load later in this session.
                self.restricted_gen_cons = Some(set.clone());
                set
            }
            None => std::collections::HashSet::new(),
        }
    }

    /// Fill `program.templates`/`program.abi` from the modules this compile
    /// loaded, then require a binding for every slot an emitted op constructs.
    ///
    /// ABI templates are the prefix `[0, abi_template_count)`. Rebuilt from
    /// scratch each emit: which modules resolved can change, and a newly
    /// bound row would otherwise shift later indices. A rewind truncates to
    /// that count, so a descriptor template appended after this call cannot
    /// survive into the next emit.
    pub(super) fn bind_abi(&mut self) {
        self.program.templates = TiVec::new();
        self.program.abi = Default::default();
        // wire_templates names slots in the table just reset — stale the
        // moment templates is, whether or not a full IncrementalSession
        // rewind runs first.
        self.program.wire_templates.clear();

        for &(slot, module, type_name, ctor) in BINDINGS {
            let key = ModuleKey::of(&module.iter().map(|s| s.to_string()).collect());
            // Resolve through the static-stdlib fallback too: with a
            // precompiled stdlib every module's bytecode rides in the program
            // whether or not this compile imported it, so its constructors
            // must be bound. Only a truly unresolvable module (from-source
            // compile that never loaded it) may stay unbound — its ops were
            // never emitted.
            let Some(iface) = self.module_table.get_or_hydrate(&key) else {
                continue;
            };
            // From here on the module is present, so a missing type or
            // constructor is stdlib drift: the SCARLET source no longer matches
            // this registry. Surface it, naming the slot.
            let Some(ti) = iface.types.get(type_name).map(|et| et.info) else {
                self.abi_drift(slot, type_name, ctor, "type not found");
                continue;
            };
            let Some(variants) = ti.variants() else {
                self.abi_drift(slot, type_name, ctor, "type has no constructors");
                continue;
            };
            let found = self.engine.variants[variants.range()]
                .iter()
                .enumerate()
                .find(|(_, v)| self.engine.str(v.name) == ctor)
                .map(|(idx, v)| (idx, v.fields));
            let Some((variant_idx, fields)) = found else {
                self.abi_drift(slot, type_name, ctor, "constructor not found");
                continue;
            };
            let labels: Vec<&str> = self.engine.variant_fields[fields.range()]
                .iter()
                .map(|f| self.engine.str(f.label))
                .collect();
            if labels.len() != slot.arity() {
                self.abi_drift(slot, type_name, ctor, "constructor arity changed");
                continue;
            }
            let tpl = EnumTemplate::build(
                &mut self.frozen,
                ti.id,
                variant_idx as u16,
                type_name,
                ctor,
                &labels,
            );
            let idx = self.program.templates.push(tpl);
            self.program.abi.bind(slot, idx);
        }
        self.abi_template_count = self.program.templates.len();

        let missing = self
            .program
            .abi
            .unbound_for(self.program.code.iter().map(|i| i.op));
        if !missing.is_empty() {
            let names: Vec<&str> = missing.iter().map(|s| s.name()).collect();
            self.error(
                format!(
                    "internal: emitted ops construct unbound ABI slots: {}",
                    names.join(", ")
                ),
                ZERO_SPAN,
            );
        }
    }

    /// Mint one `EnumTemplate` per `WireVariant` across `descs`, extending
    /// `program.templates` past the ABI prefix `bind_abi` just fixed, and
    /// record where each one landed in `program.wire_templates` — keyed by
    /// the constructor identity a descriptor carries (`type_id`,
    /// `variant_idx`), the same identity `VariantRef` names and never a
    /// declared name: a renamed type, or two programs that declared the same
    /// shape independently, must still resolve to one template.
    ///
    /// Call after `bind_abi`, whose prefix length is what a rewind truncates
    /// `program.templates` back to (`IncrementalSession::reset_to`) — so a
    /// template minted here is exactly as session-scoped as an ABI one, and
    /// disappears the same way rather than surviving under a stale index.
    ///
    /// Idempotent across `descs`: two `WireVariant`s naming the same
    /// constructor — one type reachable through two different `wire.encode`/
    /// `wire.decode` call sites, say — mint one template, not two.
    ///
    /// `descs` is what elaboration built for the compile being emitted
    /// (`Compiler::wire_descs`), including the ones an imported module's own
    /// toplevel produced: they accumulate across module inits and are drained
    /// once, here, after `bind_abi`.
    pub(super) fn mint_wire_templates(&mut self, descs: &[crate::typed_ir::wire::Desc]) {
        for desc in descs {
            for variant in desc.variants() {
                let key = (variant.variant.type_id, variant.variant.variant_idx);
                if self.program.wire_templates.contains_key(&key) {
                    continue;
                }
                let type_name = self.engine.str(variant.variant.type_name);
                let ctor_name = self.engine.str(variant.name);
                let labels: Vec<&str> = variant
                    .fields
                    .iter()
                    .map(|f| self.engine.str(f.label))
                    .collect();
                let tpl = EnumTemplate::build(
                    &mut self.frozen,
                    variant.variant.type_id,
                    variant.variant.variant_idx,
                    type_name,
                    ctor_name,
                    &labels,
                );
                let idx = self.program.templates.push(tpl);
                self.program.wire_templates.insert(key, idx);
            }
        }
    }

    fn abi_drift(&mut self, slot: AbiSlot, type_name: &str, ctor: &str, what: &str) {
        self.error(
            format!(
                "internal: ABI slot {} binds {type_name}.{ctor}, but {what} — \
                 the stdlib no longer matches the compiler's ABI registry",
                slot.name()
            ),
            ZERO_SPAN,
        );
    }
}
