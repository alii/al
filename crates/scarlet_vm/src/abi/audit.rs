//! Checks [`slots_for`](crate::abi::slots_for)'s arms against what each op's
//! handler can actually construct, by reading this crate's own sources.
//!
//! `slots_for` being exhaustive over `Op` only makes an *omitted* op a compile
//! error. An op that is listed but whose arm understates its slots compiles,
//! and nothing else in the tree notices: `bind_abi` binds from the static
//! registry rather than from `slots_for`, so with a precompiled stdlib every
//! slot is bound whatever the arm says, and `AbiTable::unbound_for` — the one
//! consumer — just asks for less. The failure only appears in a from-source
//! compile, as a runtime `unbound slot` the compiler declined to predict.
//!
//! # The model
//!
//! An op's outcome value is built either in the handler the dispatch ladder
//! names, or in a continuation the handler selects with a token. The sweep
//! walks both:
//!
//! - **Dispatch.** Both ladders — the interpreter's `Op::X => …` in `vm/exec.rs`
//!   and the native bridge's `opc::X => …` in `vm/native_shims.rs` — give an
//!   op its entry functions. The two disagree in content: `Op::Print` builds
//!   nothing in the interpreter and a `Unit` in the bridge, which is why both
//!   are read.
//! - **Calls.** A `self.f()`, a free `f()`, a `m!()` and a method on a receiver
//!   rooted at `self` all resolve crate-wide by name. A method on any other
//!   receiver resolves only within its own file: without types, `frozen.value()`
//!   and `tokens.value(h1)` are one name.
//! - **Construction.** Naming `AbiSlot::X` builds `X`, except where the slot is
//!   only being named — `unbound(slot)` blames it, `is_abi(..)` tests against
//!   it. Reading a field of the pre-resolved [`H1`](crate::vm) bundle builds
//!   that field's slot; `vm/http.rs` constructs through the bundle and touches
//!   none of the eight constructors in `vm/exec.rs`.
//! - **Continuations.** A parked op returns before its value exists. `file_read`
//!   mints `BlockingOp::ReadFile` and `poll.rs`'s `completion_result` builds the
//!   value from `BlockingResult::ReadFile` much later, on the poller's stack.
//!   A pending connect wakes under `WakeAction::CompleteConnect` from either
//!   direction — writable fd or passed deadline — and the arm asks the socket
//!   which happened. Its consumers are *read off those arms* rather than named:
//!   the set was one function until `Op::TcpConnectUntil` made it two, and a
//!   name written down here is a blind spot the day it grows again.
//!   A monitor and a watch are the third: the op stores a closure, returns a
//!   handle, and the reason that closure is applied to is built when the
//!   target ends. [`NOTICE_REGISTRARS`] is that link's minting end, and it is
//!   keyed on the two handlers rather than on the reason's type because every
//!   other body naming an `Ended` is on the delivery side.
//! - **Arm selection.** Where a caller names `E::V` and its callee dispatches on
//!   `E`, only that arm counts. `tls_read` reaches `tls_error_value` only as
//!   `TlsFail::Io`, so it cannot build `TlsInvalidServerName`.
//!
//! # What this does not witness
//!
//! - **Which foreign errors a syscall can raise.** [`CLASSIFIERS`] map an errno
//!   or a rustls error onto a slot and are total over their input; that
//!   `read(2)` never returns `EADDRINUSE` is POSIX, not Rust, and is not in
//!   these sources. Slots named inside a classifier are therefore permitted,
//!   not required — an arm may list any subset of them. An errno this crate
//!   mints *itself* is the exception: [`ERRNO_MINTS`] carries it, and the slot
//!   it classifies to is required of every op that reaches the mint.
//! - **Which reason a given notice will carry.** The notice link gives a
//!   registrar every reason its consumers can build, because the op chooses
//!   neither when its target ends nor how. That a particular program's
//!   monitored process can only ever return normally is not in these sources.
//! - **An arm that overstates.** The check is one-directional: declaring a slot
//!   the handler cannot build costs a binding, not a crash.
//!
//! A blind spot that is *not* declared is a test failure:
//! [`every_construction_site_is_attributed_to_an_op`] fails when a slot is
//! built somewhere no op reaches, which is what an unmodelled edge looks like.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use crate::abi::{AbiSlot, slots_for};
use crate::bytecode::Op;

/// Functions that map a foreign error onto a slot. Total over their input, so
/// which of their outputs a given op can reach is not stated in this crate.
const CLASSIFIERS: &[&str] = &["classify_fs", "classify_net", "session_error_slot"];

/// Errors this crate mints itself, with the slot [`CLASSIFIERS`] map them to.
/// The errno is a literal in these sources rather than a syscall's to choose,
/// so an op reaching one of these *can* build that slot: [`reach`] takes it
/// back out of the permitted set, making it required like any other.
///
/// Keyed by the function that mints, and matched as a whole word rather than
/// as a call, because `listener_addr` passes `stale_socket` to `ok_or_else`
/// without calling it and [`call_edges`] needs a `(`.
///
/// Two further in-crate mints are deliberately absent: the sweep reaches
/// neither site, so requiring their slots would assert a coverage this model
/// does not have. `drain_write`'s `EPIPE` is called from the scrutinee of the
/// `match` whose arms its caller is selected by, and a selected callee is
/// never walked; `timed_out_offload`'s `ETIMEDOUT` is poller-side, past
/// [`REENTRY`]. Both were checked by hand: every op that reaches either
/// already declares the slot, so neither is a live gap.
const ERRNO_MINTS: &[(&str, AbiSlot)] = &[("stale_socket", AbiSlot::NetEnotconn)];

/// Where the sweep stops. Each of these hands control to the scheduler, the
/// blocking pool or the poller, which then runs *other* ops and other
/// processes; what they build is attributed to the op they dispatch, not to
/// the one that parked. Following them makes every op reach every slot.
const REENTRY: &[&str] = &[
    "park",
    "offload",
    "ensure_workers",
    "spawn_process",
    "reap_in_background",
    "resume",
    "wake_with",
    "run_slice",
    "execute_slice_budgeted",
    "scheduler_loop",
    "worker_main",
    "blocking_worker_main",
    "run_blocking",
    "spawn_blocking_worker",
    "terminate",
    "reap",
];

/// Construction sites no op reaches, each with the reason it does not. A site
/// that is not here and not reachable fails
/// [`every_construction_site_is_attributed_to_an_op`].
const UNATTRIBUTED: &[(&str, &str)] = &[(
    "resolve",
    "Templates::resolve binds the H1 bundle once at VM start; it is the \
     binding step, not an op's outcome",
)];

/// The blocking pool's mint/consume pair. A handler returns
/// `BlockingOp::V`; the poller builds the value in `completion_result`'s
/// `BlockingResult::V` arm. Asserted variant-for-variant by
/// [`the_continuation_model_still_matches_the_runtime`], so a new blocking op
/// cannot be added without this file noticing.
const BLOCKING_MINT: &str = "BlockingOp";
const BLOCKING_CONSUME: &str = "BlockingResult";
const BLOCKING_CONSUMER_FN: &str = "completion_result";

/// The poller's one non-rerun wake: a pending connect is finished by the
/// poller rather than by re-running its op. Which functions do that is derived
/// from the arms that match it — see [`wake_complete_consumers`].
const WAKE_ENUM: &str = "WakeAction";
const WAKE_COMPLETE: &str = "CompleteConnect";
/// The file those arms live in.
const WAKE_FILE: &str = "poll.rs";
/// Every other wake re-runs the op's own handler, which the call walk already
/// covers. Asserted so a third action fails here.
const WAKE_RERUN: &str = "Rerun";

/// The notice link's minting end. Both handlers store a closure to be started
/// when their target ends; the value it is applied to is built there and then,
/// past [`REENTRY`], so neither op reaches it by call.
///
/// Keyed on the two handlers rather than on the registration's type because
/// every *other* body naming an `Ended` — `incarnation_exited`,
/// `request_restart`, `free_entry` — is on the delivery side, and linking
/// those would hand the same eleven reasons to every supervision op, which is
/// what [`REENTRY`] exists to prevent. Nothing but the two dispatch ladders
/// calls either registrar, and that is what keeps the link this narrow:
/// [`the_continuation_model_still_matches_the_runtime`] asserts it.
const NOTICE_REGISTRARS: &[&str] = &["process_monitor", "watch_new"];

/// What builds a notice's payload, with the enum each is total over. Walked
/// with every arm live: a registrar chooses neither when its target ends nor
/// how, so it reaches all of them. Totality is asserted, which is what bounds
/// the set to these three — a fourth reason cannot be added to `Exit`,
/// `Crash` or `Ended` without failing that check.
const NOTICE_CONSUMERS: &[(&str, &str)] = &[
    ("exit_reason", "Exit"),
    ("crash_value", "Crash"),
    ("fire_watch", "Ended"),
];

/// Slot mentions that name a slot without building one.
const NAMING_ONLY: &[&str] = &["unbound", "is_abi"];

/// This file. It defines names that collide with the crate's (`resolve`,
/// `entries`) and is the analyser, not the analysed.
const SELF_FILE: &str = "audit.rs";

// ---------------------------------------------------------------------------
// source text
// ---------------------------------------------------------------------------

struct Source {
    name: String,
    text: Vec<u8>,
}

fn read_sources() -> Vec<Source> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut out = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("the audit needs this crate's sources: {dir:?}: {e}"));
        for e in entries {
            let p = e.expect("dir entry").path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                let name = p.file_name().unwrap().to_string_lossy().into_owned();
                if name == SELF_FILE {
                    continue;
                }
                let raw = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{p:?}: {e}"));
                out.push(Source {
                    name,
                    text: blank_test_mods(strip_literals(raw.as_bytes())),
                });
            }
        }
    }
    assert!(
        out.len() > 10,
        "read {} sources under {root:?}; the audit is reading the wrong tree",
        out.len()
    );
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Blank comments and string/char literals in place, so a slot name inside a
/// doc comment or a message is not a construction. Length and newlines are
/// preserved, which keeps every offset usable.
fn strip_literals(src: &[u8]) -> Vec<u8> {
    let mut out = src.to_vec();
    let n = src.len();
    let mut i = 0;
    let blank = |out: &mut Vec<u8>, a: usize, b: usize| {
        for c in out[a..b.min(n)].iter_mut() {
            if *c != b'\n' {
                *c = b' ';
            }
        }
    };
    while i < n {
        match src[i] {
            b'/' if i + 1 < n && src[i + 1] == b'/' => {
                let j = src[i..]
                    .iter()
                    .position(|&c| c == b'\n')
                    .map_or(n, |k| i + k);
                blank(&mut out, i, j);
                i = j;
            }
            b'/' if i + 1 < n && src[i + 1] == b'*' => {
                let (mut d, mut j) = (1usize, i + 2);
                while j < n && d > 0 {
                    if src[j] == b'/' && j + 1 < n && src[j + 1] == b'*' {
                        d += 1;
                        j += 2;
                    } else if src[j] == b'*' && j + 1 < n && src[j + 1] == b'/' {
                        d -= 1;
                        j += 2;
                    } else {
                        j += 1;
                    }
                }
                blank(&mut out, i, j);
                i = j;
            }
            // A raw string, possibly hashed. `b` and `br` prefixes land here
            // through their `r`.
            b'r' if i + 1 < n && (src[i + 1] == b'#' || src[i + 1] == b'"') => {
                let mut j = i + 1;
                let mut hashes = 0;
                while j < n && src[j] == b'#' {
                    hashes += 1;
                    j += 1;
                }
                if j < n && src[j] == b'"' {
                    let mut k = j + 1;
                    let end = loop {
                        if k >= n {
                            break n;
                        }
                        if src[k] == b'"' && src[k + 1..].iter().take(hashes).all(|&c| c == b'#') {
                            break (k + 1 + hashes).min(n);
                        }
                        k += 1;
                    };
                    blank(&mut out, i, end);
                    i = end;
                } else {
                    i += 1;
                }
            }
            b'"' => {
                let mut j = i + 1;
                while j < n {
                    if src[j] == b'\\' {
                        j += 2;
                    } else if src[j] == b'"' {
                        j += 1;
                        break;
                    } else {
                        j += 1;
                    }
                }
                blank(&mut out, i, j);
                i = j;
            }
            // A char literal is `'x'` or `'\n'`; anything else beginning with a
            // quote is a lifetime and must stay, or `'a>` swallows the code
            // after it.
            b'\'' => {
                if i + 1 < n && src[i + 1] == b'\\' {
                    let j = src[i + 2..]
                        .iter()
                        .position(|&c| c == b'\'')
                        .map_or(n, |k| i + 2 + k + 1);
                    blank(&mut out, i, j);
                    i = j;
                } else if i + 2 < n && src[i + 2] == b'\'' {
                    blank(&mut out, i, i + 3);
                    i += 3;
                } else {
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }
    out
}

/// Blank the body of every inline `#[cfg(test)] mod x { .. }`. A test that
/// builds a slot is not an op constructing one, and a test helper sharing a
/// handler's name would merge into it.
///
/// Only an inline module is blanked. `#[cfg(test)] mod x;` declares a file and
/// its brace is the *next unrelated* one, so treating the two alike blanks an
/// arbitrary region of live code — the attribute on this module's own
/// declaration used to erase the whole of `AbiSlot`.
fn blank_test_mods(mut src: Vec<u8>) -> Vec<u8> {
    const ATTR: &[u8] = b"#[cfg(test)]";
    let mut i = 0;
    while let Some(p) = find(&src, i, ATTR) {
        i = p + ATTR.len();
        let mut k = skip_ws(&src, i);
        if src[k..].starts_with(b"pub") {
            k = skip_ws(&src, k + 3);
        }
        if !src[k..].starts_with(b"mod") {
            continue;
        }
        k = skip_ws(&src, k + 3);
        while k < src.len() && is_ident_byte(src[k]) {
            k += 1;
        }
        let open = skip_ws(&src, k);
        if open >= src.len() || src[open] != b'{' {
            continue;
        }
        let end = match_brace(&src, open);
        for b in src[p..end].iter_mut() {
            if *b != b'\n' {
                *b = b' ';
            }
        }
        i = end;
    }
    src
}

fn find(h: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    if from >= h.len() {
        return None;
    }
    h[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|k| from + k)
}

/// Whether `body` names `word` as a whole identifier, called or not.
fn names_word(body: &[u8], word: &str) -> bool {
    let w = word.as_bytes();
    let mut i = 0;
    while let Some(p) = find(body, i, w) {
        i = p + 1;
        let after = p + w.len();
        if (p == 0 || !is_ident_byte(body[p - 1]))
            && (after >= body.len() || !is_ident_byte(body[after]))
        {
            return true;
        }
    }
    false
}

/// `open` indexes a `{`; the index just past its `}`.
fn match_brace(s: &[u8], open: usize) -> usize {
    let mut d = 0usize;
    for (i, &c) in s.iter().enumerate().skip(open) {
        if c == b'{' {
            d += 1;
        } else if c == b'}' {
            d -= 1;
            if d == 0 {
                return i + 1;
            }
        }
    }
    s.len()
}

fn is_ident_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// The identifier ending just before `i`, skipping whitespace.
fn ident_before(s: &[u8], i: usize) -> Option<(usize, usize)> {
    let mut e = i;
    while e > 0 && s[e - 1].is_ascii_whitespace() {
        e -= 1;
    }
    let mut b = e;
    while b > 0 && is_ident_byte(s[b - 1]) {
        b -= 1;
    }
    (b < e && !s[b].is_ascii_digit()).then_some((b, e))
}

fn skip_ws(s: &[u8], mut i: usize) -> usize {
    while i < s.len() && s[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

/// The extent of a match arm's body, given the index just past its `=>`:
/// a block, or everything up to the next comma outside brackets.
fn arm_extent(s: &[u8], from: usize) -> (usize, usize) {
    let i = skip_ws(s, from);
    if i < s.len() && s[i] == b'{' {
        return (i, match_brace(s, i));
    }
    let mut d = 0i32;
    let mut e = i;
    while e < s.len() {
        match s[e] {
            b'(' | b'[' | b'{' => d += 1,
            b')' | b']' | b'}' => {
                if d == 0 {
                    break;
                }
                d -= 1;
            }
            b',' if d == 0 => break,
            _ => {}
        }
        e += 1;
    }
    (i, e)
}

// ---------------------------------------------------------------------------
// what a body says
// ---------------------------------------------------------------------------

/// Every `A::B` in `body`, uppercase-initial on both halves — an enum variant
/// or an associated item, which is as far as this needs to tell them apart.
fn paths(body: &[u8]) -> Vec<(String, String, usize, usize)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < body.len() {
        if !is_ident_byte(body[i]) || (i > 0 && is_ident_byte(body[i - 1])) {
            i += 1;
            continue;
        }
        let b = i;
        while i < body.len() && is_ident_byte(body[i]) {
            i += 1;
        }
        if !body[b].is_ascii_uppercase() {
            continue;
        }
        let j = skip_ws(body, i);
        if j + 1 >= body.len() || body[j] != b':' || body[j + 1] != b':' {
            continue;
        }
        let k = skip_ws(body, j + 2);
        let mut e = k;
        while e < body.len() && is_ident_byte(body[e]) {
            e += 1;
        }
        if e > k && body[k].is_ascii_uppercase() {
            out.push((
                String::from_utf8_lossy(&body[b..i]).into_owned(),
                String::from_utf8_lossy(&body[k..e]).into_owned(),
                b,
                e,
            ));
            i = e;
        }
    }
    out
}

/// Whether the path ending at `end` heads a match arm: optional payload
/// pattern, then `=>`, or `|` and another path that does. Returns the index
/// just past the `=>`.
fn arm_head_at(body: &[u8], end: usize) -> Option<usize> {
    let mut i = skip_ws(body, end);
    // `Variant(..)` or `Variant { .. }`
    if i < body.len() && (body[i] == b'(' || body[i] == b'{') {
        let close = if body[i] == b'(' { b')' } else { b'}' };
        let open = body[i];
        let mut d = 0i32;
        while i < body.len() {
            if body[i] == open {
                d += 1;
            } else if body[i] == close {
                d -= 1;
                if d == 0 {
                    i += 1;
                    break;
                }
            }
            i += 1;
        }
        i = skip_ws(body, i);
    }
    if i + 1 < body.len() && body[i] == b'=' && body[i + 1] == b'>' {
        return Some(i + 2);
    }
    if i < body.len() && body[i] == b'|' {
        // The next path in the or-pattern decides for all of them.
        let rest = &body[i..];
        let p = paths(rest).into_iter().next()?;
        return arm_head_at(body, i + p.3);
    }
    None
}

/// The body of the match arm whose *pattern* holds the path ending at `end`,
/// or `None` when that occurrence is not in a pattern. The same path spells a
/// struct literal in `Wait::connecting` and a bare variant in the enum
/// declaration, and neither is an arm.
fn enclosing_arm(s: &[u8], end: usize) -> Option<(usize, usize)> {
    let bare = skip_ws(s, end);
    if s[bare..].starts_with(b"=>") {
        return Some(arm_extent(s, bare + 2));
    }
    let mut d = 0i32;
    let mut j = end;
    while j + 1 < s.len() {
        match s[j] {
            b'(' | b'[' | b'{' => d += 1,
            b')' | b']' | b'}' => {
                d -= 1;
                // Out of the pattern's own brackets: an arm has `=>` here, or
                // `|` and more alternatives before it.
                if d < 0 {
                    let k = skip_ws(s, j + 1);
                    if s[k..].starts_with(b"=>") {
                        return Some(arm_extent(s, k + 2));
                    }
                    if k >= s.len() || s[k] != b'|' {
                        return None;
                    }
                    let mut m = k;
                    while m + 1 < s.len() {
                        if s[m] == b'=' && s[m + 1] == b'>' {
                            return Some(arm_extent(s, m + 2));
                        }
                        if s[m] == b';' {
                            return None;
                        }
                        m += 1;
                    }
                    return None;
                }
            }
            _ => {}
        }
        j += 1;
    }
    None
}

/// A named body: every `fn` and every `macro_rules!`. Trait signatures without
/// a body are skipped.
struct Def {
    name: String,
    file: usize,
    body: Vec<u8>,
}

fn defs_in(file: usize, s: &[u8]) -> Vec<Def> {
    let mut out = Vec::new();
    for (kw, is_macro) in [(&b"fn "[..], false), (&b"macro_rules!"[..], true)] {
        let mut i = 0;
        while let Some(p) = find(s, i, kw) {
            i = p + kw.len();
            if p > 0 && is_ident_byte(s[p - 1]) {
                continue;
            }
            let b = skip_ws(s, p + kw.len());
            let mut e = b;
            while e < s.len() && is_ident_byte(s[e]) {
                e += 1;
            }
            if e == b {
                continue;
            }
            let open = if is_macro {
                match s[e..].iter().position(|&c| c == b'{') {
                    Some(k) => e + k,
                    None => continue,
                }
            } else {
                // The body brace, at bracket depth zero. `;` first means a
                // signature with no body.
                let (mut pd, mut bd, mut k) = (0i32, 0i32, e);
                loop {
                    if k >= s.len() {
                        break;
                    }
                    match s[k] {
                        b'(' => pd += 1,
                        b')' => pd -= 1,
                        b'[' => bd += 1,
                        b']' => bd -= 1,
                        b';' if pd == 0 && bd == 0 => {
                            k = s.len();
                            break;
                        }
                        b'{' if pd == 0 && bd == 0 => break,
                        _ => {}
                    }
                    k += 1;
                }
                if k >= s.len() {
                    continue;
                }
                k
            };
            out.push(Def {
                name: String::from_utf8_lossy(&s[b..e]).into_owned(),
                file,
                body: s[open..match_brace(s, open)].to_vec(),
            });
        }
    }
    out
}

/// Call edges out of `body`. A `self.f()`, a free `f()`, a `m!()` and a method
/// on a receiver rooted at `self` resolve crate-wide; a method on any other
/// receiver resolves only among `local`.
fn call_edges(body: &[u8], local: &BTreeSet<String>, all: &BTreeSet<String>) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut i = 0;
    while i < body.len() {
        if !is_ident_byte(body[i])
            || (i > 0 && is_ident_byte(body[i - 1]))
            || body[i].is_ascii_digit()
        {
            i += 1;
            continue;
        }
        let b = i;
        while i < body.len() && is_ident_byte(body[i]) {
            i += 1;
        }
        let mut j = skip_ws(body, i);
        if j < body.len() && body[j] == b'!' {
            j = skip_ws(body, j + 1);
        }
        if j >= body.len() || !matches!(body[j], b'(' | b'[' | b'{') {
            continue;
        }
        // `{` only counts for a macro invocation, not for `if cond {`.
        if body[j] == b'{'
            && !(i < body.len() && skip_ws(body, i) < body.len() && body[skip_ws(body, i)] == b'!')
        {
            continue;
        }
        if body[j] == b'[' && !(skip_ws(body, i) < body.len() && body[skip_ws(body, i)] == b'!') {
            continue;
        }
        let name = String::from_utf8_lossy(&body[b..i]).into_owned();
        let mut k = b;
        while k > 0 && body[k - 1].is_ascii_whitespace() {
            k -= 1;
        }
        let is_method = k > 0 && body[k - 1] == b'.' && !(k > 1 && body[k - 2] == b'.');
        if !is_method {
            if all.contains(&name) {
                out.insert(name);
            }
            continue;
        }
        // Walk the receiver chain back looking for `self`.
        let mut rooted = false;
        let mut at = k - 1;
        while let Some((sb, se)) = ident_before(body, at) {
            if &body[sb..se] == b"self" {
                rooted = true;
                break;
            }
            let mut prev = sb;
            while prev > 0 && body[prev - 1].is_ascii_whitespace() {
                prev -= 1;
            }
            if prev == 0 || body[prev - 1] != b'.' {
                break;
            }
            at = prev - 1;
        }
        if (rooted && all.contains(&name)) || local.contains(&name) {
            out.insert(name);
        }
    }
    out
}

/// The slots `body` builds: every `AbiSlot::X` that is not merely named, plus
/// every read of an `H1` field.
fn built_slots(
    body: &[u8],
    variants: &BTreeMap<String, AbiSlot>,
    h1: &BTreeMap<String, AbiSlot>,
) -> BTreeSet<AbiSlot> {
    let mut out = BTreeSet::new();
    for (a, b, start, _) in paths(body) {
        if a != "AbiSlot" {
            continue;
        }
        let Some(&slot) = variants.get(&b) else {
            continue;
        };
        // `unbound(AbiSlot::X)` / `is_abi(.., AbiSlot::X, ..)`: the slot an
        // error blames, or one a renderer tests against.
        let mut k = start;
        while k > 0 && (body[k - 1].is_ascii_whitespace() || body[k - 1] == b',') {
            k -= 1;
        }
        let naming = if k > 0 && body[k - 1] == b'(' {
            ident_before(body, k - 1).is_some_and(|(b0, e0)| {
                NAMING_ONLY.contains(&String::from_utf8_lossy(&body[b0..e0]).as_ref())
            })
        } else if k > 0 {
            // `is_abi(program, AbiSlot::X, ..)` — one argument in.
            ident_before(body, k)
                .and_then(|(b0, _)| (b0 > 0).then_some(b0))
                .and_then(|b0| {
                    let mut m = b0;
                    while m > 0 && (body[m - 1].is_ascii_whitespace() || body[m - 1] == b'(') {
                        m -= 1;
                    }
                    ident_before(body, m)
                })
                .is_some_and(|(b0, e0)| {
                    NAMING_ONLY.contains(&String::from_utf8_lossy(&body[b0..e0]).as_ref())
                })
        } else {
            false
        };
        if !naming {
            out.insert(slot);
        }
    }
    let mut i = 0;
    while i < body.len() {
        if body[i] != b'.' || (i + 1 < body.len() && body[i + 1] == b'.') {
            i += 1;
            continue;
        }
        let b = skip_ws(body, i + 1);
        let mut e = b;
        while e < body.len() && is_ident_byte(body[e]) {
            e += 1;
        }
        if e > b
            && let Some(&slot) = h1.get(String::from_utf8_lossy(&body[b..e]).as_ref())
        {
            out.insert(slot);
        }
        i = e.max(i + 1);
    }
    out
}

// ---------------------------------------------------------------------------
// the graph
// ---------------------------------------------------------------------------

/// What each arm of a body's match on an enum builds and calls, keyed by the
/// enum and then the variant.
type Arms = BTreeMap<String, BTreeMap<String, (BTreeSet<AbiSlot>, BTreeSet<String>)>>;

struct Node {
    slots: BTreeSet<AbiSlot>,
    calls: BTreeSet<String>,
    mints: BTreeSet<(String, String)>,
    /// enum -> variant -> what that arm builds and calls.
    arms: Arms,
}

struct Graph {
    nodes: BTreeMap<String, Node>,
    /// Keyed by opcode discriminant: `Op` is not `Ord`.
    entries: BTreeMap<u8, BTreeSet<String>>,
    /// Slots named directly in a dispatch arm rather than in a called function.
    inline: BTreeMap<u8, BTreeSet<AbiSlot>>,
    /// Opcodes a ladder arm was found for, empty body or not. `Op::Nop => {}`
    /// contributes nothing and is still covered.
    covered: BTreeSet<u8>,
    /// What the poller calls on a `WakeAction::CompleteConnect` wake.
    wake_complete: BTreeSet<String>,
    sources: Vec<Source>,
}

fn source<'a>(sources: &'a [Source], name: &str) -> &'a [u8] {
    &sources
        .iter()
        .find(|s| s.name == name)
        .unwrap_or_else(|| panic!("{name} is not in this crate any more"))
        .text
}

/// Every variant of `enum`, in declaration order.
fn enum_variants(sources: &[Source], name: &str) -> Vec<String> {
    let needle = format!("enum {name}");
    for s in sources {
        let Some(p) = find(&s.text, 0, needle.as_bytes()) else {
            continue;
        };
        let Some(open) = s.text[p..].iter().position(|&c| c == b'{').map(|k| p + k) else {
            continue;
        };
        let body = &s.text[open + 1..match_brace(&s.text, open) - 1];
        let mut out = Vec::new();
        let (mut d, mut i) = (0i32, 0usize);
        while i < body.len() {
            match body[i] {
                b'(' | b'[' | b'{' | b'<' => d += 1,
                b')' | b']' | b'}' | b'>' => d -= 1,
                _ => {}
            }
            if d == 0 && body[i].is_ascii_uppercase() && (i == 0 || !is_ident_byte(body[i - 1])) {
                let b = i;
                while i < body.len() && is_ident_byte(body[i]) {
                    i += 1;
                }
                let j = skip_ws(body, i);
                if j >= body.len() || matches!(body[j], b',' | b'(' | b'{') {
                    out.push(String::from_utf8_lossy(&body[b..i]).into_owned());
                }
                continue;
            }
            i += 1;
        }
        return out;
    }
    panic!("enum {name} is not in this crate any more");
}

/// Every function the poller reaches from an arm matching
/// `WakeAction::CompleteConnect`. Read off the arms because the set grows: a
/// writable fd goes to `finish_connect` and a passed deadline to
/// `timeout_connect`, and the second only appeared with `Op::TcpConnectUntil`.
fn wake_complete_consumers(
    poll: &[u8],
    local: &BTreeSet<String>,
    all: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for (a, b, _, end) in paths(poll) {
        if a != WAKE_ENUM || b != WAKE_COMPLETE {
            continue;
        }
        if let Some((s, e)) = enclosing_arm(poll, end) {
            out.extend(call_edges(&poll[s..e], local, all));
        }
    }
    out
}

fn build() -> Graph {
    let sources = read_sources();

    let variants: BTreeMap<String, AbiSlot> = AbiSlot::ALL
        .iter()
        .map(|s| (s.name().to_string(), *s))
        .collect();

    // H1 field -> slot, read off `Templates::resolve`'s initialiser. The bundle
    // is how `vm/http.rs` constructs; nothing there calls a slot by name.
    let tm = source(&sources, "templates.rs");
    let mut h1: BTreeMap<String, AbiSlot> = BTreeMap::new();
    for (a, b, start, _) in paths(tm) {
        if a != "AbiSlot" {
            continue;
        }
        let Some(&slot) = variants.get(&b) else {
            continue;
        };
        // `field: get(AbiSlot::X)?` or `let field = nullary(AbiSlot::X)?`
        let mut k = start;
        while k > 0 && (tm[k - 1].is_ascii_whitespace() || tm[k - 1] == b'(') {
            k -= 1;
        }
        let Some((gb, ge)) = ident_before(tm, k) else {
            continue;
        };
        if !matches!(&tm[gb..ge], b"get" | b"nullary") {
            continue;
        }
        let mut m = gb;
        while m > 0 && (tm[m - 1].is_ascii_whitespace() || tm[m - 1] == b':' || tm[m - 1] == b'=') {
            m -= 1;
        }
        if let Some((fb, fe)) = ident_before(tm, m) {
            let f = String::from_utf8_lossy(&tm[fb..fe]).into_owned();
            if f != "let" && !f.is_empty() && tm[fb].is_ascii_lowercase() {
                h1.insert(f, slot);
            }
        }
    }
    assert!(
        h1.len() > 20,
        "mapped {} H1 fields; Templates::resolve has changed shape",
        h1.len()
    );

    // Every named body in the crate.
    let mut defs: Vec<Def> = Vec::new();
    for (i, s) in sources.iter().enumerate() {
        defs.extend(defs_in(i, &s.text));
    }
    let all: BTreeSet<String> = defs.iter().map(|d| d.name.clone()).collect();
    let mut per_file: Vec<BTreeSet<String>> = vec![BTreeSet::new(); sources.len()];
    for d in &defs {
        per_file[d.file].insert(d.name.clone());
    }

    let mut nodes: BTreeMap<String, Node> = BTreeMap::new();
    for d in &defs {
        let n = nodes.entry(d.name.clone()).or_insert_with(|| Node {
            slots: BTreeSet::new(),
            calls: BTreeSet::new(),
            mints: BTreeSet::new(),
            arms: BTreeMap::new(),
        });
        n.slots.extend(built_slots(&d.body, &variants, &h1));
        n.calls.extend(call_edges(&d.body, &per_file[d.file], &all));
        for (a, b, _, end) in paths(&d.body) {
            n.mints.insert((a.clone(), b.clone()));
            let Some(past) = arm_head_at(&d.body, end) else {
                continue;
            };
            let (s, e) = arm_extent(&d.body, past);
            let arm = &d.body[s..e];
            let entry = n
                .arms
                .entry(a)
                .or_default()
                .entry(b)
                .or_insert_with(|| (BTreeSet::new(), BTreeSet::new()));
            entry.0.extend(built_slots(arm, &variants, &h1));
            entry.1.extend(call_edges(arm, &per_file[d.file], &all));
        }
    }

    // The mint builds its slot, and a body that merely names one gets the edge
    // `call_edges` cannot see. Missing means renamed, which would silently
    // return the slot to the permitted set.
    for (mint, slot) in ERRNO_MINTS {
        let n = nodes.get_mut(*mint).unwrap_or_else(|| {
            panic!("{mint} mints an errno and is gone from this crate; ERRNO_MINTS is stale")
        });
        n.slots.insert(*slot);
    }
    for d in &defs {
        for (mint, _) in ERRNO_MINTS {
            if d.name != *mint
                && names_word(&d.body, mint)
                && let Some(n) = nodes.get_mut(&d.name)
            {
                n.calls.insert((*mint).to_string());
            }
        }
    }
    // An enum with one arm in a body is a `let ... = E::V` destructure, not a
    // dispatch; selecting on it would drop the other paths.
    for n in nodes.values_mut() {
        n.arms.retain(|_, v| v.len() > 1);
    }

    // The two dispatch ladders.
    let mut entries: BTreeMap<u8, BTreeSet<String>> = BTreeMap::new();
    let mut inline: BTreeMap<u8, BTreeSet<AbiSlot>> = BTreeMap::new();
    let mut covered: BTreeSet<u8> = BTreeSet::new();
    let by_name: BTreeMap<String, Op> = (0..=u8::MAX)
        .filter_map(Op::from_u8)
        .map(|o| (format!("{o:?}"), o))
        .collect();

    let ex = source(&sources, "exec.rs");
    for (a, b, _, end) in paths(ex) {
        if a != "Op" {
            continue;
        }
        let Some(&op) = by_name.get(&b) else { continue };
        let Some(past) = arm_head_at(ex, end) else {
            continue;
        };
        let (s, e) = arm_extent(ex, past);
        covered.insert(op as u8);
        entries
            .entry(op as u8)
            .or_default()
            .extend(call_edges(&ex[s..e], &BTreeSet::new(), &all));
        inline
            .entry(op as u8)
            .or_default()
            .extend(built_slots(&ex[s..e], &variants, &h1));
    }

    // The bridge matches on `opc::NAME`, a `u8` const per opcode.
    let sh = source(&sources, "native_shims.rs");
    let mut opc: BTreeMap<String, Op> = BTreeMap::new();
    for (a, b, _, _) in paths(sh) {
        if a != "Op" {
            continue;
        }
        // `pub const NAME: u8 = Op::X as u8;`
        let Some(&op) = by_name.get(&b) else { continue };
        let hay = format!("= Op::{b} as u8");
        if let Some(p) = find(sh, 0, hay.as_bytes()) {
            let mut k = p;
            while k > 0 && sh[k - 1] != b':' {
                k -= 1;
            }
            if let Some((nb, ne)) = ident_before(sh, k.saturating_sub(1)) {
                opc.insert(String::from_utf8_lossy(&sh[nb..ne]).into_owned(), op);
            }
        }
    }
    let mut i = 0;
    while let Some(p) = find(sh, i, b"opc::") {
        i = p + 5;
        let mut e = i;
        while e < sh.len() && is_ident_byte(sh[e]) {
            e += 1;
        }
        let name = String::from_utf8_lossy(&sh[i..e]).into_owned();
        let Some(&op) = opc.get(&name) else { continue };
        let Some(past) = arm_head_at(sh, e) else {
            continue;
        };
        let (s, en) = arm_extent(sh, past);
        covered.insert(op as u8);
        entries
            .entry(op as u8)
            .or_default()
            .extend(call_edges(&sh[s..en], &BTreeSet::new(), &all));
        inline
            .entry(op as u8)
            .or_default()
            .extend(built_slots(&sh[s..en], &variants, &h1));
    }

    let wake_file = sources
        .iter()
        .position(|s| s.name == WAKE_FILE)
        .unwrap_or_else(|| panic!("{WAKE_FILE} is not in this crate any more"));
    let wake_complete =
        wake_complete_consumers(&sources[wake_file].text, &per_file[wake_file], &all);

    Graph {
        nodes,
        entries,
        inline,
        covered,
        wake_complete,
        sources,
    }
}

/// What `op` can build, split into what it must declare and what it may.
fn reach(g: &Graph, op: Op) -> (BTreeSet<AbiSlot>, BTreeSet<AbiSlot>, BTreeSet<String>) {
    let mut strict: BTreeSet<AbiSlot> = g.inline.get(&(op as u8)).cloned().unwrap_or_default();
    let mut loose = BTreeSet::new();
    let mut minted: BTreeSet<AbiSlot> = BTreeSet::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut stack: Vec<String> = g
        .entries
        .get(&(op as u8))
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .collect();

    let blocking_arms = g
        .nodes
        .get(BLOCKING_CONSUMER_FN)
        .and_then(|n| n.arms.get(BLOCKING_CONSUME));

    while let Some(name) = stack.pop() {
        if !seen.insert(name.clone()) || REENTRY.contains(&name.as_str()) {
            continue;
        }
        let Some(node) = g.nodes.get(&name) else {
            continue;
        };
        if CLASSIFIERS.contains(&name.as_str()) {
            loose.extend(node.slots.iter().copied());
            continue;
        }
        strict.extend(node.slots.iter().copied());
        if let Some((_, slot)) = ERRNO_MINTS.iter().find(|(m, _)| *m == name) {
            minted.insert(*slot);
        }

        // Registration is the token: take each payload builder whole, arms and
        // all. Going through the stack instead would let an arm-selected edge
        // reach the same function first and mark it seen, leaving the walk with
        // only the one arm the registrar happened to name — `watch_new` calls
        // `fire_watch` directly as `Ended::AlreadyGone`.
        if NOTICE_REGISTRARS.contains(&name.as_str()) {
            for (consumer, _) in NOTICE_CONSUMERS {
                let Some(c) = g.nodes.get(*consumer) else {
                    continue;
                };
                seen.insert((*consumer).to_string());
                strict.extend(c.slots.iter().copied());
                stack.extend(c.calls.iter().cloned());
            }
        }

        for (e, v) in &node.mints {
            if e == BLOCKING_MINT
                && let Some((s, c)) = blocking_arms.and_then(|a| a.get(v))
            {
                strict.extend(s.iter().copied());
                stack.extend(c.iter().cloned());
            }
            if e == WAKE_ENUM && v == WAKE_COMPLETE {
                stack.extend(g.wake_complete.iter().cloned());
            }
        }

        for callee in &node.calls {
            let selected = g.nodes.get(callee).and_then(|c| {
                c.arms.iter().find_map(|(en, tbl)| {
                    let named: Vec<&String> = node
                        .mints
                        .iter()
                        .filter(|(e2, v)| e2 == en && tbl.contains_key(v))
                        .map(|(_, v)| v)
                        .collect();
                    (!named.is_empty()).then_some((tbl, named))
                })
            });
            match selected {
                None => stack.push(callee.clone()),
                Some((tbl, named)) => {
                    seen.insert(callee.clone());
                    for v in named {
                        let (s, c) = &tbl[v];
                        strict.extend(s.iter().copied());
                        stack.extend(c.iter().cloned());
                    }
                }
            }
        }
    }
    // This op reached the mint, so the errno is this crate's and the slot is
    // required of it — whatever the syscall on the same path could return.
    for s in &minted {
        loose.remove(s);
    }
    (strict, loose, seen)
}

// ---------------------------------------------------------------------------
// the tests
// ---------------------------------------------------------------------------

/// The model's own inputs. Each of these is a shape the sweep assumes; a
/// change to any of them must reach this file rather than silently narrow it.
#[test]
fn the_continuation_model_still_matches_the_runtime() {
    let g = build();

    let mint: BTreeSet<String> = enum_variants(&g.sources, BLOCKING_MINT)
        .into_iter()
        .collect();
    let consume: Vec<String> = enum_variants(&g.sources, BLOCKING_CONSUME);
    let consume_set: BTreeSet<String> = consume.iter().cloned().collect();
    assert_eq!(
        mint, consume_set,
        "{BLOCKING_MINT} and {BLOCKING_CONSUME} no longer pair variant for \
         variant, so a parked op's outcome is not attributed to it"
    );
    let arms = g
        .nodes
        .get(BLOCKING_CONSUMER_FN)
        .and_then(|n| n.arms.get(BLOCKING_CONSUME))
        .unwrap_or_else(|| {
            panic!("{BLOCKING_CONSUMER_FN} no longer dispatches on {BLOCKING_CONSUME}")
        });
    let armed: BTreeSet<&String> = arms.keys().collect();
    let expect: BTreeSet<&String> = consume.iter().collect();
    assert_eq!(
        armed, expect,
        "{BLOCKING_CONSUMER_FN} does not build every {BLOCKING_CONSUME}"
    );

    let wake: BTreeSet<String> = enum_variants(&g.sources, WAKE_ENUM).into_iter().collect();
    assert_eq!(
        wake,
        BTreeSet::from([WAKE_COMPLETE.to_string(), WAKE_RERUN.to_string()]),
        "{WAKE_ENUM} gained an action; a wake that neither re-runs the op nor \
         finishes a connect is a continuation this sweep does not follow"
    );
    // Derived, so it cannot go stale — but it can go empty, and an empty set
    // silently unhooks every connect outcome. Require that it still reaches a
    // function that builds one.
    assert!(
        g.wake_complete
            .iter()
            .any(|f| g.nodes.get(f).is_some_and(|n| !n.slots.is_empty())),
        "no arm matching {WAKE_ENUM}::{WAKE_COMPLETE} in {WAKE_FILE} reaches a \
         function that builds a slot; found {:?}. The poller finishes a connect \
         somewhere this sweep can no longer see.",
        g.wake_complete
    );

    // The notice link. Each consumer is total over the enum it dispatches on,
    // so a new way for a process to end reaches this file rather than becoming
    // a reason no op is checked against.
    for (f, en) in NOTICE_CONSUMERS {
        let arms = g
            .nodes
            .get(*f)
            .and_then(|n| n.arms.get(*en))
            .unwrap_or_else(|| panic!("{f} no longer dispatches on {en}"));
        let variants = enum_variants(&g.sources, en);
        let armed: BTreeSet<&String> = arms.keys().collect();
        let expect: BTreeSet<&String> = variants.iter().collect();
        assert_eq!(armed, expect, "{f} does not build every {en}");
    }
    // A registrar is a written-down name, so it can rot two ways: the handler
    // is renamed, or it stops being what its ladder arm calls. Either leaves
    // the link minting nothing and the reasons unattributed again.
    let linked: BTreeSet<String> = [Op::ProcessMonitor, Op::WatchNew]
        .into_iter()
        .flat_map(|o| reach(&g, o).2)
        .collect();
    for r in NOTICE_REGISTRARS {
        assert!(
            g.nodes.contains_key(*r),
            "notice registrar {r} is not in this crate any more"
        );
        assert!(
            linked.contains(*r),
            "{r} is no longer reached from Op::ProcessMonitor or Op::WatchNew, \
             so the notice link mints nothing for it"
        );
    }
    // And the link stays narrow only because nothing else calls a registrar.
    // A third caller would give its op all eleven reasons silently.
    let stray: Vec<String> = (0..=u8::MAX)
        .filter_map(Op::from_u8)
        .filter(|o| !matches!(o, Op::ProcessMonitor | Op::WatchNew))
        .flat_map(|o| {
            let seen = reach(&g, o).2;
            NOTICE_REGISTRARS
                .iter()
                .filter(move |r| seen.contains(**r))
                .map(move |r| format!("{o:?} reaches {r}"))
        })
        .collect();
    assert!(
        stray.is_empty(),
        "a notice registrar is reachable from an op that did not place the \
         monitor, so the notice link now spreads exit and crash reasons over \
         it: {stray:?}"
    );

    for c in CLASSIFIERS {
        assert!(g.nodes.contains_key(*c), "classifier {c} is gone");
    }
    for (f, _) in UNATTRIBUTED {
        assert!(
            g.nodes.contains_key(*f),
            "UNATTRIBUTED names {f}, which is gone"
        );
    }
}

/// Both ladders together must name a handler for every op, or an op's arm is
/// checked against nothing at all.
#[test]
fn every_op_has_a_handler_the_sweep_can_find() {
    let g = build();
    let missing: Vec<Op> = (0..=u8::MAX)
        .filter_map(Op::from_u8)
        .filter(|o| !g.covered.contains(&(*o as u8)))
        .collect();
    assert!(
        missing.is_empty(),
        "no dispatch arm found for {missing:?}; their slots_for arms are \
         unchecked"
    );
}

/// One witness per modelled edge, so the sweep degrading to "reaches nothing"
/// is a failure rather than a green run. Each row names the path it pins;
/// without them a scanner that stopped finding calls would pass every arm.
#[test]
fn the_sweep_witnesses_each_kind_of_construction_path() {
    let g = build();
    let cases: &[(Op, AbiSlot, &str)] = &[
        (
            Op::BinIndexOf,
            AbiSlot::OptionSome,
            "self-call into a handler",
        ),
        (Op::JsonParse, AbiSlot::JsonDoc, "the interpreter ladder"),
        (
            Op::HttpParseHead,
            AbiSlot::H1ParsedDone,
            "the H1 bundle's fields",
        ),
        (
            Op::FileRead,
            AbiSlot::FsErrnoOther,
            "the blocking-pool continuation",
        ),
        (
            Op::TcpConnect,
            AbiSlot::Socket,
            "a method on a non-self receiver",
        ),
        (
            Op::TlsHandshake,
            AbiSlot::TlsSocket,
            "the native bridge's ladder",
        ),
        (
            Op::ProcessMonitor,
            AbiSlot::CrashTypeMismatch,
            "the notice continuation, two functions deep",
        ),
        (
            Op::WatchNew,
            AbiSlot::ExitNormal,
            "the notice continuation, through a watch",
        ),
    ];
    let missed: Vec<String> = cases
        .iter()
        .filter(|(op, slot, _)| !reach(&g, *op).0.contains(slot))
        .map(|(op, slot, why)| format!("{op:?} no longer reaches {} via {why}", slot.name()))
        .collect();
    assert!(
        missed.is_empty(),
        "the sweep has stopped following an edge it is built on:\n  {}",
        missed.join("\n  ")
    );
}

/// The check itself: an arm may not understate.
#[test]
fn every_op_declares_what_its_handler_can_construct() {
    let g = build();
    let mut bad: Vec<String> = Vec::new();
    for op in (0..=u8::MAX).filter_map(Op::from_u8) {
        let declared: BTreeSet<AbiSlot> = slots_for(op).iter().copied().collect();
        let (strict, loose, _) = reach(&g, op);
        let missing: Vec<&str> = strict
            .difference(&declared)
            .filter(|s| !loose.contains(s))
            .map(|s| s.name())
            .collect();
        if !missing.is_empty() {
            bad.push(format!("{op:?} builds but does not declare {missing:?}"));
        }
    }
    assert!(
        bad.is_empty(),
        "understated slots_for arms:\n  {}",
        bad.join("\n  ")
    );
}

/// The guard on the guard. A slot built where no op reaches is an edge the
/// model does not follow, and every op downstream of it is checked against
/// less than it should be. Declaring one in [`UNATTRIBUTED`] is how that gets
/// said out loud.
#[test]
fn every_construction_site_is_attributed_to_an_op() {
    let g = build();
    let mut reached: BTreeSet<String> = BTreeSet::new();
    for op in (0..=u8::MAX).filter_map(Op::from_u8) {
        reached.extend(reach(&g, op).2);
    }
    let excused: BTreeSet<&str> = UNATTRIBUTED.iter().map(|(f, _)| *f).collect();
    let orphans: Vec<&String> = g
        .nodes
        .iter()
        .filter(|(n, node)| {
            !node.slots.is_empty() && !reached.contains(*n) && !excused.contains(n.as_str())
        })
        .map(|(n, _)| n)
        .collect();
    assert!(
        orphans.is_empty(),
        "these build ABI slots and no op reaches them: {orphans:?} — either \
         the sweep is missing an edge, or they belong in UNATTRIBUTED with the \
         reason"
    );
}
