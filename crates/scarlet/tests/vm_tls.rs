//! TLS, end to end: a Scarlet program against a real TLS server on loopback.
//!
//! **The negative tests are the point of this file.** A TLS client that accepts
//! any certificate is worse than no TLS client, because it still looks like it
//! works: every test here would pass, the bytes would flow, and the connection
//! would be readable by anyone on the path. So three separate ways of being the
//! wrong peer are checked — an issuer we do not trust, a certificate outside
//! its validity window, and a certificate for a different name — and each must
//! come back as its own typed `TlsError`, not merely as "an error".
//!
//! Every certificate is minted here, per test, by `rcgen`. The alternative is
//! aiming the tests at a public host that is misconfigured on purpose, which
//! makes a security test depend on a third party's uptime and turns a network
//! outage into a green run.
//!
//! Trust is granted the way the documentation tells a user to grant it: through
//! the machine's certificate store, via `SSL_CERT_FILE`, which is what
//! `rustls-native-certs` reads on Unix. There is deliberately no way to ask the
//! runtime to skip verification, so there is nothing here that switches it off
//! — the positive test earns its trust by installing a root, exactly as a
//! program talking to an internal CA would.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::thread;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose, date_time_ymd,
};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

// ---------------------------------------------------------------------------
// Certificate authority and leaves
// ---------------------------------------------------------------------------

/// A throwaway CA, plus the PEM a client trusts it by.
struct Ca {
    params: rcgen::Certificate,
    key: KeyPair,
    pem: String,
}

fn make_ca() -> Ca {
    let mut params = CertificateParams::new(Vec::new()).expect("ca params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params
        .distinguished_name
        .push(DnType::CommonName, "scarlet test ca");
    let key = KeyPair::generate().expect("ca key");
    let cert = params.self_signed(&key).expect("self-sign ca");
    let pem = cert.pem();
    Ca {
        params: cert,
        key,
        pem,
    }
}

/// A leaf for `name`, signed by `ca`. `validity` picks the window, which is how
/// the expired case is built.
enum Validity {
    Current,
    Expired,
}

struct Leaf {
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

fn make_leaf(ca: &Ca, name: &str, validity: Validity) -> Leaf {
    let mut params = CertificateParams::new(vec![name.to_string()]).expect("leaf params");
    params
        .distinguished_name
        .push(DnType::CommonName, name.to_string());
    if let Validity::Expired = validity {
        // Comfortably in the past, so no clock skew on a test machine can drag
        // it back into validity.
        params.not_before = date_time_ymd(2015, 1, 1);
        params.not_after = date_time_ymd(2016, 1, 1);
    }
    let key = KeyPair::generate().expect("leaf key");
    let cert = params
        .signed_by(&key, &ca.params, &ca.key)
        .expect("sign leaf");
    Leaf {
        chain: vec![cert.der().clone(), ca.params.der().clone()],
        key: PrivateKeyDer::try_from(key.serialize_der()).expect("leaf key der"),
    }
}

// ---------------------------------------------------------------------------
// A one-shot TLS server on loopback
// ---------------------------------------------------------------------------

/// Pick the crypto provider for THIS test process.
///
/// Two are linked in — `scarlet_vm` asks for `aws-lc-rs`, and `ureq` brings
/// `ring` — so rustls refuses to guess and panics on the first `builder()`.
/// The runtime has the same problem and solves it the same way, in
/// `vm/tls.rs`; that call is load-bearing rather than defensive, and this is
/// the evidence.
fn install_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

/// Serve exactly one TLS connection, echoing back a fixed reply, and return the
/// port it bound. The thread is detached: a test that fails the handshake on
/// purpose leaves it waiting, and the process exiting collects it.
fn spawn_tls_server(leaf: Leaf, reply: &'static str) -> u16 {
    install_provider();
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(leaf.chain, leaf.key)
        .expect("server config");
    let config = Arc::new(config);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("local_addr").port();

    thread::spawn(move || {
        let Ok((mut sock, _)) = listener.accept() else {
            return;
        };
        let Ok(mut conn) = rustls::ServerConnection::new(config) else {
            return;
        };
        // A failed handshake here is the expected outcome of every negative
        // test, so it is not reported: the assertion lives on the client side.
        if conn.complete_io(&mut sock).is_err() {
            return;
        }
        let mut buf = [0u8; 1024];
        let mut stream = rustls::Stream::new(&mut conn, &mut sock);
        let _ = stream.read(&mut buf);
        let _ = stream.write_all(reply.as_bytes());
        let _ = stream.flush();
    });

    port
}

// ---------------------------------------------------------------------------
// Running a Scarlet program
// ---------------------------------------------------------------------------

fn project_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "scarlet_tls_{tag}_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

/// Write `src` as a one-file program and run it. `trust` is the PEM installed
/// as the machine's certificate store for the child, or `None` to leave the
/// child with the roots it would ordinarily have.
fn run_program(tag: &str, src: &str, trust: Option<&str>) -> String {
    let dir = project_dir(tag);
    let entry = dir.join("main.scrl");
    std::fs::write(&entry, src).expect("write program");
    std::fs::write(dir.join("package.scrl"), "name = 'tls_test'\n").expect("write package");

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_scarlet"));
    cmd.arg("run").arg(&entry).current_dir(&dir);
    match trust {
        Some(pem) => {
            let roots = dir.join("roots.pem");
            std::fs::write(&roots, pem).expect("write roots");
            cmd.env("SSL_CERT_FILE", &roots);
        }
        // An empty file is a certificate store with nothing in it, which is
        // what makes "this issuer is not trusted" the test's own doing rather
        // than a property of whatever CAs happen to be on the build machine.
        None => {
            let empty = dir.join("empty.pem");
            std::fs::write(&empty, "").expect("write empty roots");
            cmd.env("SSL_CERT_FILE", &empty);
        }
    }
    let out = cmd.output().expect("run scarlet");
    let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&out.stderr));
    combined
}

/// A program that connects and reports the outcome.
///
/// The TCP connect goes to the literal `127.0.0.1` while the certificate is
/// verified against `localhost`. That split is not a workaround for the test —
/// it is the reason `handshake` takes the name as its own argument. Connecting
/// by address and verifying by name is what a connection pool does, and what a
/// client behind a proxy does. Using `tls.connect('localhost', …)` here would
/// instead resolve `localhost` to `::1` on this host, where nothing is bound,
/// and every assertion below would pass on `ConnectionRefused` without a
/// certificate ever being examined.
fn connect_program(name: &str, port: u16) -> String {
    format!(
        r#"import scarlet/net
import scarlet/net/tls
import scarlet/string

match net.connect('127.0.0.1', {port}) {{
    Ok(sock) -> match tls.handshake(sock, '{name}') {{
        Ok(conn) -> {{
            println('connected')
            tls.close(conn) or Nil
        }}
        Err(e) -> println('failed: ${{string.inspect(e)}}')
    }}
    Err(e) -> println('connect failed: ${{string.inspect(e)}}')
}}
"#
    )
}

// ---------------------------------------------------------------------------
// The negative tests
// ---------------------------------------------------------------------------

#[test]
fn an_untrusted_issuer_is_rejected() {
    let ca = make_ca();
    let leaf = make_leaf(&ca, "localhost", Validity::Current);
    let port = spawn_tls_server(leaf, "HTTP/1.1 200 OK\r\n\r\n");

    // The CA is deliberately NOT installed.
    let out = run_program("untrusted", &connect_program("localhost", port), None);

    assert!(
        out.contains("CertificateUnknownIssuer"),
        "a certificate from an issuer we do not trust must be rejected as \
         CertificateUnknownIssuer, got:\n{out}"
    );
    assert!(
        !out.contains("connected"),
        "the handshake must not succeed against an untrusted issuer:\n{out}"
    );
}

#[test]
fn an_expired_certificate_is_rejected() {
    let ca = make_ca();
    let leaf = make_leaf(&ca, "localhost", Validity::Expired);
    let port = spawn_tls_server(leaf, "HTTP/1.1 200 OK\r\n\r\n");

    // The issuer IS trusted, so the only thing wrong is the validity window.
    let out = run_program(
        "expired",
        &connect_program("localhost", port),
        Some(&ca.pem),
    );

    assert!(
        out.contains("CertificateExpired"),
        "a certificate outside its validity window must be rejected as \
         CertificateExpired, got:\n{out}"
    );
    assert!(
        !out.contains("connected"),
        "the handshake must not succeed with an expired certificate:\n{out}"
    );
}

#[test]
fn a_hostname_mismatch_is_rejected() {
    let ca = make_ca();
    // Valid, current, and signed by a CA the client trusts — issued for the
    // wrong name. This is the case a connection pool gets wrong by reusing a
    // connection under the wrong key, and the only thing that catches it.
    let leaf = make_leaf(&ca, "wrong.example", Validity::Current);
    let port = spawn_tls_server(leaf, "HTTP/1.1 200 OK\r\n\r\n");

    let out = run_program(
        "mismatch",
        &connect_program("localhost", port),
        Some(&ca.pem),
    );

    assert!(
        out.contains("HostnameMismatch"),
        "a certificate issued for another name must be rejected as \
         HostnameMismatch, got:\n{out}"
    );
    assert!(
        !out.contains("connected"),
        "the handshake must not succeed against a certificate for another \
         name:\n{out}"
    );
}

// ---------------------------------------------------------------------------
// The positive test, so the negatives are not passing by never connecting
// ---------------------------------------------------------------------------

#[test]
fn a_trusted_certificate_completes_the_handshake_and_moves_bytes() {
    let ca = make_ca();
    let leaf = make_leaf(&ca, "localhost", Validity::Current);
    let port = spawn_tls_server(leaf, "hello over tls");

    let src = format!(
        r#"import scarlet/net
import scarlet/net/tls
import scarlet/net/socket.{{Data, Closed}}
import scarlet/binary
import scarlet/string

match net.connect('127.0.0.1', {port}) {{
    Ok(sock) -> match tls.handshake(sock, 'localhost') {{
        Ok(conn) -> {{
            tls.write(conn, <<'ping'>>) or Nil
            match tls.read(conn, 1024) {{
                Ok(Data(b)) -> println('read: ${{binary.to_string(b) or "<not utf-8>"}}')
                Ok(Closed) -> println('closed')
                Err(e) -> println('read failed: ${{string.inspect(e)}}')
            }}
            tls.close(conn) or Nil
        }}
        Err(e) -> println('failed: ${{string.inspect(e)}}')
    }}
    Err(e) -> println('connect failed: ${{string.inspect(e)}}')
}}
"#
    );

    let out = run_program("trusted", &src, Some(&ca.pem));

    assert!(
        out.contains("read: hello over tls"),
        "a trusted certificate must complete the handshake and carry bytes \
         both ways, got:\n{out}"
    );
}

/// The cleartext handle is stale once the connection has been secured.
///
/// This is the runtime half of the guarantee whose compile-time half is that
/// `Socket` and `TlsSocket` are different types: `tls.handshake` re-keys the
/// connection, so a caller holding the `Socket` it passed in cannot go around
/// the encryption with it.
#[test]
fn the_cleartext_handle_is_dead_after_an_upgrade() {
    let ca = make_ca();
    let leaf = make_leaf(&ca, "localhost", Validity::Current);
    let port = spawn_tls_server(leaf, "hello over tls");

    let src = format!(
        r#"import scarlet/net
import scarlet/net/tls
import scarlet/net/socket
import scarlet/string

match net.connect('127.0.0.1', {port}) {{
    Ok(plain) -> match tls.handshake(plain, 'localhost') {{
        Ok(secure) -> {{
            // The same connection, named by the handle that predates the
            // upgrade. It must not reach the wire.
            match socket.write(plain, <<'cleartext'>>) {{
                Ok(Nil) -> println('LEAKED: cleartext write succeeded')
                Err(e) -> println('cleartext refused: ${{string.inspect(e)}}')
            }}
            tls.close(secure) or Nil
        }}
        Err(e) -> println('handshake failed: ${{string.inspect(e)}}')
    }}
    Err(e) -> println('connect failed: ${{string.inspect(e)}}')
}}
"#
    );

    let out = run_program("stale", &src, Some(&ca.pem));

    assert!(
        !out.contains("LEAKED"),
        "a cleartext write on the pre-upgrade handle must not reach the \
         wire:\n{out}"
    );
    assert!(
        out.contains("cleartext refused: NotConnected"),
        "the pre-upgrade handle must be reported as a gone socket, got:\n{out}"
    );
}

/// Connecting with TLS to a plaintext port is a protocol error, not a hang and
/// not a silent success.
#[test]
fn a_plaintext_peer_is_a_protocol_error() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf);
            // An HTTP server's answer to a ClientHello: not TLS at all.
            let _ = sock.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
        }
    });

    let out = run_program("plaintext", &connect_program("localhost", port), None);

    assert!(
        out.contains("ProtocolError") || out.contains("HandshakeFailed"),
        "a peer that answers a ClientHello in cleartext must fail the \
         handshake with a typed error, got:\n{out}"
    );
    assert!(
        !out.contains("connected"),
        "a plaintext peer must not be reported as a TLS connection:\n{out}"
    );
}
