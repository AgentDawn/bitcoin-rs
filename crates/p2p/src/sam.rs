//! I2P SAM v3 client (pinned IVNP bridge) for typed I2P transports.
//!
//! One persistent `SESSION CREATE STYLE=STREAM` root is held per session;
//! every dial opens a fresh SAM bridge connection with `STREAM CONNECT`,
//! and inbound streams arrive through fresh `STREAM ACCEPT` bridges.
//! Names resolve only through `NAMING LOOKUP` on the bridge — never
//! through the system resolver — and no failure falls back to direct TCP.
//! Private destination material is never logged.
//!
//! Each installed root carries a generation. A stream request is issued
//! against the root that was live when the caller started, so a stale
//! `INVALID_ID` retires only that root and never one recovered meanwhile.
//! The generation rises only when a root is installed.
//!
//! # Root readiness
//!
//! The pinned bridge answers `SESSION CREATE` only once its destination is
//! ready, which can take its whole readiness wait ([`READINESS_WAIT`]).
//! A root under construction is therefore one resumable [`PendingRoot`]
//! owned by the `recovery` state: its socket, one absolute readiness
//! deadline fixed once per root, before its socket connects, so the budget
//! covers the TCP connect, `HELLO`, the readiness wait, and `NAMING LOOKUP`
//! together, an explicit [`RootPhase`], the count of command bytes the socket
//! already accepted, and the bounded partial reply line. A connect or accept
//! caller advances it only while it holds `recovery`, bounded by the earlier
//! of its own deadline and the root's deadline. A caller deadline pauses the
//! exchange and reports `TimedOut`; the next caller resumes the same
//! exchange, so each command reaches the bridge exactly once. Only a hard
//! protocol or I/O failure, the root deadline, or [`SamSession::close`]
//! discards it. A TCP connect that cannot finish inside a caller's deadline
//! is abandoned: nothing was sent, so nothing can be duplicated. The
//! readiness budget is separate from the per-stream [`EXCHANGE_BUDGET`].
//!
//! [`SamSession::close`] wakes a connected root at once. Before the socket
//! exists there is nothing to wake, so `close` waits for at most the one
//! connect attempt in flight (at most [`EXCHANGE_BUDGET`]) and never for the
//! root's budget.
//!
//! # Lock order
//!
//! `recovery` then `control`, never the reverse. `wake` is a leaf: no other
//! lock is taken while it is held, and `close` releases it before taking
//! `recovery`.

use parking_lot::{Mutex, MutexGuard};
use std::cell::Cell;
use std::fmt::Write as _;
#[cfg(test)]
use std::fs::OpenOptions;
#[cfg(test)]
use std::io::BufReader;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
#[cfg(test)]
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[cfg(test)]
use bitcoin::secp256k1::rand::Rng;
use bitcoin::secp256k1::rand::{RngCore, thread_rng};
use bitcoin_rs_primitives::endpoint::base32_encode;
use sha2::{Digest, Sha256};

/// How long the pinned IVNP bridge may take to answer `SESSION CREATE`: its
/// default SAM readiness wait (`operating.go:471-473`). Readiness needs an
/// inbound tunnel, an outbound tunnel, and a confirmed publication.
const READINESS_WAIT: Duration = Duration::from_secs(120);

/// Budget of one bounded exchange: a stream request, a key step, and each
/// of the connect, `HELLO`, and `NAMING LOOKUP` steps that bracket the
/// readiness wait. It is never widened to cover the readiness wait.
pub(crate) const EXCHANGE_BUDGET: Duration = Duration::from_secs(5);

/// Owner budget for one root: the readiness wait plus three bounded steps
/// (connect, `HELLO`, `NAMING LOOKUP`).
pub(crate) const ROOT_READINESS_BUDGET: Duration =
    READINESS_WAIT.saturating_add(Duration::from_secs(3 * EXCHANGE_BUDGET.as_secs()));

/// How long startup keeps retrying a bridge that has never accepted a
/// connection (a refused or black-holed `--i2psam` address): the overall
/// startup limit this node had before the readiness budget existed. It
/// bounds the TCP connect waits as well as the retries: no connect attempt
/// waits past it while the bridge has never accepted. Only a bridge that
/// connects is given [`ROOT_READINESS_BUDGET`], and once one has connected
/// the window no longer applies.
#[cfg(test)]
const UNREACHABLE_WINDOW: Duration = Duration::from_secs(20);

/// Longest wait before a blocked root read or write notices cancellation. It
/// only slices waits; every slice is clipped to the remaining deadline. A TCP
/// connect is not sliced this finely: a handshake needs one full round trip
/// inside its timeout, so each attempt gets up to [`EXCHANGE_BUDGET`].
const CANCEL_POLL: Duration = Duration::from_millis(100);

/// Retry pause growth per failed startup step, in milliseconds.
#[cfg(test)]
const PAUSE_STEP_MS: u64 = 250;

/// Failed startup steps after which the retry pause stops growing.
#[cfg(test)]
const PAUSE_STEPS_MAX: u64 = 10;

/// Remaining budget before `deadline`.
///
/// An exhausted deadline is reported as `TimedOut` rather than handed to
/// the socket layer, which rejects a zero timeout as `InvalidInput`.
fn remaining_timeout(deadline: Instant) -> io::Result<Duration> {
    match deadline.checked_duration_since(Instant::now()) {
        Some(rem) if !rem.is_zero() => Ok(rem),
        _ => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "sam exchange deadline expired",
        )),
    }
}

/// Acquire `mutex` without waiting past `deadline`.
///
/// Every blocking step on the recovery path is charged to the caller's
/// absolute deadline, so a wider budget held by another caller can never
/// extend this exchange. An expired budget is reported here rather than
/// handed to the lock, which would wait without one.
fn lock_within<T>(mutex: &Mutex<T>, deadline: Instant) -> io::Result<MutexGuard<'_, T>> {
    let remaining = remaining_timeout(deadline)?;
    mutex.try_lock_for(remaining).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "sam recovery deadline expired waiting for the session lock",
        )
    })
}

const MAX_SAM_LINE: usize = 16_384;

/// Derive the SAM session id for one node instance from its private
/// destination, so two nodes sharing one SAM bridge never collide on
/// `SESSION CREATE`. Stable for the life of one destination key; falls
/// back to a process-random suffix when the destination cannot decode.
#[must_use]
fn session_id_for(private_destination: &str) -> String {
    let mut out = String::from("btcrs-");
    if let Some(bytes) = i2p_base64_decode(private_destination) {
        let hash = Sha256::digest(&bytes);
        for b in &hash[..6] {
            let _ = write!(out, "{b:02x}");
        }
    } else {
        let mut bytes = [0u8; 6];
        thread_rng().fill_bytes(&mut bytes);
        for b in bytes {
            let _ = write!(out, "{b:02x}");
        }
    }
    out
}

/// Strict canonical I2P base64 decode (SAM alphabet: `-`/`~` replace
/// `+`/`/`; the standard alphabet is also accepted).
///
/// Canonicality is load-bearing: destinations decoded here are hashed
/// into peer endpoints and accepted as key material, so malformed
/// encodings must not silently decode. Rejects: invalid alphabet bytes
/// (including whitespace/control bytes), padding anywhere except one or
/// two trailing `=` completing a quartet, any data after padding,
/// non-zero padding bits, and truncated quartets (a lone trailing
/// character or padding that does not complete a group of four).
#[must_use]
pub(crate) fn i2p_base64_decode(text: &str) -> Option<Vec<u8>> {
    if text.is_empty() {
        return None;
    }
    let bytes = text.as_bytes();
    let padding = bytes.iter().rev().take_while(|b| **b == b'=').count();
    if padding > 2 {
        return None;
    }
    let core = &bytes[..bytes.len() - padding];
    if core.contains(&b'=') {
        return None; // padding embedded in the body, or data after padding
    }
    if padding > 0 && !(core.len() + padding).is_multiple_of(4) {
        return None; // padding does not complete a quartet
    }
    if core.len() % 4 == 1 {
        return None; // truncated quartet
    }
    let mut values = Vec::with_capacity(core.len());
    for byte in core {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'~' => 63,
            _ => return None,
        };
        values.push(value);
    }
    // Non-zero padding bits make the encoding non-canonical: a final
    // pair carries 4 spare bits, a final triple carries 2.
    match values.len() % 4 {
        2 if values.last().is_some_and(|v| v & 0x0f != 0) => return None,
        3 if values.last().is_some_and(|v| v & 0x03 != 0) => return None,
        _ => {}
    }
    let mut out = Vec::with_capacity(values.len() * 3 / 4);
    for chunk in values.chunks(4) {
        let mut acc: u32 = 0;
        for (index, value) in chunk.iter().enumerate() {
            acc |= u32::from(*value) << (18 - 6 * index);
        }
        match chunk.len() {
            4 => out.extend_from_slice(&acc.to_be_bytes()[1..]),
            3 => out.extend_from_slice(&acc.to_be_bytes()[1..3]),
            2 => out.push(acc.to_be_bytes()[1]),
            _ => return None,
        }
    }
    Some(out)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// The one failure a closed session reports from every entry point.
fn session_closed() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "sam session is closed")
}

/// Test builds only: `(local, bridge)` address pair of every bridge socket a
/// session in this process opened, recorded before the socket's first write.
///
/// Fixture bridges listen on loopback, where any host process can connect
/// (a local HTTP service probes every listening socket). A fixture uses this
/// record to tell its session's connections, which stay strict, from
/// connections no session opened. Entries are never removed: a stale pair
/// can only make a later connection with the same addresses strict, never
/// excuse one.
#[cfg(test)]
static SESSION_SOCKETS: std::sync::Mutex<Vec<(SocketAddr, SocketAddr)>> =
    std::sync::Mutex::new(Vec::new());

struct SamConn {
    reader: TcpStream,
    writer: TcpStream,
}

impl SamConn {
    fn connect_with_deadline(sam: SocketAddr, deadline: Instant) -> io::Result<Self> {
        let rem = remaining_timeout(deadline)?;
        let stream = TcpStream::connect_timeout(&sam, rem)?;
        stream.set_read_timeout(Some(rem))?;
        stream.set_write_timeout(Some(rem))?;
        Self::from_stream(stream)
    }

    /// Wrap a connected bridge socket as a reader and a writer half.
    ///
    /// Every session socket passes through here before its first write, so
    /// test builds record its address pair in `SESSION_SOCKETS`.
    fn from_stream(stream: TcpStream) -> io::Result<Self> {
        #[cfg(test)]
        if let (Ok(local), Ok(bridge)) = (stream.local_addr(), stream.peer_addr()) {
            SESSION_SOCKETS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((local, bridge));
        }
        let _ = stream.set_nodelay(true);
        let writer = stream.try_clone()?;
        Ok(Self {
            reader: stream,
            writer,
        })
    }

    /// Read one reply line byte at a time. This is deliberately
    /// unbuffered: after `STREAM STATUS RESULT=OK` the same socket
    /// carries bridged peer payload, and a buffered reader could
    /// prefetch and drop those bytes when the stream is handed off.
    ///
    /// The deadline is absolute: the remaining budget is recomputed
    /// before every byte, so a bridge that trickles one byte inside each
    /// socket timeout cannot stretch the exchange past the deadline.
    ///
    /// EOF before `\n` is always a truncated exchange, never a reply, even
    /// when the bytes read so far are syntactically complete.
    fn read_line(&mut self, deadline: Instant) -> io::Result<String> {
        let mut line = Vec::new();
        loop {
            let rem = remaining_timeout(deadline)?;
            self.reader.set_read_timeout(Some(rem))?;
            let mut byte = [0u8; 1];
            let read = match self.reader.read(&mut byte) {
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            };
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "sam bridge closed the connection before the reply line ended",
                ));
            }
            if byte[0] == b'\n' {
                break;
            }
            line.push(byte[0]);
            if line.len() >= MAX_SAM_LINE {
                return Err(invalid("sam reply line exceeds the bound"));
            }
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        String::from_utf8(line).map_err(|_| invalid("sam reply line is not utf-8"))
    }

    /// Write every byte of `buf` inside `deadline`, recomputing the
    /// socket timeout before each partial write.
    fn write_all_deadline(&mut self, mut buf: &[u8], deadline: Instant) -> io::Result<()> {
        while !buf.is_empty() {
            let rem = remaining_timeout(deadline)?;
            self.writer.set_write_timeout(Some(rem))?;
            match self.writer.write(buf) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "sam bridge stopped accepting commands",
                    ));
                }
                Ok(written) => buf = &buf[written..],
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn command(&mut self, command: &str, deadline: Instant) -> io::Result<String> {
        self.write_all_deadline(command.as_bytes(), deadline)?;
        self.write_all_deadline(b"\n", deadline)?;
        self.read_line(deadline)
    }

    /// SAM handshake: requires the bridge to negotiate exactly 3.3.
    fn hello(&mut self, deadline: Instant) -> io::Result<()> {
        let reply = self.command("HELLO VERSION MIN=3.1 MAX=3.3", deadline)?;
        check_hello(&reply)
    }

    /// Whether the bridge still holds this session's control connection.
    ///
    /// The probe must not spend the caller's exchange budget, so the
    /// socket is switched to non-blocking for one `MSG_PEEK`: a healthy
    /// idle root reports `WouldBlock`. Only an orderly close or a hard
    /// connection error counts as dead; an unrecognized error leaves a
    /// possibly-live root alone, because replacing a live root would
    /// race the bridge into `DUPLICATED_ID`.
    fn is_alive(&mut self) -> bool {
        if self.reader.set_nonblocking(true).is_err() {
            return false;
        }
        let mut buf = [0u8; 1];
        let alive = match self.reader.peek(&mut buf) {
            Ok(read) => read > 0,
            Err(error) => {
                error.kind() == io::ErrorKind::Interrupted
                    || !matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionReset
                            | io::ErrorKind::ConnectionAborted
                            | io::ErrorKind::BrokenPipe
                            | io::ErrorKind::NotConnected
                    )
            }
        };
        // Restoring the blocking mode is best effort: the root is only
        // ever peeked, never read for payload, so a failed restore cannot
        // corrupt the session and must not declare a live root dead.
        let _ = self.reader.set_nonblocking(false);
        alive
    }

    fn into_stream(self) -> TcpStream {
        // Reads were unbuffered, so no bridged bytes can be stranded.
        let _ = self.writer.set_read_timeout(None);
        let _ = self.writer.set_write_timeout(None);
        let _ = self.reader.set_read_timeout(None);
        let _ = self.reader.set_write_timeout(None);
        self.writer
    }
}

/// Require a `HELLO REPLY` that negotiated exactly version 3.3.
fn check_hello(reply: &str) -> io::Result<()> {
    let fields = parse_fields(reply, "HELLO REPLY")?;
    if field(&fields, "RESULT") != Some("OK") || field(&fields, "VERSION") != Some("3.3") {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "sam bridge did not negotiate version 3.3",
        ));
    }
    Ok(())
}

/// Parse `VERB SUBVERB KEY=VALUE ...` SAM replies with quote awareness,
/// exact verb boundary, and duplicate key rejection.
fn parse_fields(reply: &str, prefix: &str) -> io::Result<Vec<(String, String)>> {
    let rest = if reply == prefix {
        ""
    } else if let Some(stripped) = reply.strip_prefix(prefix) {
        if !stripped.starts_with(' ') && !stripped.starts_with('\t') {
            return Err(invalid("unexpected sam reply verb boundary"));
        }
        stripped.trim_start()
    } else {
        return Err(invalid("unexpected sam reply prefix"));
    };

    let mut fields: Vec<(String, String)> = Vec::new();
    let chars: Vec<char> = rest.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        while i < chars.len() && (chars[i] == ' ' || chars[i] == '\t') {
            i += 1;
        }
        if i >= chars.len() {
            break;
        }
        if fields.len() >= 64 {
            return Err(invalid("too many fields in sam reply"));
        }
        let key_start = i;
        while i < chars.len() && chars[i] != '=' && chars[i] != ' ' && chars[i] != '\t' {
            i += 1;
        }
        if i >= chars.len() || chars[i] != '=' {
            return Err(invalid("malformed sam field: token missing '='"));
        }
        let key: String = chars[key_start..i].iter().collect();
        if key.is_empty() {
            return Err(invalid("malformed sam field: empty key"));
        }
        i += 1; // skip '='

        if i < chars.len() && chars[i] == '"' {
            i += 1; // skip opening quote
            let val_start = i;
            while i < chars.len() && chars[i] != '"' {
                i += 1;
            }
            if i >= chars.len() {
                return Err(invalid("malformed sam field: unterminated quoted value"));
            }
            let value: String = chars[val_start..i].iter().collect();
            i += 1; // skip closing quote
            if i < chars.len() && chars[i] != ' ' && chars[i] != '\t' {
                return Err(invalid(
                    "malformed sam field: trailing characters after quote",
                ));
            }
            if fields.iter().any(|(k, _)| k == &key) {
                return Err(invalid("duplicate field in sam reply"));
            }
            fields.push((key, value));
        } else {
            let val_start = i;
            while i < chars.len() && chars[i] != ' ' && chars[i] != '\t' {
                i += 1;
            }
            let value: String = chars[val_start..i].iter().collect();
            if value.is_empty() {
                return Err(invalid("malformed sam field: empty value"));
            }
            if fields.iter().any(|(k, _)| k == &key) {
                return Err(invalid("duplicate field in sam reply"));
            }
            fields.push((key, value));
        }
    }
    Ok(fields)
}

fn field<'a>(fields: &'a [(String, String)], key: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

fn sanitize_sam_result(result: &str) -> &'static str {
    match result {
        "OK" => "OK",
        "CANT_REACH_PEER" => "CANT_REACH_PEER",
        "KEY_NOT_FOUND" => "KEY_NOT_FOUND",
        "PEER_NOT_FOUND" => "PEER_NOT_FOUND",
        "TIMEOUT" => "TIMEOUT",
        "I2P_ERROR" => "I2P_ERROR",
        "INVALID_KEY" => "INVALID_KEY",
        "INVALID_ID" => "INVALID_ID",
        "ALREADY_ACCEPTING" => "ALREADY_ACCEPTING",
        "DUPLICATED_ID" => "DUPLICATED_ID",
        "DUPLICATED_DEST" => "DUPLICATED_DEST",
        _ => "UNKNOWN",
    }
}

fn require_ok(reply: &str, prefix: &str) -> io::Result<Vec<(String, String)>> {
    let fields = parse_fields(reply, prefix)?;
    if field(&fields, "RESULT") != Some("OK") {
        let raw = field(&fields, "RESULT").unwrap_or("");
        let sanitized = sanitize_sam_result(raw);
        return Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            format!("sam request failed: {prefix} RESULT={sanitized}"),
        ));
    }
    Ok(fields)
}

/// Length of the I2P `KeysAndCert` identity when `bytes` opens with a
/// structurally valid destination: 384 key bytes plus a certificate
/// (3-byte header + payload) at offset 384. For `CertificateKey` (5)
/// the payload must be exactly `4 + signing excess + crypto excess`
/// for recognized key types, mirroring the pinned bridge's
/// `ParseIdentity`. Other certificate types follow its payload rules.
/// Returns the identity's total length, or `None` when malformed.
#[must_use]
fn destination_identity_len(bytes: &[u8]) -> Option<usize> {
    const BASE: usize = 384;
    if bytes.len() < BASE + 3 {
        return None;
    }
    let cert_type = bytes[BASE];
    let payload_len = usize::from(u16::from_be_bytes([bytes[BASE + 1], bytes[BASE + 2]]));
    let total = BASE + 3 + payload_len;
    if bytes.len() < total {
        return None;
    }
    let payload = &bytes[BASE + 3..total];
    let valid = match cert_type {
        0 | 2 => payload_len == 0,                   // Null, Hidden
        1 | 4 => true,                               // HashCash, Multiple
        3 => payload_len == 40 || payload_len == 72, // Signed
        5 => {
            // Key: signing type (2) || crypto type (2) || excess keys.
            if payload_len < 4 {
                return None;
            }
            let signing = u16::from_be_bytes([payload[0], payload[1]]);
            let crypto = u16::from_be_bytes([payload[2], payload[3]]);
            let signing_len: usize = match signing {
                0 | 10 => 128,
                1 | 9 => 64,
                2 => 96,
                3 => 132,
                4 => 256,
                5 => 384,
                6 => 512,
                7 | 8 | 11 => 32,
                _ => return None,
            };
            let crypto_len: usize = match crypto {
                0 => 256,
                1 => 64,
                2 => 96,
                3 => 132,
                4 | 6 | 7 => 32,
                _ => return None,
            };
            payload_len == 4 + signing_len.saturating_sub(128) + crypto_len.saturating_sub(256)
        }
        _ => false,
    };
    valid.then_some(total)
}

/// Whether `bytes` is exactly one structurally valid I2P destination
/// (`KeysAndCert` wire form, no trailing data; 387 bytes for Null Certificate,
/// ~391 bytes for `CertificateKey`).
#[must_use]
fn valid_destination(bytes: &[u8]) -> bool {
    destination_identity_len(bytes) == Some(bytes.len()) && bytes.len() >= 387
}

/// The hash identifying an I2P destination (SHA-256 of the destination).
#[must_use]
pub(crate) fn destination_hash(destination: &[u8]) -> [u8; 32] {
    Sha256::digest(destination).into()
}

/// The session root together with the generation that identifies it.
///
/// One root, one generation: the count rises on every install and is never
/// reused, so evidence gathered against an older root can never be mistaken
/// for evidence about a newer one. Both fields live under the same exclusion
/// so comparing a generation and retiring the root are one atomic step.
struct ControlState {
    /// The installed root, if any. Only the recovery owner installs one.
    conn: Option<SamConn>,
    /// Generation of the root in `conn`, or of the most recently installed
    /// root once `conn` is empty.
    generation: u64,
}

/// Phase of the one root exchange. Each variant names the command that is
/// next written or whose reply is awaited; a phase ends only when its reply
/// line has been consumed, so a command is never written twice.
enum RootPhase {
    /// `HELLO VERSION`: the bridge must negotiate exactly 3.3.
    Hello,
    /// `SESSION CREATE`: the reply may take the whole readiness wait.
    Create,
    /// `NAMING LOOKUP NAME=ME`: the bridge reports our public destination.
    Lookup,
    /// Every reply has arrived. Only installation remains; the structurally
    /// valid public destination the bridge reported is kept for it.
    Ready(String),
}

impl RootPhase {
    /// The command line (newline included) this phase writes.
    fn command(&self, id: &str, private_destination: &str) -> String {
        match self {
            Self::Hello => "HELLO VERSION MIN=3.1 MAX=3.3\n".to_owned(),
            Self::Create => {
                format!("SESSION CREATE STYLE=STREAM ID={id} DESTINATION={private_destination}\n")
            }
            Self::Lookup => "NAMING LOOKUP NAME=ME\n".to_owned(),
            Self::Ready(_) => String::new(),
        }
    }

    /// The phase that follows once `reply` answered this one.
    fn on_reply(&self, reply: &str) -> io::Result<Self> {
        match self {
            Self::Hello => check_hello(reply).map(|()| Self::Create),
            Self::Create => require_ok(reply, "SESSION STATUS").map(|_| Self::Lookup),
            Self::Lookup => {
                let fields = require_ok(reply, "NAMING REPLY")?;
                let destination = field(&fields, "VALUE")
                    .ok_or_else(|| invalid("sam naming reply carries no public destination"))?;
                if i2p_base64_decode(destination).is_none_or(|bytes| !valid_destination(&bytes)) {
                    return Err(invalid("sam public destination is not a valid destination"));
                }
                Ok(Self::Ready(destination.to_owned()))
            }
            Self::Ready(_) => Err(invalid("sam root exchange is already complete")),
        }
    }
}

/// Why one resumable root step ended without finishing.
enum Stop {
    /// The caller's own deadline passed. The exchange is intact and resumable.
    Paused,
    /// The root's readiness deadline passed. The exchange is spent.
    Expired,
    /// The cancellation predicate fired: the session closed, or the startup
    /// owner cancelled.
    Cancelled,
    /// A hard I/O or protocol failure. The exchange is spent.
    Failed(io::Error),
}

impl Stop {
    /// The error a caller reports; `cancelled` builds the owner's own error.
    fn into_io(self, cancelled: fn() -> io::Error) -> io::Error {
        match self {
            Self::Paused => io::Error::new(
                io::ErrorKind::TimedOut,
                "sam root is not ready before this caller's deadline",
            ),
            Self::Expired => {
                io::Error::new(io::ErrorKind::TimedOut, "sam root readiness budget expired")
            }
            Self::Cancelled => cancelled(),
            Self::Failed(error) => error,
        }
    }
}

/// The failure a cancelled startup reports.
fn startup_cancelled() -> io::Error {
    io::Error::new(
        io::ErrorKind::Interrupted,
        "i2p session startup was cancelled",
    )
}

/// Whether a socket call ended because its slice timeout elapsed.
fn slice_ended(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

/// The wait for the next blocking step: at most `cap`, clipped to the
/// earlier of the caller's and the root's deadline, after the checks that
/// decide whether the step may start at all. The root deadline wins a tie,
/// so a spent root is never merely paused.
fn poll_slice(
    call_deadline: Instant,
    root_deadline: Instant,
    cap: Duration,
    cancelled: &dyn Fn() -> bool,
) -> Result<Duration, Stop> {
    if cancelled() {
        return Err(Stop::Cancelled);
    }
    let now = Instant::now();
    if now >= root_deadline {
        return Err(Stop::Expired);
    }
    call_deadline
        .min(root_deadline)
        .checked_duration_since(now)
        .filter(|left| !left.is_zero())
        .map(|left| left.min(cap))
        .ok_or(Stop::Paused)
}

/// One root exchange in progress: the socket, the phase, and exactly what
/// the bridge has been sent and has answered. It is advanced only by a
/// caller holding `recovery`, and it is the only owner of its socket until
/// it is installed or discarded.
struct PendingRoot {
    conn: SamConn,
    /// Absolute readiness deadline, fixed once per root before its socket
    /// connects, so the budget includes the TCP connect. No caller and no
    /// phase moves it.
    deadline: Instant,
    phase: RootPhase,
    /// Bytes of the current phase's command the socket already accepted.
    sent: usize,
    /// Reply bytes received for the current phase, without the newline.
    line: Vec<u8>,
}

impl PendingRoot {
    /// Connect the root socket. Each attempt waits at most
    /// [`EXCHANGE_BUDGET`], so cancellation is observed between attempts and
    /// a bridge further than one poll slice away can still connect; an
    /// attempt already in flight is not interrupted. A connect that cannot
    /// finish by `connect_deadline` is abandoned: nothing was sent, so no
    /// state is kept and no command can be duplicated. `root_deadline` is
    /// the root's own readiness deadline and wins a tie.
    fn connect(
        sam: SocketAddr,
        connect_deadline: Instant,
        root_deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Self, Stop> {
        loop {
            let slice = poll_slice(connect_deadline, root_deadline, EXCHANGE_BUDGET, cancelled)?;
            match TcpStream::connect_timeout(&sam, slice) {
                Ok(stream) => {
                    return Ok(Self {
                        conn: SamConn::from_stream(stream).map_err(Stop::Failed)?,
                        deadline: root_deadline,
                        phase: RootPhase::Hello,
                        sent: 0,
                        line: Vec::new(),
                    });
                }
                Err(error) if slice_ended(&error) => {}
                Err(error) => return Err(Stop::Failed(error)),
            }
        }
    }

    /// Write what remains of `command` for at most `slice`. The offset is
    /// recorded as soon as the socket accepts bytes, so a pause that follows
    /// resumes mid-command instead of repeating or skipping bytes.
    fn write_step(&mut self, command: &[u8], slice: Duration) -> io::Result<()> {
        self.conn.writer.set_write_timeout(Some(slice))?;
        match self.conn.writer.write(&command[self.sent..]) {
            Ok(0) => Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "sam bridge stopped accepting commands",
            )),
            Ok(written) => {
                self.sent += written;
                Ok(())
            }
            Err(error) if slice_ended(&error) => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Read at most one reply byte within `slice`. A complete line is
    /// returned and consumed; end of stream before the newline is a dead
    /// bridge, never a reply.
    fn read_step(&mut self, slice: Duration) -> io::Result<Option<String>> {
        self.conn.reader.set_read_timeout(Some(slice))?;
        let mut byte = [0u8; 1];
        match self.conn.reader.read(&mut byte) {
            Ok(0) => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "sam bridge closed the connection before the reply line ended",
            )),
            Ok(_) if byte[0] == b'\n' => {
                if self.line.last() == Some(&b'\r') {
                    self.line.pop();
                }
                String::from_utf8(std::mem::take(&mut self.line))
                    .map(Some)
                    .map_err(|_| invalid("sam reply line is not utf-8"))
            }
            Ok(_) => {
                self.line.push(byte[0]);
                if self.line.len() >= MAX_SAM_LINE {
                    return Err(invalid("sam reply line exceeds the bound"));
                }
                Ok(None)
            }
            Err(error) if slice_ended(&error) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Drive the exchange until it is [`RootPhase::Ready`], or until a
    /// deadline, cancellation, or hard failure stops it. Every blocking step
    /// is bounded by the earlier of `call_deadline` and the root deadline.
    /// A reply is consumed and the next phase entered with no deadline check
    /// in between, so a pause can only fall inside a phase, never between a
    /// reply and its successor.
    fn advance(
        &mut self,
        id: &str,
        private_destination: &str,
        call_deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), Stop> {
        while !matches!(self.phase, RootPhase::Ready(_)) {
            let command = self.phase.command(id, private_destination);
            let reply = loop {
                let slice = poll_slice(call_deadline, self.deadline, CANCEL_POLL, cancelled)?;
                let step = if self.sent < command.len() {
                    self.write_step(command.as_bytes(), slice).map(|()| None)
                } else {
                    self.read_step(slice)
                };
                if let Some(reply) = step.map_err(Stop::Failed)? {
                    break reply;
                }
            };
            self.sent = 0;
            self.phase = self.phase.on_reply(&reply).map_err(Stop::Failed)?;
        }
        Ok(())
    }
}

/// Recovery ownership: the one root exchange that may be in progress.
struct Recovery {
    pending: Option<PendingRoot>,
}

/// One persistent SAM STREAM session root.
pub struct SamSession {
    sam: SocketAddr,
    id: String,
    /// Our public destination (base64), reported for diagnostics only.
    destination: String,
    /// Private destination material, stored for session re-establishment.
    /// Never exposed via Debug or public accessors.
    private_destination: String,
    /// Installed root and its generation. Never read for payload; held so
    /// the bridge keeps the session alive.
    control: Mutex<ControlState>,
    /// Serializes root installation against retirement and close, and owns
    /// the one root exchange in progress. The order is always `recovery`
    /// then `control`.
    recovery: Mutex<Recovery>,
    /// Leaf lock: a clone of the socket `recovery`'s holder is blocked on,
    /// so `close` can wake it without waiting for `recovery`. It is empty
    /// while the holder is still in its TCP connect, when `close` waits for
    /// that one attempt (at most [`EXCHANGE_BUDGET`]) instead. The holder
    /// checks `closed` and stores the clone under this lock, and `close`
    /// stores `closed` before it takes this lock, so a close either finds
    /// the socket here or the holder finds `closed`. No lock is taken while
    /// it is held.
    wake: Mutex<Option<TcpStream>>,
    closed: AtomicBool,
    /// Budget of one stream exchange (`connect`, `accept`'s recovery step).
    timeout: Duration,
    /// Readiness budget of a root recovered after the first one.
    root_budget: Duration,
}

impl std::fmt::Debug for SamSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print destination private material; the session was
        // created from it and holds no copy worth repeating.
        f.debug_struct("SamSession")
            .field("sam", &self.sam)
            .field("id", &self.id)
            .field("closed", &self.closed.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl SamSession {
    /// Establish the persistent session with `DESTINATION=<private>` on a
    /// fresh control connection. The session id is derived from the
    /// destination (see [`session_id_for`]) and stays stable for this session's life.
    /// `timeout` bounds this establishment and is the budget of each later
    /// stream exchange; a root recovered later gets [`ROOT_READINESS_BUDGET`].
    pub fn establish(
        sam: SocketAddr,
        private_destination: &str,
        timeout: Duration,
    ) -> io::Result<Self> {
        let deadline = Instant::now() + timeout;
        Self::establish_within(
            sam,
            private_destination,
            timeout,
            deadline,
            deadline,
            &|| false,
            &Cell::new(false),
        )
    }

    /// Establish the session under two absolute deadlines and a cancellation
    /// predicate.
    ///
    /// `root_deadline` bounds the whole exchange. The owner fixes it before
    /// this call connects, so it covers the TCP connect, `HELLO`, the
    /// readiness wait, and `NAMING LOOKUP` together. `connect_deadline`
    /// bounds only the TCP connect: a connect that cannot finish by it fails
    /// `TimedOut` with nothing sent, and `root_deadline` wins a tie. Once the
    /// bridge has accepted the connection only `root_deadline` applies.
    ///
    /// `cancelled` is polled at least every [`CANCEL_POLL`] while reading or
    /// writing, between connect attempts, and once more together with
    /// `root_deadline` before the session is returned, so a cancelled
    /// establishment, or one whose root deadline passed after the final
    /// reply, never publishes a session: the first reports `Interrupted`, the
    /// second `TimedOut`. A connect attempt already in flight is not
    /// interrupted; it ends within [`EXCHANGE_BUDGET`].
    /// `timeout` is the per-stream budget the session keeps. `reached` is set
    /// once the bridge accepted the connection and this call never clears it,
    /// so a caller can tell a bridge that is unreachable from one that is
    /// merely slow to become ready, and a bridge that has connected before
    /// from one that never has.
    pub(crate) fn establish_within(
        sam: SocketAddr,
        private_destination: &str,
        timeout: Duration,
        connect_deadline: Instant,
        root_deadline: Instant,
        cancelled: &dyn Fn() -> bool,
        reached: &Cell<bool>,
    ) -> io::Result<Self> {
        validate_private_destination(private_destination)?;
        let id = session_id_for(private_destination);
        let mut root = PendingRoot::connect(sam, connect_deadline, root_deadline, cancelled)
            .map_err(|stop| match stop {
                Stop::Paused => io::Error::new(
                    io::ErrorKind::TimedOut,
                    "sam bridge accepted no connection before the connect deadline",
                ),
                stop => stop.into_io(startup_cancelled),
            })?;
        reached.set(true);
        // The SESSION STATUS reply carries the *private* destination on
        // this bridge; the exchange never stores it. The public destination
        // comes from NAMING LOOKUP NAME=ME on the session root.
        let advanced = root.advance(&id, private_destination, root_deadline, cancelled);
        let PendingRoot { conn, phase, .. } = root;
        // Publication is the last step the root deadline bounds. The same
        // check that gates every step before it runs once more, after the
        // final reply: cancellation is reported as such, and a deadline that
        // passed meanwhile is the root's `TimedOut`, never a cancellation.
        let verdict = match (advanced, phase) {
            (Ok(()), RootPhase::Ready(destination)) => {
                poll_slice(root_deadline, root_deadline, CANCEL_POLL, cancelled)
                    .map(|_left| destination)
            }
            (Err(stop), _) => Err(stop),
            (Ok(()), _) => Err(Stop::Failed(invalid(
                "sam root exchange ended without a public destination",
            ))),
        };
        let destination = match verdict {
            Ok(destination) => destination,
            Err(stop) => {
                let _ = conn.writer.shutdown(std::net::Shutdown::Both);
                return Err(stop.into_io(startup_cancelled));
            }
        };
        Ok(Self {
            sam,
            id,
            destination,
            private_destination: private_destination.to_owned(),
            control: Mutex::new(ControlState {
                conn: Some(conn),
                generation: 1,
            }),
            recovery: Mutex::new(Recovery { pending: None }),
            wake: Mutex::new(None),
            closed: AtomicBool::new(false),
            timeout,
            root_budget: ROOT_READINESS_BUDGET,
        })
    }

    /// Establish the session for node startup under one absolute owner
    /// `deadline` and a `cancelled` predicate.
    ///
    /// The identity is loaded or generated once and reused by every session
    /// attempt, so a retry never creates a second key or a second session id.
    /// Each network step is clipped to the remaining owner deadline, a
    /// session attempt gets at most [`ROOT_READINESS_BUDGET`] (connect
    /// included), and the pause between attempts is cut by cancellation and
    /// by the deadline. A corrupt key, a malformed bridge reply, and a bridge
    /// that does not speak 3.3 fail at once (`InvalidData`, `Unsupported`);
    /// every other failure retries until the deadline. Cancellation is
    /// reported as `Interrupted` and leaves no session behind; it is seen
    /// between connect attempts, so a connect attempt in flight delays it by
    /// at most [`EXCHANGE_BUDGET`]. A bridge that has never accepted a
    /// connection is given up on after [`UNREACHABLE_WINDOW`], which also
    /// clips its connect waits, instead of the whole owner deadline.
    #[cfg(test)]
    pub(crate) fn establish_startup(
        sam: SocketAddr,
        key_path: Option<&Path>,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> io::Result<Self> {
        let unreachable_after = Instant::now() + UNREACHABLE_WINDOW;
        // A key step answers at once; it never needs the readiness budget.
        let private = retry_until(
            deadline.min(unreachable_after),
            cancelled,
            || false,
            |left| match key_path {
                Some(path) => {
                    load_or_create_private_destination(sam, path, left.min(EXCHANGE_BUDGET))
                }
                None => generate_destination(sam, left.min(EXCHANGE_BUDGET))
                    .map(|(_public, private)| private),
            },
        )?;
        Self::retry_establish(
            sam,
            &private,
            deadline,
            unreachable_after,
            cancelled,
            &Cell::new(false),
        )
    }

    /// Retry root establishment until a session is up, a failure is final,
    /// `cancelled` fires, or the owner `deadline` passes.
    ///
    /// Each attempt fixes its root deadline once, before it connects:
    /// [`ROOT_READINESS_BUDGET`] clipped to `deadline`. While `reached` is
    /// false no bridge has ever accepted a connection, so an attempt's connect
    /// waits no longer than `unreachable_after`, and the retry ends, reporting
    /// its last failure, at the first failure or the end of the pause after a
    /// failure that falls at or past it. A connect cut off by the window
    /// reports `TimedOut`; a refusal that preceded the window is reported as
    /// itself. The first accepted connection sets `reached` for good; nothing
    /// here clears it, so later attempts connect, and fail, under their root
    /// deadline alone.
    #[cfg(test)]
    fn retry_establish(
        sam: SocketAddr,
        private: &str,
        deadline: Instant,
        unreachable_after: Instant,
        cancelled: &dyn Fn() -> bool,
        reached: &Cell<bool>,
    ) -> io::Result<Self> {
        retry_until(
            deadline,
            cancelled,
            || !reached.get() && Instant::now() >= unreachable_after,
            |_left| {
                let root_deadline = (Instant::now() + ROOT_READINESS_BUDGET).min(deadline);
                let connect_deadline = if reached.get() {
                    root_deadline
                } else {
                    root_deadline.min(unreachable_after)
                };
                Self::establish_within(
                    sam,
                    private,
                    EXCHANGE_BUDGET,
                    connect_deadline,
                    root_deadline,
                    cancelled,
                    reached,
                )
            },
        )
    }

    /// Ensure one live root and report the generation that owns it.
    ///
    /// The generation identifies the root this caller's request is issued
    /// against, so later evidence about that root can be retired without
    /// touching a root recovered in the meantime. The recovery lock, the
    /// control lock, and the bridge exchange are all charged to
    /// `deadline`; another caller's budget never extends this call.
    fn ensure_control(&self, deadline: Instant) -> io::Result<u64> {
        if self.closed.load(Ordering::Acquire) {
            return Err(session_closed());
        }
        // Healthy fast path: a live root costs no budget, no recovery
        // lock, and no state change.
        if let Some(generation) = self.live_control_generation(deadline)? {
            return Ok(generation);
        }

        // Recovery is serialized on `recovery`, then `control` — the same
        // order `retire_root` and `close` take. The dead root is shut down
        // while those locks are held so the bridge cannot still own the old
        // session when the replacement `SESSION CREATE` for the same id
        // arrives. The wait for `recovery` is charged to `deadline`, so
        // queueing behind another caller never extends this one.
        let mut recovery = lock_within(&self.recovery, deadline)?;
        if self.closed.load(Ordering::Acquire) {
            return Err(session_closed());
        }
        if let Some(generation) = self.live_control_generation(deadline)? {
            return Ok(generation);
        }
        {
            let mut state = lock_within(&self.control, deadline)?;
            if let Some(dead) = state.conn.take() {
                let _ = dead.writer.shutdown(std::net::Shutdown::Both);
            }
        }
        self.recover_root(&mut recovery, deadline)
    }

    /// Advance the pending root, or start one, then install it when ready.
    ///
    /// `recovery` is held by the caller. The pending root is taken out of it
    /// for the exchange and goes back only when the exchange paused at this
    /// caller's deadline; every other exit either installs it or shuts its
    /// socket down, so no discarded root keeps a bridge session alive.
    fn recover_root(&self, recovery: &mut Recovery, call_deadline: Instant) -> io::Result<u64> {
        let cancelled = || self.closed.load(Ordering::Acquire);
        let mut root = match recovery.pending.take() {
            Some(root) => root,
            // The readiness deadline is fixed here, once per root; resuming
            // never moves it.
            None => PendingRoot::connect(
                self.sam,
                call_deadline,
                Instant::now() + self.root_budget,
                &cancelled,
            )
            .map_err(|stop| stop.into_io(session_closed))?,
        };
        // Register a close-reachable clone of the socket. The `closed`
        // check and the store share the `wake` lock that `close` takes after
        // it stores `closed`, so this root is never left unwakeable.
        let armed = root.conn.reader.try_clone().and_then(|clone| {
            let mut slot = self.wake.lock();
            if self.closed.load(Ordering::Acquire) {
                return Err(session_closed());
            }
            *slot = Some(clone);
            Ok(())
        });
        let outcome = match armed {
            Ok(()) => root.advance(
                &self.id,
                &self.private_destination,
                call_deadline,
                &cancelled,
            ),
            Err(error) => Err(Stop::Failed(error)),
        };
        drop(self.wake.lock().take());
        match outcome {
            Ok(()) => self.install_root(recovery, root, call_deadline),
            Err(Stop::Paused) => {
                recovery.pending = Some(root);
                Err(Stop::Paused.into_io(session_closed))
            }
            Err(stop) => {
                let _ = root.conn.writer.shutdown(std::net::Shutdown::Both);
                // A wake-induced failure is the close, not a bridge fault.
                Err(if self.closed.load(Ordering::Acquire) {
                    session_closed()
                } else {
                    stop.into_io(session_closed)
                })
            }
        }
    }

    /// Publish a root whose exchange completed.
    ///
    /// The generation rises only here, and only when nothing refuses the
    /// root: `close`, the root's own deadline, a public destination that is
    /// not ours, or an exhausted counter each discard it with the generation
    /// untouched. `recovery` stays held, so `close` cannot drain between
    /// these checks and the install; a close that already stored `closed`
    /// waits for `recovery` and then removes the root installed here. If this
    /// caller's deadline passes while waiting for `control`, the complete
    /// root stays pending for the next caller instead of being repeated.
    fn install_root(
        &self,
        recovery: &mut Recovery,
        root: PendingRoot,
        call_deadline: Instant,
    ) -> io::Result<u64> {
        let mut state = match lock_within(&self.control, call_deadline) {
            Ok(state) => state,
            Err(error) => {
                recovery.pending = Some(root);
                return Err(error);
            }
        };
        let verdict = if self.closed.load(Ordering::Acquire) {
            Err(session_closed())
        } else if Instant::now() >= root.deadline {
            Err(Stop::Expired.into_io(session_closed))
        } else if !matches!(&root.phase, RootPhase::Ready(reported) if *reported == self.destination)
        {
            Err(invalid(
                "sam re-established session public destination mismatch",
            ))
        } else {
            state
                .generation
                .checked_add(1)
                .ok_or_else(|| io::Error::other("sam root generation exhausted"))
        };
        match verdict {
            Ok(generation) => {
                state.generation = generation;
                state.conn = Some(root.conn);
                Ok(generation)
            }
            Err(error) => {
                let _ = root.conn.writer.shutdown(std::net::Shutdown::Both);
                Err(error)
            }
        }
    }

    /// Generation of the installed root while the bridge still holds it.
    ///
    /// The probe costs one non-blocking peek under `control` only. Its
    /// answer describes the root at this instant, so retirement re-checks
    /// the generation under the same exclusion instead of trusting it.
    fn live_control_generation(&self, deadline: Instant) -> io::Result<Option<u64>> {
        let mut state = lock_within(&self.control, deadline)?;
        let alive = state.conn.as_mut().is_some_and(SamConn::is_alive);
        Ok(alive.then_some(state.generation))
    }

    /// Retire the installed root when it is still generation `observed`.
    ///
    /// `observed` names the root a request was issued against. Evidence
    /// from that request — `STREAM STATUS RESULT=INVALID_ID` — is evidence
    /// about that root alone, so a root installed while the evidence was in
    /// flight has a newer generation and survives. The comparison and the
    /// removal happen under `control` while `recovery` is held, so no
    /// install can slip between them, and the wait is charged to `deadline`.
    fn retire_root(&self, observed: u64, deadline: Instant) -> io::Result<()> {
        let _recovery = lock_within(&self.recovery, deadline)?;
        let mut state = lock_within(&self.control, deadline)?;
        if state.generation != observed {
            return Ok(());
        }
        if let Some(conn) = state.conn.take() {
            let _ = conn.writer.shutdown(std::net::Shutdown::Both);
        }
        Ok(())
    }

    /// Our public destination in SAM base64 form.
    #[must_use]
    pub fn destination(&self) -> &str {
        &self.destination
    }

    /// The per-instance SAM session id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The `.b32.i2p` name of our own destination.
    #[must_use]
    pub fn b32_name(&self) -> Option<String> {
        let bytes = i2p_base64_decode(&self.destination)?;
        Some(format!(
            "{}.b32.i2p",
            base32_encode(&destination_hash(&bytes))
        ))
    }

    /// Parse and validate our local public destination as a typed
    /// [`PeerEndpoint::I2p`] at `port`. Fails closed if the destination
    /// is structurally invalid or corrupt.
    pub fn local_endpoint(&self, port: u16) -> io::Result<crate::PeerEndpoint> {
        let bytes = i2p_base64_decode(&self.destination)
            .filter(|b| valid_destination(b))
            .ok_or_else(|| invalid("sam local destination is not a valid destination"))?;
        Ok(crate::PeerEndpoint::I2p {
            hash: destination_hash(&bytes),
            port,
        })
    }

    fn naming_lookup_with_deadline(
        &self,
        name: &str,
        deadline: Instant,
    ) -> io::Result<(String, [u8; 32])> {
        let mut conn = SamConn::connect_with_deadline(self.sam, deadline)?;
        conn.hello(deadline)?;
        let reply = conn.command(&format!("NAMING LOOKUP NAME={name}"), deadline)?;
        let fields = require_ok(&reply, "NAMING REPLY")?;
        let value = field(&fields, "VALUE")
            .map(str::to_owned)
            .ok_or_else(|| invalid("sam naming reply carries no value"))?;
        let bytes = i2p_base64_decode(&value)
            .filter(|bytes| valid_destination(bytes))
            .ok_or_else(|| invalid("sam naming value is not a valid destination"))?;
        let hash = destination_hash(&bytes);
        Ok((value, hash))
    }

    /// Dial the peer identified by `hash` at `port` over a fresh bridge.
    ///
    /// Local bridge failures (connect, hello, lookup, protocol) are
    /// [`DialFailure::Transport`]; only a bridge-reported
    /// `CANT_REACH_PEER` or `TIMEOUT` is [`DialFailure::PeerUnreachable`].
    pub fn connect(
        &self,
        hash: [u8; 32],
        port: u16,
    ) -> Result<TcpStream, crate::endpoint::DialFailure> {
        use crate::endpoint::DialFailure;
        if self.closed.load(Ordering::Acquire) {
            return Err(DialFailure::Transport(io::Error::new(
                io::ErrorKind::NotConnected,
                "sam session is closed",
            )));
        }
        let deadline = Instant::now() + self.timeout;
        let root = self
            .ensure_control(deadline)
            .map_err(DialFailure::Transport)?;
        let name = format!("{}.b32.i2p", base32_encode(&hash));
        let (destination, resolved_hash) = self
            .naming_lookup_with_deadline(&name, deadline)
            .map_err(DialFailure::Transport)?;
        if resolved_hash != hash {
            return Err(DialFailure::Transport(io::Error::new(
                io::ErrorKind::InvalidData,
                "sam naming destination does not match requested hash",
            )));
        }
        let mut conn =
            SamConn::connect_with_deadline(self.sam, deadline).map_err(DialFailure::Transport)?;
        conn.hello(deadline).map_err(DialFailure::Transport)?;
        let reply = conn
            .command(
                &format!(
                    "STREAM CONNECT ID={} DESTINATION={destination} TO_PORT={port}",
                    self.id
                ),
                deadline,
            )
            .map_err(DialFailure::Transport)?;
        let fields = parse_fields(&reply, "STREAM STATUS").map_err(DialFailure::Transport)?;
        match field(&fields, "RESULT") {
            Some("OK") => Ok(conn.into_stream()),
            Some(result @ ("CANT_REACH_PEER" | "TIMEOUT")) => {
                Err(DialFailure::PeerUnreachable(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    format!("sam peer unreachable: STREAM STATUS RESULT={result}"),
                )))
            }
            Some("INVALID_ID") => {
                // The reply describes the root this request was issued
                // against. Retiring it is bounded by the same deadline, and
                // a root recovered meanwhile keeps a newer generation.
                self.retire_root(root, deadline)
                    .map_err(DialFailure::Transport)?;
                if self.ensure_control(deadline).is_ok() {
                    if let Ok(mut retry_conn) = SamConn::connect_with_deadline(self.sam, deadline) {
                        if retry_conn.hello(deadline).is_ok() {
                            if let Ok(retry_reply) = retry_conn.command(
                                &format!(
                                    "STREAM CONNECT ID={} DESTINATION={destination} TO_PORT={port}",
                                    self.id
                                ),
                                deadline,
                            ) {
                                if let Ok(retry_fields) =
                                    parse_fields(&retry_reply, "STREAM STATUS")
                                {
                                    if field(&retry_fields, "RESULT") == Some("OK") {
                                        return Ok(retry_conn.into_stream());
                                    }
                                }
                            }
                        }
                    }
                }
                Err(DialFailure::Transport(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "sam stream request failed: STREAM STATUS RESULT=INVALID_ID",
                )))
            }
            Some(result) => Err(DialFailure::Transport(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!(
                    "sam stream request failed: STREAM STATUS RESULT={}",
                    sanitize_sam_result(result)
                ),
            ))),
            None => Err(DialFailure::Transport(invalid(
                "sam stream reply carries no result",
            ))),
        }
    }

    /// Accept one inbound stream, waiting at most `wait`. Returns the
    /// bridged stream and the remote endpoint (destination hash + the
    /// `TO_PORT` the peer dialed). An absent `TO_PORT`, or I2CP port `0`
    /// (any or unspecified service), yields the application `fallback_port`;
    /// a nonzero port is returned as reported.
    pub fn accept(
        &self,
        wait: Duration,
        fallback_port: u16,
    ) -> io::Result<(TcpStream, [u8; 32], u16)> {
        if self.closed.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "sam session is closed",
            ));
        }
        let deadline = Instant::now() + wait;
        let root = self.ensure_control(deadline)?;
        let mut conn = SamConn::connect_with_deadline(self.sam, deadline)?;
        conn.hello(deadline)?;
        let reply = conn.command(&format!("STREAM ACCEPT ID={}", self.id), deadline)?;
        let fields = parse_fields(&reply, "STREAM STATUS")?;
        if field(&fields, "RESULT") == Some("INVALID_ID") {
            let _ = self.retire_root(root, deadline);
            let _ = self.ensure_control(deadline);
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "sam stream accept failed: STREAM STATUS RESULT=INVALID_ID",
            ));
        }
        if field(&fields, "RESULT") != Some("OK") {
            let res = sanitize_sam_result(field(&fields, "RESULT").unwrap_or(""));
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!("sam request failed: STREAM STATUS RESULT={res}"),
            ));
        }
        let line = conn.read_line(deadline)?;
        let mut parts = line.split_whitespace();
        let destination = parts
            .next()
            .ok_or_else(|| invalid("sam accepted stream carries no destination"))?;
        // `Some(0)` is retained through the loop so a zero followed by
        // another `TO_PORT` is still a duplicate.
        let mut port: Option<u16> = None;
        for part in parts {
            if let Some(value) = part.strip_prefix("TO_PORT=") {
                if port.is_some() {
                    return Err(invalid("duplicate TO_PORT in sam accepted stream"));
                }
                let parsed: u16 = value
                    .parse()
                    .map_err(|_| invalid("malformed TO_PORT in sam accepted stream"))?;
                port = Some(parsed);
            }
        }
        let port = port.filter(|&p| p != 0).unwrap_or(fallback_port);
        let bytes = i2p_base64_decode(destination)
            .filter(|bytes| valid_destination(bytes))
            .ok_or_else(|| invalid("sam accepted destination is not a valid destination"))?;
        Ok((conn.into_stream(), destination_hash(&bytes), port))
    }

    /// Close the session root; later dials fail closed.
    ///
    /// Order: store `closed`; wake root I/O in progress through `wake`
    /// (released before anything else is taken); then take `recovery` and
    /// drain the pending root and, under `control`, the installed one. No
    /// root can be installed after the drain: every install holds `recovery`
    /// and re-checks `closed`.
    ///
    /// Waiting for `recovery` ends in one of two ways. Once the holder's root
    /// socket exists, the wake interrupts its read or write at once and the
    /// holder reports the close. Before the socket exists there is nothing to
    /// wake: the holder is inside a TCP connect attempt, which cannot be
    /// interrupted, so `close` waits for that one attempt, at most
    /// [`EXCHANGE_BUDGET`], after which the holder sees `closed` before it
    /// starts another. Either way `close` never waits out a readiness budget.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
        {
            let wake = self.wake.lock();
            if let Some(socket) = wake.as_ref() {
                let _ = socket.shutdown(std::net::Shutdown::Both);
            }
        }
        let mut recovery = self.recovery.lock();
        if let Some(pending) = recovery.pending.take() {
            let _ = pending.conn.writer.shutdown(std::net::Shutdown::Both);
        }
        let conn = self.control.lock().conn.take();
        if let Some(conn) = conn {
            let _ = conn.writer.shutdown(std::net::Shutdown::Both);
            drop(conn);
        }
    }
}

/// Run `attempt` until it succeeds, fails for good, is cancelled, or the
/// owner `deadline` passes. `attempt` receives the time left and must clip
/// its own network steps to it. `InvalidData` (a corrupt key or a malformed
/// bridge reply) and `Unsupported` (a bridge that does not speak 3.3) are
/// final, because retrying cannot change them; so is any failure after which
/// `give_up` reports true. `give_up` is consulted again once the pause that
/// follows a failure ends, so a limit that expired during the pause reports
/// that failure instead of spending a doomed attempt. Any other failure
/// pauses and retries. When the deadline ends the loop, the last failure is
/// reported.
#[cfg(test)]
fn retry_until<T>(
    deadline: Instant,
    cancelled: &dyn Fn() -> bool,
    give_up: impl Fn() -> bool,
    mut attempt: impl FnMut(Duration) -> io::Result<T>,
) -> io::Result<T> {
    let mut last: Option<io::Error> = None;
    let mut failures = 0u64;
    loop {
        if cancelled() {
            return Err(startup_cancelled());
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(last.unwrap_or_else(|| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "i2p session startup budget expired",
                )
            }));
        }
        match attempt(left) {
            Ok(value) => return Ok(value),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::InvalidData | io::ErrorKind::Unsupported
                ) =>
            {
                return Err(error);
            }
            Err(error) => {
                if give_up() {
                    return Err(error);
                }
                failures += 1;
                startup_pause(failures, deadline, cancelled)?;
                if give_up() {
                    return Err(error);
                }
                last = Some(error);
            }
        }
    }
}

/// The jittered, growing pause between startup attempts. It is clipped to
/// `deadline`, so it can never extend the owner deadline, and it polls
/// `cancelled` every [`CANCEL_POLL`], so shutdown never waits out a pause.
/// Reaching the deadline is not an error here: the caller's next deadline
/// check reports it with the last failure.
#[cfg(test)]
fn startup_pause(failures: u64, deadline: Instant, cancelled: &dyn Fn() -> bool) -> io::Result<()> {
    let base = Duration::from_millis(failures.min(PAUSE_STEPS_MAX) * PAUSE_STEP_MS);
    let jitter = Duration::from_millis(thread_rng().gen_range(0..=PAUSE_STEP_MS));
    let until = (Instant::now() + base + jitter).min(deadline);
    loop {
        if cancelled() {
            return Err(startup_cancelled());
        }
        let Some(left) = until
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
        else {
            return Ok(());
        };
        std::thread::sleep(left.min(CANCEL_POLL));
    }
}

/// Generate a fresh Ed25519 destination through the bridge.
/// Returns `(public, private)` SAM base64 strings.
///
/// The request is `DEST GENERATE SIGNATURE_TYPE=7`: SAM defaults an omitted
/// type to DSA-SHA1 (the pinned IVNP bridge defaults to 7), so the client
/// selects Ed25519 explicitly and relies on no bridge default. A successful
/// `DEST REPLY` is `DEST REPLY PUB=<pub> PRIV=<priv>` and carries no `RESULT`,
/// unlike every other reply here, which `require_ok` accepts only with
/// `RESULT=OK`. An explicit `RESULT=OK` is not a failure and is tolerated;
/// the key pair is authoritative and still passes full validation. Any other
/// `RESULT` is a failure status, refused before a key field is read even
/// beside keys; only the sanitized result name reaches the error.
#[cfg(test)]
pub(crate) fn generate_destination(
    sam: SocketAddr,
    timeout: Duration,
) -> io::Result<(String, String)> {
    let deadline = Instant::now() + timeout;
    let mut conn = SamConn::connect_with_deadline(sam, deadline)?;
    conn.hello(deadline)?;
    let reply = conn.command("DEST GENERATE SIGNATURE_TYPE=7", deadline)?;
    let fields = parse_fields(&reply, "DEST REPLY")?;
    match field(&fields, "RESULT") {
        None | Some("OK") => {}
        Some(result) => {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!(
                    "sam request failed: DEST REPLY RESULT={}",
                    sanitize_sam_result(result)
                ),
            ));
        }
    }
    let public = field(&fields, "PUB")
        .ok_or_else(|| invalid("dest reply carries no public destination"))?
        .to_owned();
    let private = field(&fields, "PRIV")
        .ok_or_else(|| invalid("dest reply carries no private destination"))?
        .to_owned();
    if i2p_base64_decode(&public).is_none_or(|b| !valid_destination(&b)) {
        return Err(invalid(
            "generated public destination is not a valid destination",
        ));
    }
    validate_private_destination(&private)?;
    Ok((public, private))
}

/// Open a persisted key file; the returned handle owns every later step.
///
/// Unix: the path is resolved exactly once, with `O_RDONLY | O_CLOEXEC |
/// O_NOFOLLOW | O_NONBLOCK`. `O_NOFOLLOW` refuses a final-component
/// symbolic link (a dangling one included, so it never reads as absent),
/// and `O_NONBLOCK` keeps opening a FIFO from waiting for a writer before
/// the type check below can refuse it. Only that handle is used after
/// the open: its type is checked first, a non-regular file is refused
/// before any permission change, a mode other than `0600` is repaired
/// through the handle (`fchmod`), and the caller reads the same handle, so
/// the object checked, repaired, and read cannot differ. Failure to
/// tighten fails closed rather than running with exposed key material.
/// Symbolic links in parent directories are still followed.
///
/// Elsewhere: a plain read-only open with no permission or link policy.
#[cfg(all(test, unix))]
fn open_key_file(path: &Path) -> io::Result<std::fs::File> {
    use rustix::fs::{Mode, OFlags};
    use std::os::unix::fs::PermissionsExt;

    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    let file = std::fs::File::from(fd);
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(invalid("persisted key path is not a regular file"));
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode != 0o600 {
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

/// Open a persisted key file (non-unix): no link or mode policy applies.
#[cfg(all(test, not(unix)))]
fn open_key_file(path: &Path) -> io::Result<std::fs::File> {
    std::fs::File::open(path)
}

/// Load the persisted I2P private destination, generating and persisting
/// it (mode `0600`, create-only) when the file is absent.
///
/// Fails closed on unreadable or corrupt content; never replaces an
/// existing file and never logs the material. A reused file's mode is
/// repaired to `0600` before its content is read. A symbolic link at
/// `key_path` (unix), dangling or not, or any non-regular file is an
/// error and never selects generation: only an absent path does.
#[cfg(test)]
pub(crate) fn load_or_create_private_destination(
    sam: SocketAddr,
    key_path: &Path,
    timeout: Duration,
) -> io::Result<String> {
    match read_key_file(key_path) {
        Ok(text) => validate_private_destination(text.trim()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let (_public, private) = generate_destination(sam, timeout)?;
            write_key_file(key_path, &private)?;
            Ok(private)
        }
        Err(error) => Err(error),
    }
}

fn destination_identity_and_types(bytes: &[u8]) -> Option<(usize, u16, u16)> {
    const BASE: usize = 384;
    let total = destination_identity_len(bytes)?;
    let cert_type = bytes[BASE];
    let (signing, crypto) = if cert_type == 5 {
        let payload = &bytes[BASE + 3..total];
        if payload.len() < 4 {
            return None;
        }
        (
            u16::from_be_bytes([payload[0], payload[1]]),
            u16::from_be_bytes([payload[2], payload[3]]),
        )
    } else {
        (0, 0)
    };
    Some((total, signing, crypto))
}

fn signing_public_key_len(signing: u16) -> Option<usize> {
    match signing {
        0 | 10 => Some(128),
        1 | 9 => Some(64),
        2 => Some(96),
        3 => Some(132),
        4 => Some(256),
        5 => Some(384),
        6 => Some(512),
        7 | 8 | 11 => Some(32),
        _ => None,
    }
}

fn signing_signature_len(signing: u16) -> Option<usize> {
    match signing {
        0 => Some(40),
        1 | 7 | 8 | 9 | 11 => Some(64),
        2 => Some(96),
        3 => Some(132),
        4 => Some(256),
        5 => Some(384),
        6 => Some(512),
        10 => Some(128),
        _ => None,
    }
}

fn validate_private_destination(text: &str) -> io::Result<String> {
    const SIGNING_LENGTH: usize = 32;
    let wire = i2p_base64_decode(text)
        .ok_or_else(|| invalid("persisted i2p destination key is corrupt base64"))?;
    let (consumed, signing_type, crypto_type) = destination_identity_and_types(&wire)
        .ok_or_else(|| invalid("persisted i2p destination key has invalid identity"))?;

    let encryption_len = match crypto_type {
        4 => 32,
        0 => 256,
        _ => return Err(invalid("unsupported i2p private crypto key type")),
    };

    match signing_type {
        7 => {}
        11 if crypto_type == 4 => {}
        _ => return Err(invalid("unsupported i2p private signing key type")),
    }

    if wire.len() < consumed + encryption_len + SIGNING_LENGTH {
        return Err(invalid(
            "persisted i2p private destination key is truncated",
        ));
    }

    let signing = &wire[consumed + encryption_len..consumed + encryption_len + SIGNING_LENGTH];
    let offline_section = &wire[consumed + encryption_len + SIGNING_LENGTH..];

    if signing.iter().all(|&b| b == 0) {
        if offline_section.len() < 6 {
            return Err(invalid("malformed offline i2p key section"));
        }
        let offline_key_type = u16::from_be_bytes([offline_section[4], offline_section[5]]);
        let pub_len = signing_public_key_len(offline_key_type)
            .ok_or_else(|| invalid("unknown offline key type"))?;
        let sig_len = signing_signature_len(signing_type)
            .ok_or_else(|| invalid("unknown signing signature length"))?;
        if offline_section.len() != 6 + pub_len + sig_len + 32 {
            return Err(invalid("invalid offline i2p key section length"));
        }
    } else if !offline_section.is_empty() {
        return Err(invalid(
            "persisted i2p destination key has unexpected trailing bytes",
        ));
    }

    Ok(text.to_owned())
}

#[cfg(test)]
struct TempCleanup<'a>(&'a Path);

#[cfg(test)]
impl Drop for TempCleanup<'_> {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.0);
    }
}

/// Write `contents` as a new mode-`0600` file; refuse to replace.
#[cfg(test)]
pub(crate) fn write_key_file(path: &Path, contents: &str) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut nonce = [0u8; 8];
    thread_rng().fill_bytes(&mut nonce);
    let temp_name = format!(
        ".{}.tmp.{:016x}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("key"),
        u64::from_ne_bytes(nonce)
    );
    let temp_path = parent.join(temp_name);
    let cleanup = TempCleanup(&temp_path);

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    {
        let mut file = options.open(&temp_path)?;
        file.write_all(contents.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
    }

    // Atomic publication without replacing an existing file.
    // std::fs::hard_link fails with AlreadyExists if path already exists.
    std::fs::hard_link(&temp_path, path)?;

    // Temp file can be removed now; drop guard will harmlessly find it gone.
    let _ = std::fs::remove_file(&temp_path);
    drop(cleanup);

    // Sync parent directory to ensure directory entry is durable.
    let dir = std::fs::File::open(parent)?;
    dir.sync_all()?;

    Ok(())
}

/// Read a persisted key file, failing closed on corrupt content. On unix
/// the file is opened once without following a final symbolic link, must
/// be a regular file, has its mode repaired to `0600` through that handle,
/// and is read through the same handle (see `open_key_file`). Callers treat
/// only `NotFound` as an absent key; every other error is refused.
#[cfg(test)]
pub(crate) fn read_key_file(path: &Path) -> io::Result<String> {
    let mut file = open_key_file(path)?;
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed.chars().any(char::is_whitespace) {
        return Err(invalid("persisted key file is corrupt"));
    }
    Ok(trimmed.to_owned())
}

#[cfg(test)]
mod tests;
