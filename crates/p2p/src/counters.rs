//! Per-connection traffic counters.

use bitcoin_rs_primitives::unix_time_secs;

use std::io::{IoSlice, IoSliceMut, Read, Result as IoResult, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Bytes and activity times for one peer connection.
///
/// Every field is a snapshot: a reader may see the byte count from after a
/// write and the timestamp from before it. That is what `getpeerinfo` wants --
/// the alternative is a lock on the socket path for the sake of an RPC.
#[derive(Debug, Default)]
pub struct PeerCounters {
    bytes_sent: AtomicU64,
    bytes_recv: AtomicU64,
    last_send: AtomicU64,
    last_recv: AtomicU64,
}

impl PeerCounters {
    /// Total bytes written to the peer, wire framing included.
    #[must_use]
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    /// Total bytes read from the peer, wire framing included.
    #[must_use]
    pub fn bytes_recv(&self) -> u64 {
        self.bytes_recv.load(Ordering::Relaxed)
    }

    /// Unix seconds of the last write, or zero if nothing has been sent.
    #[must_use]
    pub fn last_send(&self) -> u64 {
        self.last_send.load(Ordering::Relaxed)
    }

    /// Unix seconds of the last read, or zero if nothing has been received.
    #[must_use]
    pub fn last_recv(&self) -> u64 {
        self.last_recv.load(Ordering::Relaxed)
    }

    fn record_sent(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        let _previous = self
            .bytes_sent
            .fetch_add(u64::try_from(bytes).unwrap_or(0), Ordering::Relaxed);
        self.last_send.store(unix_time_secs(), Ordering::Relaxed);
    }

    fn record_recv(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        let _previous = self
            .bytes_recv
            .fetch_add(u64::try_from(bytes).unwrap_or(0), Ordering::Relaxed);
        self.last_recv.store(unix_time_secs(), Ordering::Relaxed);
    }
}

/// Compares the four counts, which is what a snapshot of a connection is.
impl PartialEq for PeerCounters {
    fn eq(&self, other: &Self) -> bool {
        self.bytes_sent() == other.bytes_sent()
            && self.bytes_recv() == other.bytes_recv()
            && self.last_send() == other.last_send()
            && self.last_recv() == other.last_recv()
    }
}

impl Eq for PeerCounters {}

/// A stream that counts everything passing through it.
///
/// Wrapping the stream is what makes the count complete. A connection's bytes
/// move through three separate pieces of code -- the handshake, the reader
/// loop, and the writer thread that owns a cloned socket -- so a counter added
/// at any one of them would report a fraction of the traffic as though it were
/// all of it.
///
/// Reads are buffered so a kernel delivery that holds more than one message
/// does not cost a syscall per `read_exact` of the 24-byte header. Large
/// caller buffers (block payloads) bypass the cache and read into the
/// destination. The writer-side `try_clone` starts with an empty read cache.
#[derive(Debug)]
pub struct CountingStream<S> {
    inner: S,
    counters: Arc<PeerCounters>,
    /// The connection owner's cancellation view, including its transport epoch.
    lease: Option<crate::PeerLease>,
    read_buf: Vec<u8>,
    read_pos: usize,
    read_end: usize,
}

/// Matches `std::io::BufReader`'s default.
/// Unauthenticated inbound peers allocate this on their first small read;
/// keep it small to bound the memory pinned by half-open handshakes.
const INBOUND_READ_BUFFER: usize = 8 * 1024;

impl<S> CountingStream<S> {
    /// Wraps `inner`, counting into `counters`.
    #[must_use]
    pub const fn new(inner: S, counters: Arc<PeerCounters>) -> Self {
        Self {
            inner,
            counters,
            lease: None,
            read_buf: Vec::new(),
            read_pos: 0,
            read_end: 0,
        }
    }

    /// The counters this stream feeds.
    #[must_use]
    pub const fn counters(&self) -> &Arc<PeerCounters> {
        &self.counters
    }

    /// Makes every read consult the lease, so a trickling payload cannot keep
    /// a locally cancelled or transport-revoked connection alive mid-frame.
    #[must_use]
    pub(crate) fn stop_reading_when(mut self, lease: crate::PeerLease) -> Self {
        self.lease = Some(lease);
        self
    }

    fn check_cancelled(&self) -> IoResult<()> {
        if self
            .lease
            .as_ref()
            .is_some_and(crate::PeerLease::is_cancelled)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "connection cancelled",
            ));
        }
        Ok(())
    }
}

impl CountingStream<std::net::TcpStream> {
    /// Takes a connected TCP stream and applies the P2P-04 socket contract.
    ///
    /// Disables Nagle so pipelined control messages (`inv`, `getdata`, `ping`)
    /// are not held for a delayed ACK. Handshake and the message loop still
    /// set their own read/write timeouts: those intervals differ by phase.
    ///
    /// # Errors
    ///
    /// Returns the error `TcpStream::set_nodelay` returned.
    pub(crate) fn from_connected(
        stream: std::net::TcpStream,
        counters: Arc<PeerCounters>,
    ) -> IoResult<Self> {
        stream.set_nodelay(true)?;
        Ok(Self::new(stream, counters))
    }

    /// Whether Nagle's algorithm is disabled on this socket.
    pub fn nodelay(&self) -> IoResult<bool> {
        self.inner.nodelay()
    }

    /// Clones the socket, keeping the same counters.
    ///
    /// The writer thread takes a clone; both halves of the connection must
    /// count into one place or `bytessent` reports only the handshake.
    ///
    /// # Errors
    ///
    /// Returns the error `TcpStream::try_clone` returned.
    pub fn try_clone(&self) -> IoResult<Self> {
        Ok(Self::new(
            self.inner.try_clone()?,
            Arc::clone(&self.counters),
        ))
    }

    /// Applies a read timeout to the wrapped socket.
    pub fn set_read_timeout(&self, timeout: Option<core::time::Duration>) -> IoResult<()> {
        self.inner.set_read_timeout(timeout)
    }

    /// The local address the connection is bound to.
    pub fn local_addr(&self) -> IoResult<std::net::SocketAddr> {
        self.inner.local_addr()
    }

    /// Closes one or both halves of the connection.
    pub fn shutdown(&self, how: std::net::Shutdown) -> IoResult<()> {
        self.inner.shutdown(how)
    }
}

impl<S: Read> CountingStream<S> {
    fn take_leftover(&mut self, buffer: &mut [u8]) -> Option<usize> {
        if self.read_pos >= self.read_end {
            return None;
        }
        let take = (self.read_end - self.read_pos).min(buffer.len());
        buffer[..take].copy_from_slice(&self.read_buf[self.read_pos..self.read_pos + take]);
        self.read_pos += take;
        Some(take)
    }

    fn fill_read_buf(&mut self) -> IoResult<()> {
        if self.read_buf.len() < INBOUND_READ_BUFFER {
            self.read_buf.resize(INBOUND_READ_BUFFER, 0);
        }
        // Indices move only after a successful read. Resetting `read_pos`
        // first would make a timeout revive already-consumed leftover bytes;
        // the handshake and message loops retry TimedOut/WouldBlock.
        let filled = self.inner.read(&mut self.read_buf)?;
        self.read_pos = 0;
        self.read_end = filled;
        Ok(())
    }

    fn read_buffered(&mut self, buffer: &mut [u8]) -> IoResult<usize> {
        if let Some(take) = self.take_leftover(buffer) {
            return Ok(take);
        }
        if buffer.len() >= INBOUND_READ_BUFFER {
            return self.inner.read(buffer);
        }
        self.fill_read_buf()?;
        Ok(self.take_leftover(buffer).unwrap_or(0))
    }
}

impl<S: Read> Read for CountingStream<S> {
    fn read(&mut self, buffer: &mut [u8]) -> IoResult<usize> {
        self.check_cancelled()?;
        if buffer.is_empty() {
            return Ok(0);
        }
        let read = self.read_buffered(buffer)?;
        self.counters.record_recv(read);
        Ok(read)
    }

    fn read_vectored(&mut self, buffers: &mut [IoSliceMut<'_>]) -> IoResult<usize> {
        self.check_cancelled()?;
        let read = self.inner.read_vectored(buffers)?;
        self.counters.record_recv(read);
        Ok(read)
    }
}
impl<S: Write> Write for CountingStream<S> {
    fn write(&mut self, buffer: &[u8]) -> IoResult<usize> {
        let written = self.inner.write(buffer)?;
        self.counters.record_sent(written);
        Ok(written)
    }

    /// Production `write_message` emits the 24-byte header and payload as
    /// one `write_vectored` call. The default `Write` adapter would write
    /// only the first slice, splitting that into two syscalls and counting
    /// only the header if the caller treated the return as a full write.
    fn write_vectored(&mut self, buffers: &[IoSlice<'_>]) -> IoResult<usize> {
        let written = self.inner.write_vectored(buffers)?;
        self.counters.record_sent(written);
        Ok(written)
    }

    fn flush(&mut self) -> IoResult<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests;
