//! Peekable stream wrapper for protocol detection.
//!
//! Allows reading bytes from a stream and then "unreading" them so they
//! can be consumed by subsequent readers (like HTTP or binary protocol handlers).

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A stream wrapper that allows peeking at the first bytes.
///
/// After reading the prefix bytes, they are buffered and will be
/// returned first on subsequent reads.
pub struct PeekableStream<S> {
    inner: S,
    buffer: Vec<u8>,
    pos: usize,
}

impl<S> PeekableStream<S> {
    /// Create a new peekable stream with a pre-read buffer.
    ///
    /// The `prefix` bytes will be returned first when reading from this stream.
    pub fn new(inner: S, prefix: Vec<u8>) -> Self {
        Self {
            inner,
            buffer: prefix,
            pos: 0,
        }
    }

    /// Get a reference to the inner stream.
    #[allow(dead_code)]
    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    /// Get a mutable reference to the inner stream.
    #[allow(dead_code)]
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Consume the wrapper and return the inner stream.
    #[allow(dead_code)]
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PeekableStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // First, drain any buffered bytes
        if self.pos < self.buffer.len() {
            let remaining = &self.buffer[self.pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.pos += to_copy;
            return Poll::Ready(Ok(()));
        }

        // Buffer exhausted, read from inner stream
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PeekableStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
