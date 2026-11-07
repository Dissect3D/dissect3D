//! Retain wire framing facts that Hyper normalizes before route authorization.
//! Hyper still owns HTTP parsing, limits, and errors. No body bytes are retained.

use std::io;
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Clone, Default)]
pub(super) struct WireFraming(Arc<AtomicBool>);

impl WireFraming {
    #[cfg(any(unix, test))]
    pub(super) fn duplicate_length(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

pub(super) struct FramingIo<T> {
    inner: T,
    headers: Option<Vec<u8>>,
    framing: WireFraming,
}

impl<T> FramingIo<T> {
    pub(super) fn new(inner: T, framing: WireFraming) -> Self {
        Self {
            inner,
            headers: Some(Vec::new()),
            framing,
        }
    }

    fn observe(&mut self, bytes: &[u8]) {
        let Some(headers) = &mut self.headers else {
            return;
        };
        for &byte in bytes {
            headers.push(byte);
            if headers.ends_with(b"\r\n\r\n") {
                let count = headers
                    .split(|&byte| byte == b'\n')
                    .skip(1)
                    .filter(|line| {
                        line.split(|&byte| byte == b':')
                            .next()
                            .is_some_and(|name| name.eq_ignore_ascii_case(b"content-length"))
                    })
                    .count();
                self.framing.0.store(count > 1, Ordering::Relaxed);
                self.headers = None;
                return;
            }
            if headers.len() >= super::MAX_HEADER_BYTES {
                // Hyper rejects oversized headers; stop retaining the prefix.
                self.headers = None;
                return;
            }
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for FramingIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let start = buffer.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buffer);
        if let Poll::Ready(Ok(())) = result {
            self.observe(&buffer.filled()[start..]);
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for FramingIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retains_duplicate_lengths_across_reads_without_scanning_the_body() {
        let framing = WireFraming::default();
        let mut io = FramingIo::new((), framing.clone());
        io.observe(b"POST /v1/inputs HTTP/1.1\r\nContent-Len");
        io.observe(b"gth: 1\r\ncOnTeNt-LeNgTh: 1\r\n\r\nx");
        assert!(framing.duplicate_length());
        assert!(io.headers.is_none());

        let framing = WireFraming::default();
        let mut io = FramingIo::new((), framing.clone());
        io.observe(b"POST /v1/inputs HTTP/1.1\r\nContent-Length: 50\r\n\r\nContent-Length: 1\r\n");
        assert!(!framing.duplicate_length());
        assert!(io.headers.is_none());
    }
}
