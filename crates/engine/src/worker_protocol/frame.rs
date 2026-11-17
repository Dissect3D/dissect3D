//! Finite LF-delimited frame splitting (WC-001). Pure: no I/O, no clock.
//!
//! A frame is at most `FRAME_BYTES_MAX` bytes including its LF. The partial
//! line is checked against that bound before any byte is copied, so an
//! oversized or never-terminated frame is rejected without unbounded
//! allocation. Complete frames wait in a queue of at most
//! `BUFFERED_FRAMES_MAX`; when it is full `push` stops consuming (backpressure)
//! instead of growing or dropping frames. UTF-8 is checked on the complete
//! frame, so a multibyte character may be split across reads.
use super::{BUFFERED_FRAMES_MAX, FRAME_BYTES_MAX, ProtocolViolation};
use std::collections::VecDeque;

#[derive(Debug, Default)]
pub(crate) struct FrameDecoder {
    partial: Vec<u8>,
    ready: VecDeque<String>,
    failed: Option<ProtocolViolation>,
}

impl FrameDecoder {
    /// Consume bytes up to the next full queue. Returns how many were consumed;
    /// the caller drains `next_frame` and pushes the rest. After a violation the
    /// decoder stays failed.
    pub(crate) fn push(&mut self, bytes: &[u8]) -> Result<usize, ProtocolViolation> {
        if let Some(violation) = self.failed {
            return Err(violation);
        }
        let mut consumed = 0;
        while consumed < bytes.len() && self.ready.len() < BUFFERED_FRAMES_MAX {
            let rest = &bytes[consumed..];
            let (body, terminated) = match rest.iter().position(|b| *b == b'\n') {
                Some(end) => (&rest[..end], true),
                None => (rest, false),
            };
            // Frame bytes including the LF that ends (or would end) it.
            let length = self.partial.len() + body.len() + 1;
            if length > FRAME_BYTES_MAX {
                return Err(self.fail(ProtocolViolation::OversizedFrame));
            }
            self.partial.extend_from_slice(body);
            consumed += body.len();
            if !terminated {
                break;
            }
            consumed += 1;
            let frame = std::mem::take(&mut self.partial);
            match String::from_utf8(frame) {
                Ok(text) if !text.is_empty() => self.ready.push_back(text),
                Ok(_) => return Err(self.fail(ProtocolViolation::MalformedFrame)),
                Err(_) => return Err(self.fail(ProtocolViolation::InvalidUtf8)),
            }
        }
        Ok(consumed)
    }

    pub(crate) fn next_frame(&mut self) -> Option<String> {
        self.ready.pop_front()
    }

    /// End of stream: a partial frame is incomplete, never a frame.
    pub(crate) fn finish(&mut self) -> Result<(), ProtocolViolation> {
        if let Some(violation) = self.failed {
            return Err(violation);
        }
        if !self.partial.is_empty() {
            return Err(self.fail(ProtocolViolation::IncompleteFrame));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn buffered(&self) -> usize {
        self.ready.len()
    }

    fn fail(&mut self, violation: ProtocolViolation) -> ProtocolViolation {
        self.partial = Vec::new();
        self.ready.clear();
        self.failed = Some(violation);
        violation
    }
}
