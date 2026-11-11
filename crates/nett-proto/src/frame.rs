//! Envelope encoding and fragmentation (design/protocol.md sections 4.1, 11): one Noise message
//! carries one Envelope; an Envelope that exceeds [`MAX_ENVELOPE`] after encoding is split into
//! several `Chunk`s, which the receiver reassembles by `stream_id` and then decodes into the
//! original Envelope.

use std::collections::BTreeMap;

use prost::Message as _;

use crate::v1::envelope::Body;
use crate::v1::{Chunk, Envelope};

/// Upper limit of a single encoded Envelope: with the Noise authentication tag added it still fits
/// in a single Noise message.
pub const MAX_ENVELOPE: usize = 60 * 1024;
/// Data carried by each fragment: leaves room for the Chunk's and Envelope's own fields.
const CHUNK_DATA: usize = MAX_ENVELOPE - 256;
/// Upper limit of a single fragment stream after reassembly.
pub const MAX_STREAM: usize = 8 << 20;
/// Streams being reassembled at the same time.
pub const MAX_STREAMS: usize = 2;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    #[error("message is not a valid envelope: {0}")]
    Decode(String),
    #[error("message is larger than {MAX_ENVELOPE} bytes")]
    TooLarge,
    #[error("a chunked message is larger than {MAX_STREAM} bytes")]
    StreamTooLarge,
    #[error("more than {MAX_STREAMS} chunked messages at once")]
    TooManyStreams,
    #[error("chunk {seq} of stream {stream} is out of order")]
    OutOfOrder { stream: u64, seq: u32 },
    #[error("a chunked message contains another chunk")]
    Nested,
}

/// Encodes an Envelope into one or several messages to send (each no larger than [`MAX_ENVELOPE`]).
/// `next_id` assigns a number to the fragmented Envelope, and `stream_id` is the fragment stream
/// number of this message.
pub fn encode(
    envelope: &Envelope,
    next_id: &mut u64,
    stream_id: u64,
) -> Result<Vec<Vec<u8>>, FrameError> {
    let bytes = envelope.encode_to_vec();
    if bytes.len() <= MAX_ENVELOPE {
        return Ok(vec![bytes]);
    }
    if bytes.len() > MAX_STREAM {
        return Err(FrameError::StreamTooLarge);
    }
    let pieces: Vec<&[u8]> = bytes.chunks(CHUNK_DATA).collect();
    let last = pieces.len() - 1;
    let mut out = Vec::with_capacity(pieces.len());
    for (seq, data) in pieces.into_iter().enumerate() {
        *next_id += 1;
        let chunk = Envelope {
            id: *next_id,
            reply_to: 0,
            sent_at: None,
            body: Some(Body::Chunk(Chunk {
                stream_id,
                seq: u32::try_from(seq).map_err(|_| FrameError::StreamTooLarge)?,
                last: seq == last,
                data: data.to_vec(),
            })),
        };
        let encoded = chunk.encode_to_vec();
        if encoded.len() > MAX_ENVELOPE {
            return Err(FrameError::TooLarge);
        }
        out.push(encoded);
    }
    Ok(out)
}

/// Reassembles fragments: yields a complete Envelope when it is received.
#[derive(Debug, Default)]
pub struct Reassembler {
    streams: BTreeMap<u64, (u32, Vec<u8>)>,
}

impl Reassembler {
    /// Handles a received message. Returns `None` when it is a fragment and has not been completely
    /// received.
    pub fn push(&mut self, message: &[u8]) -> Result<Option<Envelope>, FrameError> {
        if message.len() > MAX_ENVELOPE {
            return Err(FrameError::TooLarge);
        }
        let envelope = Envelope::decode(message).map_err(|e| FrameError::Decode(e.to_string()))?;
        let Some(Body::Chunk(chunk)) = envelope.body else {
            return Ok(Some(envelope));
        };
        if !self.streams.contains_key(&chunk.stream_id) {
            if chunk.seq != 0 {
                return Err(FrameError::OutOfOrder {
                    stream: chunk.stream_id,
                    seq: chunk.seq,
                });
            }
            if self.streams.len() >= MAX_STREAMS {
                return Err(FrameError::TooManyStreams);
            }
            self.streams.insert(chunk.stream_id, (0, Vec::new()));
        }
        let (next, buf) = self
            .streams
            .get_mut(&chunk.stream_id)
            .expect("inserted above");
        if chunk.seq != *next {
            let stream = chunk.stream_id;
            self.streams.remove(&stream);
            return Err(FrameError::OutOfOrder {
                stream,
                seq: chunk.seq,
            });
        }
        if buf.len() + chunk.data.len() > MAX_STREAM {
            self.streams.remove(&chunk.stream_id);
            return Err(FrameError::StreamTooLarge);
        }
        buf.extend_from_slice(&chunk.data);
        *next += 1;
        if !chunk.last {
            return Ok(None);
        }
        let (_, whole) = self
            .streams
            .remove(&chunk.stream_id)
            .expect("present above");
        let inner =
            Envelope::decode(whole.as_slice()).map_err(|e| FrameError::Decode(e.to_string()))?;
        if matches!(inner.body, Some(Body::Chunk(_))) {
            return Err(FrameError::Nested);
        }
        Ok(Some(inner))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1::{DesiredState, Partition, PartitionKind, Ping};

    fn desired(size: usize) -> Envelope {
        Envelope {
            id: 1,
            reply_to: 0,
            sent_at: None,
            body: Some(Body::DesiredState(DesiredState {
                generation: 7,
                base_generation: 0,
                partitions: vec![Partition {
                    kind: PartitionKind::Mesh as i32,
                    content: vec![b'x'; size],
                }],
            })),
        }
    }

    #[test]
    fn small_envelopes_go_as_one_message() {
        let ping = Envelope {
            id: 3,
            reply_to: 0,
            sent_at: None,
            body: Some(Body::Ping(Ping {})),
        };
        let mut id = 10;
        let out = encode(&ping, &mut id, 1).expect("encoded");
        assert_eq!(out.len(), 1);
        assert_eq!(id, 10);
        let mut r = Reassembler::default();
        assert_eq!(r.push(&out[0]).expect("decoded"), Some(ping));
    }

    #[test]
    fn large_envelopes_are_chunked_and_reassembled() {
        let big = desired(200 * 1024);
        let mut id = 1;
        let out = encode(&big, &mut id, 9).expect("encoded");
        assert!(out.len() >= 4);
        assert!(out.iter().all(|m| m.len() <= MAX_ENVELOPE));
        let mut r = Reassembler::default();
        for m in &out[..out.len() - 1] {
            assert_eq!(r.push(m).expect("partial"), None);
        }
        assert_eq!(r.push(&out[out.len() - 1]).expect("whole"), Some(big));
        // Skip a fragment: rejected, and this stream is dropped
        let mut r = Reassembler::default();
        r.push(&out[0]).expect("first");
        assert!(matches!(
            r.push(&out[2]),
            Err(FrameError::OutOfOrder { .. })
        ));
        // Over the limit: not sent
        assert_eq!(
            encode(&desired(MAX_STREAM + 1), &mut id, 2),
            Err(FrameError::StreamTooLarge)
        );
        assert!(r.push(&[0xff; 10]).is_err());
    }
}
