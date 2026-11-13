//! Rebuild ClientHellos that span several TCP segments (1.x's
//! `frfw.tlsfp.reassembly`, phase 19).
//!
//! A modern browser's ClientHello often doesn't fit one packet: the
//! hybrid post-quantum key share alone is 1,216 bytes, so the hello is
//! ~1.7-2 KB and arrives in two segments. The XDP program hands over the
//! first segment of every ClientHello plus the next few segments of the
//! same flow. This keeps a small per-flow buffer, places segments by TCP
//! sequence number (so retransmissions and reordering are harmless), and
//! returns the handshake message once it is complete. Everything is
//! bounded: flows, bytes per flow, and age.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::hash::Hash;

use crate::clienthello::{MAX_HELLO_BYTES, ParseError, handshake_from_records};
use crate::ordered::{OrderedMap, py_min_by};

pub const MAX_FLOWS: usize = 4096;
pub const FLOW_TIMEOUT_SECONDS: f64 = 5.0;

/// A segment this far past the hello's first byte (or more) is not part
/// of it: the hello's cap plus four record headers.
const MAX_OFFSET: u32 = (MAX_HELLO_BYTES + 5 * 4) as u32;

struct Flow {
    /// Sequence number of the hello's first byte.
    isn: u32,
    started: f64,
    /// Offset from `isn` -> the bytes first seen there.
    chunks: BTreeMap<u32, Vec<u8>>,
}

/// `K` identifies a flow; the daemon uses (source address, source port,
/// destination address, destination port).
pub struct Reassembler<K> {
    flows: OrderedMap<K, Flow>,
    pub max_flows: usize,
    pub timeout: f64,
}

impl<K: Eq + Hash + Clone> Default for Reassembler<K> {
    fn default() -> Self {
        Self::new(MAX_FLOWS, FLOW_TIMEOUT_SECONDS)
    }
}

impl<K: Eq + Hash + Clone> Reassembler<K> {
    pub fn new(max_flows: usize, timeout: f64) -> Self {
        Self {
            flows: OrderedMap::new(),
            max_flows,
            timeout,
        }
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.len() == 0
    }

    /// Feed one segment. `first` marks the segment that starts the hello
    /// (its payload begins with the TLS record header). Returns the
    /// complete handshake message once available. A flow whose bytes
    /// turn out not to be a ClientHello is dropped and the error
    /// returned.
    pub fn add(
        &mut self,
        key: &K,
        seq: u32,
        payload: &[u8],
        now: f64,
        first: bool,
    ) -> Result<Option<Vec<u8>>, ParseError> {
        self.expire(now);
        if first {
            if !self.flows.contains_key(key)
                && self.flows.len() >= self.max_flows
                && let Some(oldest) = py_min_by(self.flows.iter(), |f| f.started)
            {
                let oldest = oldest.clone();
                self.flows.remove(&oldest);
            }
            // A new hello on a known flow starts over, in the flow's place.
            self.flows.insert(
                key.clone(),
                Flow {
                    isn: seq,
                    started: now,
                    chunks: BTreeMap::new(),
                },
            );
        }
        let Some(flow) = self.flows.get_mut(key) else {
            return Ok(None);
        };
        let offset = seq.wrapping_sub(flow.isn);
        if offset >= MAX_OFFSET {
            return Ok(None); // not part of this hello (or a wrapped, stale seq)
        }
        let keep = &payload[..payload.len().min(MAX_HELLO_BYTES)];
        flow.chunks.entry(offset).or_insert_with(|| keep.to_vec());
        let stream = contiguous(flow);
        match handshake_from_records(&stream) {
            Err(e) => {
                self.flows.remove(key);
                Err(e)
            }
            Ok(Some(message)) => {
                self.flows.remove(key);
                Ok(Some(message))
            }
            Ok(None) => Ok(None),
        }
    }

    fn expire(&mut self, now: f64) {
        let timeout = self.timeout;
        // Stale when `now - started > timeout`; a NaN compares false and
        // stays, as in 1.x.
        self.flows
            .retain(|_, f| (now - f.started).partial_cmp(&timeout) != Some(Ordering::Greater));
    }
}

fn contiguous(flow: &Flow) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    for (&offset, chunk) in &flow.chunks {
        let offset = offset as usize;
        if offset > out.len() {
            break; // a gap: wait for the missing segment
        }
        let skip = out.len() - offset;
        if let Some(rest) = chunk.get(skip..) {
            out.extend_from_slice(rest);
        }
    }
    out
}
