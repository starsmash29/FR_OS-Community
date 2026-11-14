//! Reading one of the XDP program's pinned ring buffers (`events`,
//! `hello_pkts`), as 1.x's `RingBufferReader` does through libbpf: open
//! the pin (needs CAP_BPF), then wait for records and hand each one
//! over. A record the reader can't decode is dropped, as in 1.x.

use std::os::fd::AsFd as _;
use std::path::Path;

use aya::maps::{Map, MapData, RingBuf};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};

pub struct Reader {
    ring: RingBuf<MapData>,
}

impl Reader {
    /// The ring buffer pinned at `pin`.
    pub fn open(pin: &Path) -> Result<Reader, String> {
        let data = MapData::from_pin(pin).map_err(|e| format!("opening {}: {e}", pin.display()))?;
        let map = Map::from_map_data(data).map_err(|e| format!("{}: {e}", pin.display()))?;
        let ring = RingBuf::try_from(map).map_err(|e| format!("{}: {e}", pin.display()))?;
        Ok(Reader { ring })
    }

    /// Waits up to `timeout_ms` for records, then hands every one there
    /// is to `each`; the number handed over (0 on timeout).
    pub fn poll(&mut self, timeout_ms: u16, mut each: impl FnMut(&[u8])) -> Result<usize, String> {
        let mut n = 0;
        while let Some(item) = self.ring.next() {
            each(&item);
            n += 1;
        }
        if n > 0 {
            return Ok(n);
        }
        let mut fds = [PollFd::new(self.ring.as_fd(), PollFlags::POLLIN)];
        match poll(&mut fds, PollTimeout::from(timeout_ms)) {
            Ok(_) | Err(nix::errno::Errno::EINTR) => {}
            Err(e) => return Err(format!("poll: {e}")),
        }
        while let Some(item) = self.ring.next() {
            each(&item);
            n += 1;
        }
        Ok(n)
    }
}
