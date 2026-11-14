"""FR_OS 1.x's first-boot DHCP probe (frfw.netdetect), with the capture
plugin: the DISCOVER frame it sends from a port's MAC address, and the
network it reads from every frame it hears -- offers built in every
shape, then damaged at random (a byte changed, the frame cut). Each case
records 1.x's answer; nothing here asserts anything about 1.x.
"""

from __future__ import annotations

import ipaddress
import random
import struct
import sys

import pytest


def _record(case: dict) -> None:
    capture = sys.modules.get("fros_capture")
    if capture is not None:
        capture._record("netdetect", case)


XID = 0x1A2B3C4D
MAC = bytes.fromhex("525400000001")


def _offer(*, op: int = 2, xid: int = XID, yiaddr: str = "192.168.1.57", options: bytes | None = None,
           dport: int = 68, proto: int = 17, ethertype: int = 0x0800, ihl: int = 5, magic: bytes = b"\x63\x82\x53\x63",
           pad: int = 0) -> bytes:
    """A server's answer to DISCOVER XID, as it arrives on the packet socket."""
    if options is None:
        options = bytes([53, 1, 2, 1, 4, 255, 255, 255, 0, 3, 4, 192, 168, 1, 1, 255])
    bootp = struct.pack("!BBBBIHH4s4s4s4s16s64s128s", op, 1, 6, 0, xid, 0, 0x8000, bytes(4),
                        ipaddress.IPv4Address(yiaddr).packed, bytes(4), bytes(4), MAC.ljust(16, b"\0"), b"", b"")
    payload = bootp + magic + options + bytes(pad)
    udp = struct.pack("!HHHH", 67, dport, 8 + len(payload), 0) + payload
    ip_options = bytes(max(0, 4 * (ihl - 5)))
    ip = struct.pack("!BBHHHBBH4s4s", 0x40 | ihl, 0, 20 + len(ip_options) + len(udp), 1, 0, 64, proto, 0,
                     bytes([192, 168, 1, 1]), bytes([255, 255, 255, 255])) + ip_options
    return b"\xff" * 6 + bytes.fromhex("525400aabbcc") + struct.pack("!H", ethertype) + ip + udp


def _mask(mask: str) -> bytes:
    return bytes([53, 1, 2, 1, 4]) + ipaddress.IPv4Address(mask).packed + bytes([255])


OFFERS = {
    "offer": _offer(),
    "no mask": _offer(options=bytes([53, 1, 2, 255])),
    "mask first": _offer(options=bytes([1, 4, 255, 255, 0, 0, 53, 1, 2, 255])),
    "pads": _offer(options=bytes([0, 0, 53, 1, 2, 0, 1, 4, 255, 0, 0, 0, 255])),
    "no end": _offer(options=bytes([53, 1, 2, 1, 4, 255, 255, 255, 128])),
    "only pads": _offer(options=bytes([0, 0, 0])),
    "nothing after the magic": _offer(options=b""),
    "an ack": _offer(options=bytes([53, 1, 5, 255])),
    "a request": _offer(op=1),
    "message type twice": _offer(options=bytes([53, 1, 2, 53, 1, 5, 255])),
    "message type twice, offer last": _offer(options=bytes([53, 1, 5, 53, 1, 2, 255])),
    "message type long": _offer(options=bytes([53, 2, 2, 0, 255])),
    "mask short": _offer(options=bytes([53, 1, 2, 1, 3, 255, 255, 255, 255])),
    "mask twice": _offer(options=bytes([53, 1, 2, 1, 4, 255, 0, 0, 0, 1, 4, 255, 255, 0, 0, 255])),
    "option cut": _offer(options=bytes([53, 1, 2, 1, 4, 255, 255])),
    "option length cut": _offer(options=bytes([53, 1, 2, 1])),
    "length only": _offer(options=bytes([53])),
    "other xid": _offer(xid=XID + 1),
    "other port": _offer(dport=67),
    "tcp": _offer(proto=6),
    "vlan": _offer(ethertype=0x8100),
    "ip options": _offer(ihl=7),
    "ihl too small": _offer(ihl=2),
    "bad magic": _offer(magic=b"\x63\x82\x53\x64"),
    "padding after": _offer(pad=60),
    "address zero": _offer(yiaddr="0.0.0.0"),
    "broadcast address": _offer(yiaddr="255.255.255.255"),
    "empty": b"",
    "ethernet only": _offer()[:14],
    "short": _offer()[:14 + 20 + 8 + 239],
    "just long enough": _offer()[:14 + 20 + 8 + 240],
}
for mask in ("255.255.255.255", "0.0.0.0", "255.0.0.0", "255.255.254.0", "128.0.0.0", "255.0.255.0",
             "0.0.0.255", "0.0.255.255", "0.255.255.255", "127.255.255.255", "0.0.0.1", "254.0.0.0",
             "255.255.255.254", "1.2.3.4", "0.0.1.255"):
    OFFERS["mask " + mask] = _offer(options=_mask(mask))


def _damaged(seed: int) -> bytes:
    rng = random.Random(seed)
    frame = bytearray(rng.choice(list(OFFERS.values())[:16]))
    if not frame:
        return b""
    for _ in range(rng.randrange(1, 4)):
        kind = rng.randrange(3)
        if kind == 0:
            frame[rng.randrange(len(frame))] = rng.randrange(256)
        elif kind == 1 and len(frame) > 1:
            del frame[rng.randrange(len(frame)):]
        else:
            # Somewhere in the options: where the parser is most at risk.
            start = min(len(frame) - 1, 14 + 20 + 8 + 240)
            frame[rng.randrange(start, len(frame))] = rng.choice((0, 1, 2, 3, 4, 53, 255, rng.randrange(256)))
    return bytes(frame)


@pytest.mark.parametrize("name", sorted(OFFERS))
def test_offer(name):
    from frfw import netdetect

    frame = OFFERS[name]
    network = netdetect._offered_network(frame, XID)
    _record({"op": "offer", "id": name, "frame": frame.hex(), "xid": XID,
             "network": None if network is None else str(network)})


@pytest.mark.parametrize("seed", range(400))
def test_damaged(seed):
    from frfw import netdetect

    frame = _damaged(seed)
    network = netdetect._offered_network(frame, XID)
    _record({"op": "offer", "id": f"damaged {seed}", "frame": frame.hex(), "xid": XID,
             "network": None if network is None else str(network)})


@pytest.mark.parametrize("mac, xid, ip_id", [
    ("525400000001", XID, 1), ("ffffffffffff", 0, 0), ("000000000000", 0xFFFFFFFF, 65535),
    ("aabbccddeeff", 0x12345678, 4660), ("020000000001", 1, 40000)])
def test_discover(monkeypatch, mac, xid, ip_id):
    from frfw import netdetect

    monkeypatch.setattr(netdetect.random, "randrange", lambda n: ip_id)
    frame = netdetect._discover_frame(bytes.fromhex(mac), xid)
    _record({"op": "discover", "id": f"discover {mac} {xid}", "mac": mac, "xid": xid, "ip_id": ip_id,
             "frame": frame.hex()})
