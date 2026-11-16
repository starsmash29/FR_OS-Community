"""FR_OS 1.x's release verification (frfw.release_signing), with the
capture plugin: a SHA256SUMS signature checked against trusted keys of
every shape (none, one, several, broken, the wrong kind), signatures
damaged at random, the checksum SHA256SUMS lists for a name in every
text shape sha256sum and a hand could write, and whole releases checked
end to end. The keys are made here from fixed seeds, for these cases
only: none of them is, or signs, a real release. Each case records
1.x's answer; nothing here asserts anything about 1.x.
"""

from __future__ import annotations

import hashlib
import random
import subprocess
import sys
from pathlib import Path

import pytest


def _record(case: dict) -> None:
    capture = sys.modules.get("fros_capture")
    if capture is not None:
        capture._record("release", case)


#: An Ed25519 private key's PKCS #8 DER, but for its 32-byte seed.
_PKCS8_PREFIX = bytes.fromhex("302e020100300506032b657004220420")


def _private_pem(seed: int) -> str:
    der = _PKCS8_PREFIX + hashlib.sha256(f"fros release case key {seed}".encode()).digest()
    return subprocess.run(["openssl", "pkey", "-inform", "DER"], input=der, capture_output=True,
                          check=True).stdout.decode()


def _public_pem(seed: int) -> str:
    return subprocess.run(["openssl", "pkey", "-pubout"], input=_private_pem(seed).encode(),
                          capture_output=True, check=True).stdout.decode()


def _public_der(seed: int) -> bytes:
    return subprocess.run(["openssl", "pkey", "-pubout", "-outform", "DER"], input=_private_pem(seed).encode(),
                          capture_output=True, check=True).stdout


def _sign(seed: int, data: bytes, tmp: Path) -> bytes:
    if not data:
        # openssl can't sign (or verify) nothing at all: the signature an
        # Ed25519 signer would make for it.
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        seed_bytes = hashlib.sha256(f"fros release case key {seed}".encode()).digest()
        return Ed25519PrivateKey.from_private_bytes(seed_bytes).sign(b"")
    key = tmp / f"sign-{seed}.key"
    key.write_text(_private_pem(seed))
    message = tmp / "message"
    message.write_bytes(data)
    out = tmp / "sig"
    subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(key), "-in", str(message),
                    "-out", str(out)], check=True, capture_output=True)
    return out.read_bytes()


def _x25519_public_pem() -> str:
    der = bytes.fromhex("302e020100300506032b656e04220420") + bytes(range(32))
    private = subprocess.run(["openssl", "pkey", "-inform", "DER"], input=der, capture_output=True,
                             check=True).stdout
    return subprocess.run(["openssl", "pkey", "-pubout"], input=private, capture_output=True,
                          check=True).stdout.decode()


TARBALL = b"fr_os 9.9.9 release tarball\n" * 64
NAME = "fr_os-9.9.9-amd64.tar.gz"
DIGEST = hashlib.sha256(TARBALL).hexdigest()
SUMS = f"{DIGEST}  {NAME}\n{hashlib.sha256(b'iso').hexdigest()}  FR_OS-9.9.9-amd64.iso\n".encode()


def _keys(tmp: Path, contents: list[bytes]) -> list[Path]:
    paths = []
    for n, content in enumerate(contents):
        path = tmp / f"k{n}.pem"
        path.write_bytes(content)
        paths.append(path)
    return paths


def _outcome(call) -> dict:
    from frfw import release_signing

    try:
        key = call()
    except release_signing.SignatureError as exc:
        return {"error": str(exc)}
    except Exception as exc:  # noqa: BLE001 -- recorded: 1.x lets it through
        return {"raised": type(exc).__name__}
    return {"key": key.name}


def _signature_case(case_id: str, tmp: Path, keys: list[bytes], data: bytes, signature: bytes) -> None:
    from frfw import release_signing

    sums = tmp / "SHA256SUMS"
    sums.write_bytes(data)
    sig = tmp / "SHA256SUMS.sig"
    sig.write_bytes(signature)
    paths = _keys(tmp, keys)
    outcome = _outcome(lambda: release_signing.verify_signature(sums, sig, paths))
    _record({"op": "signature", "id": case_id, "keys": [k.hex() for k in keys], "data": data.hex(),
             "signature": signature.hex(), **outcome})


def _signature_cases(tmp: Path) -> dict:
    good = _sign(1, SUMS, tmp)
    pub = [_public_pem(n).encode() for n in range(4)]
    other = _sign(2, SUMS, tmp)
    return {
        "no keys": ([], SUMS, good),
        "one key, signed by it": ([pub[1]], SUMS, good),
        "one key, signed by another": ([pub[0]], SUMS, good),
        "the second of two keys": ([pub[0], pub[1]], SUMS, good),
        "the first of two keys": ([pub[1], pub[0]], SUMS, good),
        "three keys, none": ([pub[0], pub[2], pub[3]], SUMS, good),
        "two keys, the other signed": ([pub[1], pub[2]], SUMS, other),
        "the same key twice": ([pub[1], pub[1]], SUMS, good),
        "signature of other data": ([pub[1]], SUMS, _sign(1, SUMS + b"x", tmp)),
        "data changed": ([pub[1]], SUMS.replace(b"  ", b" *", 1), good),
        "empty data signed": ([pub[1]], b"", _sign(1, b"", tmp)),
        "empty data, other signature": ([pub[1]], b"", good),
        "empty signature": ([pub[1]], SUMS, b""),
        "signature cut": ([pub[1]], SUMS, good[:63]),
        "signature one byte too long": ([pub[1]], SUMS, good + b"\0"),
        "signature doubled": ([pub[1]], SUMS, good + good),
        "signature zero": ([pub[1]], SUMS, bytes(64)),
        "signature as hex": ([pub[1]], SUMS, good.hex().encode()),
        "a key that isn't one": ([b"not a key\n", pub[1]], SUMS, good),
        "an empty key file": ([b"", pub[1]], SUMS, good),
        "only broken keys": ([b"garbage", b""], SUMS, good),
        "a private key": ([_private_pem(1).encode()], SUMS, good),
        "the key as DER": ([_public_der(1)], SUMS, good),
        "text before the key": ([b"a comment\n" + pub[1]], SUMS, good),
        "two keys in one file, signer first": ([pub[1] + pub[0]], SUMS, good),
        "two keys in one file, signer second": ([pub[0] + pub[1]], SUMS, good),
        "the key with CRLF": ([pub[1].replace(b"\n", b"\r\n")], SUMS, good),
        "the key without its last newline": ([pub[1].rstrip(b"\n")], SUMS, good),
        "the key's body changed": ([pub[1].replace(b"MCowBQYDK2Vw", b"MCowBQYDK2Vx")], SUMS, good),
        "an X25519 key": ([_x25519_public_pem().encode()], SUMS, good),
        "an X25519 key, then the signer": ([_x25519_public_pem().encode(), pub[1]], SUMS, good),
        "binary data": ([pub[1]], bytes(range(256)), _sign(1, bytes(range(256)), tmp)),
    }


@pytest.mark.parametrize("name", sorted([
    "no keys", "one key, signed by it", "one key, signed by another", "the second of two keys",
    "the first of two keys", "three keys, none", "two keys, the other signed", "the same key twice",
    "signature of other data", "data changed", "empty data signed", "empty data, other signature",
    "empty signature", "signature cut", "signature one byte too long", "signature doubled", "signature zero",
    "signature as hex", "a key that isn't one", "an empty key file", "only broken keys", "a private key",
    "the key as DER", "text before the key", "two keys in one file, signer first",
    "two keys in one file, signer second", "the key with CRLF", "the key without its last newline",
    "the key's body changed", "an X25519 key", "an X25519 key, then the signer", "binary data",
]))
def test_signature(tmp_path, name):
    keys, data, signature = _signature_cases(tmp_path)[name]
    _signature_case(name, tmp_path, keys, data, signature)


@pytest.mark.parametrize("seed", range(60))
def test_signature_damaged(tmp_path, seed):
    rng = random.Random(seed)
    data = bytearray(SUMS)
    signature = bytearray(_sign(1, SUMS, tmp_path))
    for _ in range(rng.randrange(1, 3)):
        target = signature if rng.randrange(2) else data
        target[rng.randrange(len(target))] ^= 1 << rng.randrange(8)
    _signature_case(f"damaged {seed}", tmp_path, [_public_pem(1).encode()], bytes(data), bytes(signature))


D = "0f" * 32
UPPER = "AB" * 32

SUMS_TEXTS = {
    "two spaces": f"{D}  {NAME}\n",
    "binary marker": f"{D} *{NAME}\n",
    "one space": f"{D} {NAME}\n",
    "three spaces": f"{D}   {NAME}\n",
    "a tab": f"{D}\t{NAME}\n",
    "leading spaces": f"   {D}  {NAME}\n",
    "trailing spaces": f"{D}  {NAME}   \n",
    "uppercase digest": f"{UPPER}  {NAME}\n",
    "no newline": f"{D}  {NAME}",
    "CRLF": f"{D}  {NAME}\r\n",
    "CR": f"# x\r{D}  {NAME}\r",
    "comment first": f"# FR_OS\n{D}  {NAME}\n",
    "comment with spaces": f"   # {D}  {NAME}\n{UPPER}  {NAME}\n",
    "commented out": f"#{D}  {NAME}\n",
    "blank lines": f"\n\n   \n{D}  {NAME}\n\n",
    "the first of two": f"{D}  {NAME}\n{UPPER}  {NAME}\n",
    "another name": f"{D}  other.tar.gz\n",
    "a longer name": f"{D}  {NAME}.sig\n",
    "a shorter name": f"{D}  {NAME[:-3]}\n",
    "a path": f"{D}  ./{NAME}\n",
    "two markers": f"{D} **{NAME}\n",
    "marker and spaces": f"{D} * {NAME}\n",
    "empty": "",
    "only a digest": f"{D}\n",
    "only a name": f" {NAME}\n",
    "a short digest": f"abc  {NAME}\n",
    "a non-hex digest": f"{'zz' * 32}  {NAME}\n",
    "vertical tab": f"x\x0b{D}  {NAME}\n",
    "form feed": f"x\x0c{D}  {NAME}\n",
    "file separator": f"x\x1c{D}  {NAME}\n",
    "next line": f"x\x85{D}  {NAME}\n",
    "line separator": f"x {D}  {NAME}\n",
    "paragraph separator": f"x {D}  {NAME}\n",
    "no-break space around": f" {D}  {NAME} \n",
    "ideographic space between": f"{D}　{NAME}\n",
    "unit separator": f"\x1f{D}  {NAME}\n",
    "tab around": f"\t{D}  {NAME}\t\n",
    "a sign in the digest": f"İ{D[2:]}  {NAME}\n",
    "kelvin in the digest": f"K{D[2:]}  {NAME}\n",
    "sha256sum's own": f"{DIGEST}  {NAME}\n{hashlib.sha256(b'iso').hexdigest()}  FR_OS-9.9.9-amd64.iso\n",
}


@pytest.mark.parametrize("label", sorted(SUMS_TEXTS))
@pytest.mark.parametrize("name", [NAME, "FR_OS-9.9.9-amd64.iso", "", f" {NAME}"])
def test_expected_sha256(label, name):
    from frfw import release_signing

    text = SUMS_TEXTS[label]
    try:
        outcome = {"digest": release_signing.expected_sha256(text, name)}
    except release_signing.SignatureError as exc:
        outcome = {"error": str(exc)}
    _record({"op": "expected", "id": f"{label} / {name!r}", "text": text, "name": name, **outcome})


def _release_cases(tmp: Path) -> dict:
    other = b"not the release"
    return {
        "a release": (TARBALL, SUMS, _sign(1, SUMS, tmp)),
        "the tarball changed": (other, SUMS, _sign(1, SUMS, tmp)),
        "an empty tarball": (b"", SUMS, _sign(1, SUMS, tmp)),
        "the name not listed": (TARBALL, b"# nothing\n", _sign(1, b"# nothing\n", tmp)),
        "unsigned": (TARBALL, SUMS, b""),
        "signed by another key": (TARBALL, SUMS, _sign(2, SUMS, tmp)),
        "uppercase digest signed": (TARBALL, SUMS.replace(DIGEST.encode(), DIGEST.upper().encode()),
                                    _sign(1, SUMS.replace(DIGEST.encode(), DIGEST.upper().encode()), tmp)),
        "SHA256SUMS not UTF-8, signed": (TARBALL, SUMS + b"\xff\xfe\n", _sign(1, SUMS + b"\xff\xfe\n", tmp)),
        "SHA256SUMS with CRLF, signed": (TARBALL, SUMS.replace(b"\n", b"\r\n"),
                                         _sign(1, SUMS.replace(b"\n", b"\r\n"), tmp)),
    }


@pytest.mark.parametrize("label", sorted([
    "a release", "the tarball changed", "an empty tarball", "the name not listed", "unsigned",
    "signed by another key", "uppercase digest signed", "SHA256SUMS not UTF-8, signed",
    "SHA256SUMS with CRLF, signed",
]))
def test_verify_release(tmp_path, label):
    from frfw import release_signing

    tarball_bytes, sums_bytes, signature = _release_cases(tmp_path)[label]
    tarball = tmp_path / NAME
    tarball.write_bytes(tarball_bytes)
    sums = tmp_path / "SHA256SUMS"
    sums.write_bytes(sums_bytes)
    sig = tmp_path / "SHA256SUMS.sig"
    sig.write_bytes(signature)
    keys = _keys(tmp_path, [_public_pem(0).encode(), _public_pem(1).encode()])
    outcome = _outcome(lambda: release_signing.verify_release(tarball, sums, sig, name=NAME, keys=keys))
    _record({"op": "release", "id": label, "keys": [k.read_bytes().hex() for k in keys],
             "tarball": tarball_bytes.hex(), "data": sums_bytes.hex(), "signature": signature.hex(),
             "name": NAME, **outcome})
