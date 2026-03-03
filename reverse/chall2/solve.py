#!/usr/bin/env python3
import hashlib
import struct

PREFIX = b"BCCTF{"

KEY0 = bytes.fromhex(
    "f90016370414b822ed3bb7cf2158773ad28c726aeadff133e8241092ad08dd0d"
)

HASH_PREFIX = bytes.fromhex(
    "30dec00a32284acf43aa639a2b83fdeba76c23ee339f1797a586e4b6132b335d"
)

LOCK = bytes.fromhex(
    "d4fe935e70c321c7ca3afc75ce0d0ca2f98b5422e008bb31c00c6d7f1f1c0ad6"
    "4e4349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1"
    "9b7d1b721a1e0632b7cf04edf5032c8ecffa9f9a08492152b926f1a5a7e765d7"
    "9007408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce"
    "56ac3e7343f016890c510e93f935261169d9e3f565436429830faf0934f4f8e4"
    "cae2adf7177b7a8afddbc12d1634cf23ea1a71020f6a1308070a16400fb68fde"
    "18978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
    "29b98a4da31a127d4bde6e43033f66ba274cab0eb7eb1c70ec41402bf6273dd8"
    "31e2adf7177b7a8afddbc12d1634cf23ea1a71020f6a1308070a16400fb68fde"
    "d63a718774c572bd8a25adbeb1bfcd5c0256ae11cecf9f9c3f925d0e52beaf89"
    "3b79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea"
    "f5978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
    "18e2adf7177b7a8afddbc12d1634cf23ea1a71020f6a1308070a16400fb68fde"
    "7bf51566bd6705f7ea6ad54bb9deb449f795582d6529a0e22207b8981233ec58"
    "b216b1df538ba12dc3f97edbb85caa7050d46c148134290feba80f8236c83db9"
    "f8b98a4da31a127d4bde6e43033f66ba274cab0eb7eb1c70ec41402bf6273dd8"
    "bceceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9"
    "3dc66a7a5dd70c3146618063c344e531e6d4b59e379808443ce962b3abd63c5a"
    "2c07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce"
    "56ac3e7343f016890c510e93f935261169d9e3f565436429830faf0934f4f8e4"
)

ENC_STAGE2 = b"".join(
    struct.pack("<Q", x)
    for x in (
        0x1DF2AE7138ED996C,
        0xF8023F120C1A1932,
        0x2B7E5C139DD12755,
        0x2A5E6649717E5BD0,
        0xDDB321F8DD63DDDB,
        0x3F4DBE20AFF96C25,
    )
) + struct.pack("<I", 0x1E054FEB)

STAGE2_TEMPLATE = bytes.fromhex(
    "4883c61a48c7c2390500004831c9b005f6e1044032068a1f38c37511"
    "48ffc648ffc748ffc14883f91275e3eb0348ffc24889d0c3"
)


def sha1(c: int) -> bytes:
    return hashlib.sha256(bytes([c])).digest()


def lock_block(i: int) -> bytes:
    return LOCK[i * 32 : (i + 1) * 32]


def derive_x6_to_x26() -> bytes:
    suffix_to_char = {sha1(c)[1:]: c for c in range(256)}
    seq = [None] * 21

    for i in range(20):
        nxt = suffix_to_char.get(lock_block(i)[1:])
        if nxt is None:
            raise RuntimeError(f"no preimage for lock block {i}")
        seq[i + 1] = nxt

    want = lock_block(0)[0] ^ sha1(seq[1])[0]
    cands = [c for c in range(256) if sha1(c)[0] == want]
    if len(cands) != 1:
        raise RuntimeError(f"x6 not unique: {cands}")
    seq[0] = cands[0]

    for i in range(20):
        h_cur = sha1(seq[i])
        h_nxt = sha1(seq[i + 1])
        expect = bytes([h_cur[0] ^ h_nxt[0]]) + h_nxt[1:]
        if expect != lock_block(i):
            raise RuntimeError(f"lock equation failed at {i}")

    return bytes(seq)


def build_key(x6_to_x26: bytes, c44: int, puts_mutation: bool) -> bytes:
    key = bytearray(KEY0)

    for i in range(8):
        off = i * 4
        w = int.from_bytes(key[off : off + 4], "little") ^ 0x1356
        key[off : off + 4] = w.to_bytes(4, "little")

    if puts_mutation:
        for off in (0, 8, 16, 24):
            w = int.from_bytes(key[off : off + 4], "little") ^ 0x04030201
            key[off : off + 4] = w.to_bytes(4, "little")

    for i in range(32):
        key[i] ^= HASH_PREFIX[i]

    for i in range(32):
        key[i] ^= c44

    for i in range(20):
        cur = x6_to_x26[i]
        nxt = x6_to_x26[i + 1]
        h_cur = sha1(cur)
        h_nxt = sha1(nxt)
        block = bytes([h_cur[0] ^ h_nxt[0]]) + h_nxt[1:]
        if block == lock_block(i):
            for j in range(32):
                key[j] ^= block[j]

    return bytes(key)


def decrypt_stage2(key: bytes) -> bytes:
    out = bytearray(ENC_STAGE2)
    for i in range(len(out)):
        out[i] ^= key[i % 32]
    return bytes(out)


def solve() -> str:
    x6_to_x26 = derive_x6_to_x26()

    hits = []
    for puts_mutation in (False, True):
        for c44 in range(256):
            key = build_key(x6_to_x26, c44, puts_mutation)
            if decrypt_stage2(key) == STAGE2_TEMPLATE:
                hits.append((puts_mutation, c44, key))

    if len(hits) != 1:
        raise RuntimeError(f"expected one solution, got {hits}")

    puts_mutation, c44, key = hits[0]
    if not puts_mutation:
        raise RuntimeError("expected ptrace-success mutation path")

    x26_to_x43 = bytes((key[i] ^ ((5 * i + 0x40) & 0xFF)) for i in range(18))
    if x26_to_x43[0] != x6_to_x26[-1]:
        raise RuntimeError("x[26] mismatch")

    flag = bytearray()
    flag.extend(PREFIX)
    flag.extend(x6_to_x26)
    flag.extend(x26_to_x43[1:])
    flag.append(c44)

    rdx = 0x539
    for i in range(18):
        al = ((5 * i + 0x40) & 0xFF) ^ flag[26 + i]
        bl = key[i]
        if al != bl:
            rdx += 1
            break
    if rdx != 0x539:
        raise RuntimeError("stage2 check did not validate")

    return flag.decode("ascii")


def main() -> None:
    print(solve())


if __name__ == "__main__":
    main()
