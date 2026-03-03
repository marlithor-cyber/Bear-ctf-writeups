#!/usr/bin/env python3
from hashlib import md5
import re


ENC_TREASURE = [
    76, 77, 65, 83, 67, 121, 85, 100,
    48, 94, 91, 48, 53, 102, 82, 55,
    97, 73, 111, 123, 61, 52, 76, 116,
    95, 116, 58, 123, 119, 54, 120, 127,
]

S_ARRAY = [
    0, 2, 3, 4, 0, 2, 6, 2, 2, 2, 2, 3, 9, 8, 0, 11, 17, 13,
    11, 16, 14, 20, 6, 19, 6, 13, 26, 1, 1, 28, 15, 1, 14, 9,
    14, 29, 3, 7, 23, 26, 9, 0, 41, 3, 30, 11, 1, 20, 10, 2, 27,
]


def ruby_ok_chars():
    out = []
    for ch in range(33, 127):
        if ch == 94:
            continue
        shifted = (ch - 16) % 257
        powers = {pow(shifted, e, 257) for e in range(2, 257)}
        if len(powers) == 255:
            out.append(ch)
    return out


def perl_transform(x: int) -> int:
    return int(f"{x}{int(str(x), 16)}") % 257


def reconstruct_transformed_sequence():
    chars = ruby_ok_chars()
    values = sorted(perl_transform(x) for x in chars + [10, 47])
    inv = [0] + S_ARRAY
    seq = [None] * len(inv)

    for i in range(len(inv) - 1, -1, -1):
        idx = i - inv[i]
        seq[i] = values.pop(idx)
    return seq


def build_candidates():
    chars = ruby_ok_chars()
    rev = {}
    for ch in chars + [10, 47]:
        rev.setdefault(perl_transform(ch), []).append(ch)

    seq = reconstruct_transformed_sequence()
    fixed = {
        1: ord("O"),
        5: ord("p"),
        4: ord("`"),
        22: ord("8"),
        18: ord("6"),
        21: ord("u"),
        23: ord("{"),
        25: ord("7"),
        28: ord("E"),
        37: ord("f"),
        41: ord("c"),
        46: ord("F"),
    }

    for at_tilde in ((ord("@"), ord("~")), (ord("~"), ord("@"))):
        key_bytes = []
        for i, value in enumerate(seq[:50]):
            choices = rev[value]
            if len(choices) == 1:
                key_bytes.append(choices[0])
            elif i == 16:
                key_bytes.append(at_tilde[0])
            elif i == 19:
                key_bytes.append(at_tilde[1])
            else:
                key_bytes.append(fixed[i])
        yield bytes(key_bytes)


def decrypt_flag(key: bytes) -> str:
    h = md5(key).hexdigest()
    return "".join(chr(int(h[i], 16) ^ ENC_TREASURE[i]) for i in range(32))


def main():
    for key in build_candidates():
        flag = decrypt_flag(key)
        print("key =", key.decode())
        print("out =", flag)
        if re.fullmatch(r"BCCTF\{[^}]+\}", flag):
            print("\nFLAG:", flag)
            return


if __name__ == "__main__":
    main()
