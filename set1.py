## set1

import base64
import string
from collections import Counter, defaultdict
from itertools import zip_longest

import pwn
from icecream import ic

LETTER_FREQ_TABLE = {
    "A": 8.2,
    "B": 1.5,
    "C": 2.8,
    "D": 4.3,
    "E": 12.7,
    "F": 2.2,
    "G": 2,
    "H": 6.1,
    "I": 7,
    "J": 0.15,
    "K": 0.77,
    "L": 4,
    "M": 2.4,
    "N": 6.7,
    "O": 7.5,
    "P": 1.9,
    "Q": 0.095,
    "R": 6,
    "S": 6.3,
    "T": 9.1,
    "U": 2.8,
    "V": 0.98,
    "W": 2.4,
    "X": 0.15,
    "Y": 2,
    "Z": 0.074,
}
LETTER_FREQ_TABLE = defaultdict(int, LETTER_FREQ_TABLE)


def hex2b64(x):
    return base64.b64encode(bytes.fromhex(x)).decode("ascii")


def fixed_xor(i, k):
    assert len(i) == len(k), f"len(i) = {len(i)} =/= {len(k)} = len(k)"
    i = bytes.fromhex(i)
    k = bytes.fromhex(k)
    return pwn.xor(i, k).hex()  # bytes(ii ^ kk for ii, kk in zip(i, k)).hex()


def one_char_key(c, l):
    return bytes([c for _ in range(l)]).hex()


def all_one_char_decodes(s):
    assert len(s) % 2 == 0
    candidates = []
    for one_char in range(256):
        key = one_char_key(one_char, len(s) // 2)
        candidate = fixed_xor(s, key)
        candidates.append(candidate)
    return candidates


def decode_all(cc):
    """decode all ciphertexts in cc and drop the ones that give a
    decode error.

    Use the asumption we are dealing with a proper ascii plaintext.

    """
    cc_decoded = []
    for c in cc:
        try:
            dec = bytes.fromhex(c).decode()
            if set(dec).difference(set(string.printable)):
                continue
            cc_decoded.append(dec)
        except UnicodeDecodeError:
            pass
    return cc_decoded


def freq_tables(cc_decoded):
    return {c: Counter(c.upper()) for c in cc_decoded}


def ft_dist(a, b):
    return sum((a[k] - b[k]) ** 2 for k in a.keys() | b.keys())


def order_ft(fts):
    return [
        p[0]
        for p in sorted(fts.items(), key=lambda p: ft_dist(p[1], LETTER_FREQ_TABLE))
    ]


def score(decode):
    return ft_dist(Counter(decode.upper()), LETTER_FREQ_TABLE)


def find_decode(cipher: str, candidate_count: int = 1) -> list[str]:
    candidates = all_one_char_decodes(cipher)
    candidates_decoded = decode_all(candidates)
    ft = freq_tables(candidates_decoded)
    candidates_ordered = order_ft(ft)
    return candidates_ordered[:candidate_count]


def find_all_decodes(
    ciphers: list[str], per_candidate_count: int = 1, candidate_count: int = 1
) -> list[list[(str, float)]]:
    scored = [
        [(d, score(d)) for d in decode_all(all_one_char_decodes(c))] for c in ciphers
    ]
    scored_sorted = [sorted(x, key=lambda p: p[1]) for x in scored if x]
    return [xs[:per_candidate_count] for xs in scored_sorted[:candidate_count]]


def repeating_key_xor(plain: str, key: bytes):
    def get_key():
        while True:
            for c in key:
                yield c

    return bytes(i ^ k for i, k in zip(plain.encode(), get_key())).hex()


def bit_diff(b1: int, b2: int) -> int:
    ct = 0
    while b1 or b2:
        if b1 % 2 != b2 % 2:
            ct += 1
        b1 //= 2
        b2 //= 2
    return ct


def edit_distance(w1: bytes, w2: bytes) -> int:
    """Counting difference in number of _bits_ between these two bytes"""
    return sum(bit_diff(b1, b2) for b1, b2 in zip(w1, w2))


def find_keysize(cipher: str, k: int = 3) -> list[int]:
    """Use the hint to find the most likely k keysizes"""
    cipher_b = bytes.fromhex(cipher)
    ls_graded = [
        (
            n,
            (
                edit_distance(cipher_b[:n], cipher_b[n : 2 * n]) / n
                + edit_distance(cipher_b[2 * n : 3 * n], cipher_b[3 * n : 4 * n]) / n
            )
            / 2,
        )
        for n in range(2, min(40, len(cipher) // 4))
    ]
    ls_sorted = sorted(ls_graded, key=lambda p: p[1])
    return ls_sorted[:k]


def transpose(cipher: str, l: int) -> list[str]:
    rv = []
    for i in range(l):
        txt = "".join(cipher[j] for j in range(i, len(cipher), l))
        rv.append(txt)
    return rv


def combine(blocks: list[str]):
    return "".join(
        itertools.chain.from_iterable(itertools.zip_longest(*blocks, fillvalue=""))
    )
