## set1

import base64
import string
from collections import Counter, defaultdict

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
    return bytes(ii ^ kk for ii, kk in zip(i, k)).hex()


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
