## test_set1.py

import random
import secrets
from collections import Counter

import pytest
from hypothesis import given, note
from hypothesis.strategies import binary, composite, integers

from set1 import *


def test_ex1():
    """in_text and out_text fro https://cryptopals.com/sets/1/challenges/1"""
    in_text = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    # bytes.fromhex(in_text)
    out_text = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    assert hex2b64(in_text) == out_text


def test_ex2():
    in_key = "1c0111001f010100061a024b53535009181c"
    in_text = "686974207468652062756c6c277320657965"  # bytes.fromhex(in_text)
    out_text = "746865206b696420646f6e277420706c6179"
    assert fixed_xor(in_text, in_key) == out_text


@composite
def same_length_hex_binaries(draw, number=2):
    l = draw(integers(min_value=1, max_value=1000))
    return [draw(binary(min_size=l, max_size=l)).hex() for _ in range(number)]


@given(same_length_hex_binaries())
def test_fixed_xor_invertible(bs):
    b0 = bs[0]
    b1 = bs[1]
    assert b1 == fixed_xor(fixed_xor(b1, b0), b0)
    assert b1 == fixed_xor(b0, fixed_xor(b1, b0))


@given(same_length_hex_binaries())
def test_fixed_xor_commutative(bs):
    b0 = bs[0]
    b1 = bs[1]
    assert fixed_xor(b0, b1) == fixed_xor(b1, b0)


@given(same_length_hex_binaries(3))
def test_fixed_xor_associative(bs):
    b0 = bs[0]
    b1 = bs[1]
    b2 = bs[2]
    assert fixed_xor(fixed_xor(b0, b1), b2) == fixed_xor(b0, fixed_xor(b1, b2))


def test_fixed_xor_rejects_different_length():
    in1 = "1c0111001f010100061a024b53535009181c"
    in2 = "686974207468652062756c6c277320657"
    with pytest.raises(AssertionError):
        fixed_xor(in1, in2)


@pytest.mark.parametrize(
    "plaintext, short",
    [
        ("This is a normal English text to be encrypted with a one char key", False),
        ("Another perfectly normal English text to be tried", False),
        ("Does this work as well?", False),
        ("How about this?", True),
        ("Some more text to try", False),
        ("Cooking MC's like a pound of bacon", True),
    ],
)
def test_find_decryption(plaintext, short):
    """Our scoring is not perfect, on some "short" texts the right
    decoding is not the best scoring result.  Hence for some we only
    check that the candidate is among the first 3.  We can filter more
    on "special" characters, but that doesn't feel right.

    """
    plain = plaintext.encode().hex()
    c = 42
    key = one_char_key(c, len(plain) // 2)
    cipher = fixed_xor(plain, key)

    candidates = all_one_char_decodes(cipher)
    candidates_decoded = decode_all(candidates)
    assert plaintext in candidates_decoded
    ft = freq_tables(candidates_decoded)
    assert ft[plaintext] == Counter(plaintext.upper())
    candidates_ordered = order_ft(ft)
    assert plaintext in candidates_ordered[:3]
    if not short:
        assert plaintext == candidates_ordered[0]


def test_ex3():
    cipher = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    candidates = all_one_char_decodes(cipher)
    assert "Cooking MC's like a pound of bacon" in find_decode(cipher, 5)


@pytest.mark.parametrize(
    "plaintext",
    [
        "This is a normal English text to be encrypted with a one char key",
        "Another perfectly normal English text to be tried",
        "Does this work as well?",
        "How about this?",
        "Some more text to try",
        "Cooking MC's like a pound of bacon",
    ],
)
def test_develop_ex4(plaintext):
    plain = plaintext.encode().hex()
    c = 42
    key = one_char_key(c, len(plain) // 2)
    cipher = fixed_xor(plain, key)

    l = len(cipher.encode())
    N = 50
    fake_ciphers = [secrets.token_hex(l) for _ in range(N)]
    ciphers = fake_ciphers + [cipher]
    random.shuffle(ciphers)

    assert plaintext in [p[0] for ps in find_all_decodes(ciphers, 3, 2) for p in ps]


def test_ex4():
    with open("4.txt") as f:
        data = [l.strip() for l in f.readlines()]
    assert "Now that the party is jumping\n" in [
        p[0] for ps in find_all_decodes(data, 4, 4) for p in ps
    ]
