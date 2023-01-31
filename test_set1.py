## test_set1.py

import pytest
from hypothesis import given
from hypothesis.strategies import binary, composite, integers

from set1 import fixed_xor, hex2b64


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
