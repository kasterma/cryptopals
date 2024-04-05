## test_set1.py

import base64
import random
import secrets
from collections import Counter

import pytest
from hypothesis import given, note
from hypothesis.strategies import binary, composite, integers
from icecream import ic

from set1 import *


def test_ex1():
    """in_text and out_text from https://cryptopals.com/sets/1/challenges/1"""
    in_text = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    # bytes.fromhex(in_text)
    out_text = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    assert hex2b64(in_text) == out_text


def test_ex2():
    in_key = bytes.fromhex("1c0111001f010100061a024b53535009181c")
    in_text = bytes.fromhex("686974207468652062756c6c277320657965")
    out_text = bytes.fromhex("746865206b696420646f6e277420706c6179")
    assert fixed_xor(in_text, in_key) == out_text


@composite
def same_length_binaries(draw, number=2):
    l = draw(integers(min_value=1, max_value=1000))
    return [draw(binary(min_size=l, max_size=l)) for _ in range(number)]


@given(same_length_binaries())
def test_fixed_xor_invertible(bs):
    b0 = bs[0]
    b1 = bs[1]
    assert b1 == fixed_xor(fixed_xor(b1, b0), b0)
    assert b1 == fixed_xor(b0, fixed_xor(b1, b0))


@given(same_length_binaries())
def test_fixed_xor_commutative(bs):
    b0 = bs[0]
    b1 = bs[1]
    assert fixed_xor(b0, b1) == fixed_xor(b1, b0)


@given(same_length_binaries(3))
def test_fixed_xor_associative(bs):
    b0 = bs[0]
    b1 = bs[1]
    b2 = bs[2]
    assert fixed_xor(fixed_xor(b0, b1), b2) == fixed_xor(b0, fixed_xor(b1, b2))


def test_fixed_xor_rejects_different_length():
    in1 = bytes.fromhex("1c0111001f010100061a024b53535009181c")
    in2 = bytes.fromhex("686974207468652062756c6c2773206579")
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
    plain = plaintext.encode()
    c = 42
    key = one_char_key(c, len(plain))
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
    cipher = bytes.fromhex(
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    )
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
    plain = plaintext.encode()
    c = 42
    key = one_char_key(c, len(plain))
    cipher = fixed_xor(plain, key)

    l = len(cipher)
    N = 50
    fake_ciphers = [secrets.token_bytes(l) for _ in range(N)]
    ciphers = fake_ciphers + [cipher]
    random.shuffle(ciphers)

    assert plaintext in [p[0] for ps in find_all_decodes(ciphers, 3, 2) for p in ps]


def test_ex4():
    with open("4.txt") as f:
        data = [bytes.fromhex(l.strip()) for l in f.readlines()]
    assert "Now that the party is jumping\n" in [
        p[0] for ps in find_all_decodes(data, 4, 4) for p in ps
    ]


def test_ex5():
    plain = (
        "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    )
    key = "ICE".encode()
    cipher = repeating_key_xor(plain, key)
    expected_result = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    assert cipher.hex() == expected_result


@pytest.mark.parametrize(
    "b1, b2, d",
    [
        (116, 119, 2),
        (104, 111, 3),
        (105, 107, 1),
        (115, 107, 2),
        (32, 97, 2),
        (105, 32, 3),
        (115, 119, 1),
        (32, 111, 5),
        (97, 107, 2),
        (32, 107, 4),
        (116, 97, 3),
        (101, 33, 2),
        (115, 33, 3),
        (116, 33, 4),
        (5, 5, 0),
        (5, 6, 2),
        (0, 6, 2),
        (123456789, 987654321, 15),
    ],
)
def test_bit_diff(b1, b2, d):
    assert bit_diff(b1, b2) == d


def test_bit_diff_negative_numbers():
    with pytest.raises(ValueError):
        bit_diff(-1, 5)


def test_edit_distance():
    assert edit_distance("kitten".encode(), "sitting".encode()) == 4
    assert edit_distance("bla".encode(), "blb".encode()) == 2
    assert edit_distance("this is a test".encode(), "wokka wokka!!!".encode()) == 37


def bs(k):
    return random.randbytes(k)  # nosec: B311


# Made this test deterministic, with the random keys there were
# occasional fails.
plain_inputs = [
    (
        "Some text of a decent length to check the key length finding algorithm.  It looks like we need some fair bit of text to work with.",
        bytes.fromhex("49ba84535477ba197675"),  # bs(10)
    ),
    (
        "Some text of a decent length to check the key length finding algorithm.  It looks like we need some fair bit of text to work with.",
        bytes.fromhex("6435c576930d6d6718afe0959d482a"),  # bs(15)
    ),
    (
        "Some text of a decent length to check the key length finding algorithm.  It looks like we need some fair bit of text to work with.",
        bytes.fromhex("74dad78bd0af8af44ade7fb103e5e2941f5867ad"),  # bs(20)
    ),
]


@pytest.mark.wip
@pytest.mark.parametrize("text, key", plain_inputs)
def test_find_keysize(text, key):
    key_length = len(key)
    ic(key_length)
    cipher = repeating_key_xor(text, key)
    key_size_guesses = find_keysize(cipher, 3)
    assert key_length in [s for s, _ in key_size_guesses]


transpose_inputs = [
    ("abcabcabcabc", 3, ["aaaa", "bbbb", "cccc"]),
    ("abcdabcdabcd", 4, ["aaa", "bbb", "ccc", "ddd"]),
    ("abcabcabcabcab", 3, ["aaaaa", "bbbbb", "cccc"]),
]


@pytest.mark.parametrize("text, l, val", transpose_inputs)
def test_transpose(text, l, val):
    assert transpose(text, l) == val


@pytest.mark.parametrize("val, l, blocks", transpose_inputs)
def test_combine(val, l, blocks):
    assert combine(blocks) == val


@pytest.mark.wip
@pytest.mark.xfail
def test_ex6():
    with open("6.txt") as f:
        data = "".join([l.strip() for l in f.readlines()])
    x = base64.b64decode(data)
    key_size_guesses = find_keysize(x)
    ic(key_size_guesses)

    assert False


def test_ex7():
    with open("7.txt") as f:
        data = "".join([l.strip() for l in f.readlines()])
    x = base64.b64decode(data)

    ## with pycryptodome (black triggers on this with B413: import_pycrypto,
    ## but also has the removed B414: import_pycryptodome)
    from Crypto.Cipher import AES  # nosec

    key = b"YELLOW SUBMARINE"
    cipher = AES.new(key, AES.MODE_ECB)
    plain = cipher.decrypt(x)
    test = "I'm back and I'm ringin' the bell"
    assert test == plain[: len(test)].decode()

    ## this is with pyca/cryptography library
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    cipher = Cipher(algorithms.AES(key), modes.ECB())  # nosec
    # encryptor = cipher.encryptor()
    # ct = encryptor.update(b"a secret message") + encryptor.finalize()

    decryptor = cipher.decryptor()

    plain2 = decryptor.update(x) + decryptor.finalize()

    assert test == plain2[: len(test)].decode()
