## test_set1.py

from set1 import hex2b64


def test_ex1():
    """in_text and out_text fro https://cryptopals.com/sets/1/challenges/1"""
    in_text = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    out_text = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    assert hex2b64(in_text) == out_text
