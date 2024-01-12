import random
import statistics
import string

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from set1 import *


def bs(k):
    return random.randbytes(k)


def ls(k):
    return "".join(random.choices(string.ascii_letters, k=k)).encode()


def lsp(k):
    return "".join(random.choices(string.printable, k=k)).encode()


byte_choices = random.sample(list(Counter(bs(10_000)).keys()), k=95)


def sbs(k):
    """selected bytes choices"""
    return bytes(random.choices(byte_choices, k=k))


k = 10
N = 1000


def get_distances(f):
    return pd.Series(edit_distance(f(k), f(k)) / k for _ in range(N))


bs_distances = get_distances(bs)
ls_distances = get_distances(ls)
sbs_distances = get_distances(sbs)
lsp_distances = get_distances(lsp)

print(bs_distances.describe())
print(ls_distances.describe())

# bs_distances.hist(alpha=0.5)
# ls_distances.hist(alpha=0.5)
# sbs_distances.hist(alpha=0.5)
# _distances.hist(alpha=0.5)
# plt.show()

df = pd.DataFrame(
    {"bs": bs_distances, "ls": ls_distances, "sbs": sbs_distances, "lsp": lsp_distances}
)

df.plot.kde(bw_method=0.2)
plt.show()


# this shows a fairly robust separation
#
# edit_distance(random bytes, other random bytes) / length
#
#   can be expected to be larger than
#
# edit_distance(random_ascii, other random ascii) / length

assert edit_distance("this is a test".encode(), "wokka wokka!!!".encode()) == 37
key = bs(len("this is a test"))
assert (
    edit_distance(
        pwn.xor(key, "this is a test".encode()), pwn.xor(key, "wokka wokka!!!".encode())
    )
    == 37
)
key2 = bs(len("this is a test"))
edit_distance(
    pwn.xor(key, "this is a test".encode()), pwn.xor(key2, "wokka wokka!!!".encode())
)
assert (
    edit_distance(
        pwn.xor(key, "this is a test".encode()),
        pwn.xor(key2, "wokka wokka!!!".encode()),
    )
    >= 37
)
# really much bigger expected, in runs it was 63, 60, 50
def gen_eds(k=1000):
    eds = []
    for _ in range(k):
        key2 = bs(len("this is a test"))
        eds.append(
            edit_distance(
                pwn.xor(key, "this is a test".encode()),
                pwn.xor(key2, "wokka wokka!!!".encode()),
            )
        )
    return eds


eds = gen_eds(10_000)
print(statistics.mean(eds), statistics.pstdev(eds))  # mean 55, stdev 5.3

plain_inputs = [
    (
        "Some text of a decent length to check the key length finding algorithm.  It looks like we need some fair bit of text to work with.",
        bs(len("abcdefghijklmn")),
    ),
    (
        "Some text of a decent length to check the key length finding algorithm.  It looks like we need some fair bit of text to work with.",
        bs(len("abcdefghijklmnop")),  # .encode(),
    ),
    (
        "Some text of a decent length to check the key length finding algorithm.  It looks like we need some fair bit of text to work with.",
        bs(len("abcdefghijklmnopqr")),  # .encode(),
    ),
]

# for the randomly generated keys we find them in the first three; in
# fact in runs they were first or second, and then second to their
# double.

for text, key in plain_inputs:
    key_length = len(key)
    ic(key_length)
    cipher = repeating_key_xor(text, key)
    key_size_guesses = find_keysize(cipher)
    print(key_length, key, key_size_guesses)
    assert key_length in [s for s, _ in key_size_guesses]

text = "Some text of a decent length to check the key length finding algorithm.  It looks like we need some fair bit of text to work with."
key = "abcdefghijklmn".encode()
key_length = len(key)
ic(key_length)
cipher = repeating_key_xor(text, key)
key_size_guesses = find_keysize(cipher, k=30)
print(
    [idx for idx, v in enumerate(key_size_guesses) if v[0] == key_length]
)  # 16, and by inspection the double is later in the list


text = "Some text of a decent length to check the key length finding algorithm.  It looks like we need some fair bit of text to work with."
key = "YELLOW SUBMARINE".encode()
key_length = len(key)
ic(key_length)
cipher = repeating_key_xor(text, key)
key_size_guesses = find_keysize(cipher, k=40)
print(
    [idx for idx, v in enumerate(key_size_guesses) if v[0] == key_length]
)  # 8, the double is a couple spots before in the list
