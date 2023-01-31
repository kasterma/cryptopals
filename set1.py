## set1

import base64


def hex2b64(x):
    return base64.b64encode(bytes.fromhex(x)).decode("ascii")


def fixed_xor(i, k):
    assert len(i) == len(k)
    i = bytes.fromhex(i)
    k = bytes.fromhex(k)
    return bytes(ii ^ kk for ii, kk in zip(i, k)).hex()
