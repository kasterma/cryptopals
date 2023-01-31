## set1

import base64


def hex2b64(x):
    return base64.b64encode(bytes.fromhex(x)).decode("ascii")
