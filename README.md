# cryptopals

Cryptopals Rule: Always operate on raw bytes, never on encoded
strings.  Only use hex and base64 for pretty-printing.

## Python strings and bytes

bytes is an immutable version of bytearray.

    s: string
    b: bytes

    b'hello'    # bytes literal, looks like ascii internally seq of integers 0 <= x < 256

    s.encode([encoding]), b.decode([encoding])     # e.g. utf-8 coding
    bytes.fromhex(s), b.hex()                      # hex representation of bytes
    base64.b64encode(b), base64.b64decode(b)       # base64 encoding
