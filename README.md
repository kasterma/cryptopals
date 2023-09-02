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

## Note on Set 1; challenge 7

The "You can obviously decrypt this using the OpenSSL command-line
tool" solution, wasn't as easy to find as I was hoping.  Confusing (to
me) errors, and then a final not careful reading of a man page.
Solution is

    openssl enc -aes-128-ecb -d -a -in 7.txt -K $(echo -n "YELLOW SUBMARINE" | xxd -p)

Last error to solve was the hex encoding of the key.  In the man
page it does give

    -K val              Raw key, in hex

but in the -pass option page
https://www.openssl.org/docs/manmaster/man1/openssl-passphrase-options.html
I didn't find this information.  Also I currently still don't know how
to pass this through the '-pass' option.
