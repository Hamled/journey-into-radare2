#!/usr/bin/env python
import sys


DECODE_TABLE = "AaCcdDeFfGhiKLlMmnNoOpPrRsSTtUuVvwWxyZz32.\\EbgjHI _YQB:\"/@\r\n\x1A"

def decode(str):
    indexes = bytes(str, 'ascii')
    return ''.join([ DECODE_TABLE[x] for x in indexes[::2] ])

if __name__ == "__main__":
    if len(sys.argv) > 1:
        decoded = decode(sys.argv[1])
    else:
        decoded = decode(sys.stdin.readline())
    print(decoded)
