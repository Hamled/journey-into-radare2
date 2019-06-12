#!/usr/bin/env python
import sys


DEFAULT_TABLE = "AaCcdDeFfGhiKLlMmnNoOpPrRsSTtUuVvwWxyZz32.\\EbgjHI _YQB:\"/@\r\n\x1A"

def decode(indexes, table=DEFAULT_TABLE):
    return ''.join([ table[x] for x in indexes[::2] ])

if __name__ == "__main__":
    if len(sys.argv) > 1:
        input = sys.argv[1]
    else:
        input = sys.stdin.readline()

    print(decode(bytes(input, 'ascii')))
