# Bitcoin address-based TeslaCrypt key reconstructor
#
# This is an alternative to unfactor-ecdsa.py, which should also work with
# ancient versions of TeslaCrypt.
# 
# To use this tool, you need the Bitcoin address where ransom was expected to be paid,
# as well as the 512-bit Bitcoin shared secret. This is typically found in the recovery
# file, which is a text file named "RECOVERY_KEY.TXT", "recover_file.txt", or similar
# dropped in the Documents folder by TeslaCrypt.
# The first line of the recovery file is the Bitcoin address, while the 3rd line is
# the shared secret. These values can also be obtained from key.dat, storage.bin
# TeslaCrypt's registry entry, or (in case of TeslaCrypt 2.x) from the encrypted files
# or from network packet dumps, in case the recovery file is lost.
#
# Once you have these values, factor the shared secrets, then run this script with the
# factors, like this:
# unfactor-bitcoin.py <1st line of recovery file> <factors of 3rd line of recovery file>
# The generated key can then be used with TeslaDecoder.

from __future__ import print_function
try:
    from coinkit.keypair import BitcoinKeypair
except ImportError:
    from pybitcoin.keypair import BitcoinKeypair
import sys

def main(addr, primes):
    addrs = {}
    prod = 1
    try:
        xrange
    except NameError:
        xrange = range
    for p in primes:
        if int(p) >= 1<<256:
            return "Factor too large: %s" % p
        prod *= int(p)
    if prod >= 1<<512:
        return "Superfluous factors or incorrect factorization detected!"
    
    i = 1
    while i < 1<<len(primes):
        x = 1
        for j in xrange(len(primes)):
            if i & 1<<j:
                x *= int(primes[j])
        if x < 1<<256 and prod/x < 1<<256:
            if x not in addrs:
                addrs[x] = BitcoinKeypair(x).address()
            if addr == addrs[x]:
                return "Found Bitcoin private key: %064X" % x
        i += 1

    return "No keys found, check your factors!"
    
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("usage: unfactor-bitcoin.py <bitcoin address> <space-separated list of factors>")
        exit()
    print(main(sys.argv[1], sys.argv[2:]))
