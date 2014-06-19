import os
import sys
from random import Random, RECIP_BPF

if sys.platform == 'linux':
    def _random(count):
        with open('/dev/random', 'rb') as fd:
            return fd.read(count)
else:
    _random = os.urandom


class SecureRandom(Random):
    """Alternate random number generator using sources provided
    by the operating system (such as /dev/random on Unix or
    CryptGenRandom on Windows).

     Not available on all systems (see os.urandom() for details).
    """

    def random(self):
        """Get the next random number in the range [0.0, 1.0)."""
        return (int.from_bytes(self.getrandbits(7 * 8), 'big') >> 3) * RECIP_BPF

    def getrandbits(self, k):
        """getrandbits(k) -> x.  Generates an int with k random bits."""
        if k <= 0:
            raise ValueError('number of bits must be greater than zero')
        if k != int(k):
            raise TypeError('number of bits should be an integer')
        numbytes = (k + 7) // 8                       # bits / 8 and rounded up
        x = int.from_bytes(_random(numbytes), 'big')
        return x >> (numbytes * 8 - k)                # trim excess bits

    def seed(self, *args, **kwds):
        "Stub method.  Not used for a system random number generator."
        return None

    def _notimplemented(self, *args, **kwds):
        "Method should not be called for a system random number generator."
        raise NotImplementedError('System entropy source does not have state.')
    getstate = setstate = _notimplemented
