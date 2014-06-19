import collections
import ecdsa
import hashlib
import re

from .secure_random import SecureRandom
from .base58 import base58decode, base58encode, BASE58_ALPHABET_REGEX

class Cryptocoin(collections.namedtuple('CryptocoinDescription',
                                        ['code',
                                         'network_version',
                                         'private_key_prefix',
                                         'wallet_import_format_prefix',
                                         'compressed_wif_prefix'])):
    def is_wallet_import_format(self, byteseq):
        regex = b'^' + self.wallet_import_format_prefix + \
                    BASE58_ALPHABET_REGEX + b'{50}$'
        return re.match(regex, byteseq) is not None

    def __str__(self):
        return self.code

Bitcoin  = Cryptocoin('BTC', 0x00, 0x80, b'5', b'[LK]')
Litecoin = Cryptocoin('LTC', 0x30, 0xb0, b'6', b'T')
Dogecoin = Cryptocoin('DOGE', 0x1e, 0x9e, b'6', b'Q')
Testnet  = Cryptocoin('TESTNET', 0x6F, 0xEF, b'9', b'c')

# TODO: auto add coins to a coin container
COINS = [Bitcoin, Litecoin, Dogecoin, Testnet]


def decode_wallet_import_format(base58_text, version=None):
    bs = base58decode(base58_text)
    data = bs[0:33]
    checksum = hashlib.sha256(hashlib.sha256(data).digest()).digest()

    if checksum[:4] != bs[33:]:
        raise ValueError("Failed to validate checksum!")

    if version is not None and version != data[0]:
        raise ValueError("Unexpected version!")

    return data[1:], data[0]


class CoinAddress():
    """
    >>> a = CoinAddress(Bitcoin, '5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ')
    >>> a.in_wallet_import_format
    b'5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ'
    >>> a.address
    b'1GAehh7TsJAHuUAeKZcXf5CnwuGuGgyX2S'
    >>> a = CoinAddress(Bitcoin, 0x18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725)
    >>> a.address
    b'16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM'
    >>> str(CoinAddress(Litecoin, '6vcHcscccKuBVdka8qXkb2aD5YPvxzf6zv5RfFrVNi5JYGJ55W7'))
    'LTC: LZSQEQSKQeyx64rTZAND3FkfNWBAFzg4WQ (priv: 6vcHcscccKuBVdka8qXkb2aD5YPvxzf6zv5RfFrVNi5JYGJ55W7 )'
    """

    # TODO: compressed addresses

    def __init__(self, currency, private_key_data=None):
        """
        :param currency: Cryptocoin object
        :param private_key_data: can be one of
            - None (new key is generate)
            - int
            - 32 bytes
            - wallet import format
        """
        assert isinstance(currency, Cryptocoin)
        self.currency = currency
        self.secret = self.parse_private_key(private_key_data)

    def parse_private_key(self, private_key_data):
        if private_key_data is None:
            return self.generate_new_ecdsa_private_key()
        if isinstance(private_key_data, int):
            return private_key_data
        if isinstance(private_key_data, str):
            private_key_data = private_key_data.encode('utf8')
        if isinstance(private_key_data, bytes):
            if self.currency.is_wallet_import_format(private_key_data):
                private_key_data,*_ = decode_wallet_import_format(
                                        private_key_data,
                                        version=self.currency.private_key_prefix
                                    )
            # TODO: more formats - base64, hex, compressed, etc.
            if len(private_key_data) != 32:
                raise ValueError("Unknown private_key_data bytes data")
            return int.from_bytes(private_key_data, 'big')

        raise ValueError("Unknown private_key_data type")

    def generate_new_ecdsa_private_key(self):
        g = ecdsa.ecdsa.generator_secp256k1
        n = g.order()
        secret = SecureRandom().randrange(1, n)
        return secret

    @property
    def public_key(self):
        g = ecdsa.ecdsa.generator_secp256k1
        return ecdsa.ecdsa.Public_key(g, g * self.secret)

    @property
    def private_key(self):
        return ecdsa.ecdsa.Private_key(self.public_key, self.secret)

    @property
    def in_wallet_import_format(self):
        data = self.currency.private_key_prefix.to_bytes(1, 'big') + \
                self.secret.to_bytes(32, 'big')
        checksum = hashlib.sha256(hashlib.sha256(data).digest()).digest()
        return base58encode(data + checksum[:4])

    @property
    def address(self):
        pub = self.public_key
        pub_der = (b'\x04' +
                   pub.point.x().to_bytes(32, 'big') +
                   pub.point.y().to_bytes(32, 'big'))

        pub_ripemd160 = hashlib.new(
                            'ripemd160',
                            hashlib.sha256(pub_der).digest()
                        ).digest()
        data = self.currency.network_version.to_bytes(1, 'big') + pub_ripemd160
        checksum = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
        return base58encode(data + checksum)

    def __str__(self):
        return '%s: %s (priv: %s )' % (self.currency.code,
                                       self.address.decode(),
                                       self.in_wallet_import_format.decode())


if __name__ == "__main__":
    import doctest
    doctest.testmod()
