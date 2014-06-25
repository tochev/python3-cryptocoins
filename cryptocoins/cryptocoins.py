#!/usr/bin/env python3
import ecdsa
import hashlib
import requests

from .secure_random import SecureRandom
from .base58 import base58decode, base58encode
from .crypto_currencies import COINS, CryptoCurrency


def checksum_bytes(data, count=4):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()[:count]

def decode_wallet_import_format(base58_text, version=None):
    bs = base58decode(base58_text)
    data = bs[0:33]

    if checksum_bytes(data) != bs[33:]:
        raise ValueError("Failed to validate wallet checksum!")

    if version is not None and version != data[0]:
        raise ValueError("Unexpected version!")

    return data[1:], data[0]


class PublicAddress():
    """Public address."""

    def __init__(self, address, currency=None):
        self.address, self.currency = CoinAddress.validate_address(address)
        if currency is not None and currency != self.currency:
            raise ValueError(
                "Currency mismatch. Address belongs to %s, expected %s." % (
                    self.currency.code, currency.code))

    @staticmethod
    def validate_address(address):
        """Validates an address and converts it to bytes.

        :returns: (bytes(address), crypto_currency)
        :raises: ValueError, KeyError
        """
        if isinstance(address, str):
            address = address.encode('ascii')
        bs = base58decode(address)
        if checksum_bytes(bs[:21]) != bs[21:]:
            raise ValueError("Failed to validate address checksum!")
        currency = COINS.get_by_network_version(bs[0])
        return address, currency

    def __str__(self):
        return self.address.decode('ascii')

    def get_balance(self):
        """Note this makes a call to blockr.io.

        :returns: float
        """
        SUPPORTED_CODES = {'BTC': 'btc', 'LTC': 'ltc', 'TESTNET': 'tbtc'}
        code = self.currency.code
        assert code in SUPPORTED_CODES, "Currency %s not supported" % code
        r = requests.get('https://%s.blockr.io/api/v1/address/balance/%s' %
                            (SUPPORTED_CODES[code], self.address.decode('ascii')))
        r.raise_for_status()
        return r.json()['data']['balance']


class CoinAddress(PublicAddress):
    """
    Address associated with a private key.

    >>> a = CoinAddress(COINS.BTC, '5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ')
    >>> a.in_wallet_import_format
    b'5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ'
    >>> a.address
    b'1GAehh7TsJAHuUAeKZcXf5CnwuGuGgyX2S'
    >>> a = CoinAddress(COINS.BTC, 0x18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725)
    >>> a.address
    b'16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM'
    >>> str(CoinAddress(COINS.LTC, '6vcHcscccKuBVdka8qXkb2aD5YPvxzf6zv5RfFrVNi5JYGJ55W7'))
    'LTC: LZSQEQSKQeyx64rTZAND3FkfNWBAFzg4WQ (priv: 6vcHcscccKuBVdka8qXkb2aD5YPvxzf6zv5RfFrVNi5JYGJ55W7 )'
    """

    # TODO: compressed addresses

    def __init__(self, currency, private_key_data=None):
        """
        :param currency: CryptoCurrency object
        :param private_key_data: can be one of
            - None (new key is generate)
            - int
            - 32 bytes
            - wallet import format
        """
        assert isinstance(currency, CryptoCurrency)
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
        return base58encode(data + checksum_bytes(data))

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
        return base58encode(data + checksum_bytes(data))

    def __str__(self):
        return '%s: %s (priv: %s )' % (self.currency,
                                       self.address.decode(),
                                       self.in_wallet_import_format.decode())



if __name__ == "__main__":
    import doctest
    doctest.testmod()
