import collections
import re

from .base58 import BASE58_ALPHABET_REGEX

class CryptoCurrency(collections.namedtuple('CryptoCurrencyDescription',
                                            ['code',
                                             'network_version',
                                             'private_key_prefix',
                                             'wallet_import_format_prefix',
                                             'compressed_wif_prefix'])):
    def is_wallet_import_format(self, byteseq):
        regex = b'^' + self.wallet_import_format_prefix + \
                    BASE58_ALPHABET_REGEX + b'{50}$'
        return re.match(regex, byteseq) is not None

    def __eq__(self, other):
        return self.network_version == other.network_version

    def __str__(self):
        return self.code


class CryptoCurrencyContainer(list):

    def get_by_attr(self, attr, value):
        return {getattr(coin, attr): coin for coin in self}[value]

    def get_by_code(self, code):
        return self.get_by_attr('code', code.upper())

    def get_by_network_version(self, version):
        return self.get_by_attr('network_version', version)

    def get_by_private_key_prefix(self, private_key_prefix):
        return self.get_by_attr('private_key_prefix', private_key_prefix)

    def __repr__(self):
        return '%s(%s)' % (self.__class__.__name__, super().__repr__())

    def __getattr__(self, attr):
        if attr.upper() in [currency.code for currency in self]:
            return self.get_by_code(attr)

        return super().__getattr__(attr)


Bitcoin  = CryptoCurrency('BTC', 0x00, 0x80, b'5', b'[LK]')
Litecoin = CryptoCurrency('LTC', 0x30, 0xb0, b'6', b'T')
Dogecoin = CryptoCurrency('DOGE', 0x1e, 0x9e, b'6', b'Q')
Testnet  = CryptoCurrency('TESTNET', 0x6F, 0xEF, b'9', b'c')

COINS = CryptoCurrencyContainer([Bitcoin, Litecoin, Dogecoin, Testnet])
