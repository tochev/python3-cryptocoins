# NOTE different base58 alphabets are used for cryptocoins and other
# application, the difference is in the order of lower and upper case

BASE58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58_ALPHABET_REGEX = b'[1-9A-HJ-NP-Za-km-z]'
BASE58_REGEX = b'^' + BASE58_ALPHABET_REGEX + b'+$'

def base58decode(base58_text):
    """
    >>> list(map(int, base58decode(b'5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ')))
    [128, 12, 40, 252, 163, 134, 199, 162, 39, 96, 11, 47, 229, 11, 124, 174, 17, 236, 134, 211, 191, 31, 190, 71, 27, 232, 152, 39, 225, 157, 114, 170, 29, 80, 122, 91, 141]
    """
    n = 0
    leading_zeroes_count = 0
    for b in base58_text:
        n = n * 58 + BASE58_ALPHABET.find(b)
        if n == 0:
            leading_zeroes_count += 1

    res = bytearray()
    while n >= 256:
        div, mod = divmod(n, 256)
        res.insert(0, mod)
        n = div
    else:
        res.insert(0, n)

    return bytearray(1)*leading_zeroes_count + res

def base58encode(byteseq):
    """
    >>> base58encode(bytes([128, 12, 40, 252, 163, 134, 199, 162, 39, 96, 11, 47, 229, 11, 124, 174, 17, 236, 134, 211, 191, 31, 190, 71, 27, 232, 152, 39, 225, 157, 114, 170, 29, 80, 122 , 91, 141]))
    b'5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ'
    """
    n = 0
    leading_zeroes_count = 0
    for c in byteseq:
        n = n * 256 + c
        if n == 0:
            leading_zeroes_count += 1

    res = bytearray()
    while n >= 58:
        div, mod = divmod(n, 58)
        res.insert(0, BASE58_ALPHABET[mod])
        n = div
    else:
        res.insert(0, BASE58_ALPHABET[n])
    return BASE58_ALPHABET[0:1] * leading_zeroes_count + res

if __name__ == "__main__":
    import doctest
    doctest.testmod()
