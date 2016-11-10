from Crypto import Random
from Crypto.Cipher import AES, DES, DES3
from Crypto.Util.py3compat import *
from Crypto.Util.number import long_to_bytes, bytes_to_long, size, ceil_div


def get_zero_vector(numBytes):
    """
    Generates a zero vector of a given size

    :param numBytes:
    :return:
    """
    return bytearray([0] * numBytes).decode('ascii')


def compute_kcv_aes(key):
    aes = AES.new(key, AES.MODE_ECB)
    return aes.encrypt(get_zero_vector(16))


def compute_kcv_3des(key):
    aes = DES3.new(key, AES.MODE_ECB)
    return aes.encrypt(get_zero_vector(8))

