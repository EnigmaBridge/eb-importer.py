from Crypto import Random
from Crypto.Cipher import AES, DES, DES3
from Crypto.Util.py3compat import *
from Crypto.Util.number import long_to_bytes, bytes_to_long, size, ceil_div
from Crypto.PublicKey.RSA import RSAImplementation
import hashlib


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
    des = DES3.new(key, DES3.MODE_ECB)
    return des.encrypt(get_zero_vector(8))


def rsa_pub_key_to_pem(n, e):
    rsa = RSAImplementation()
    rsa_key = rsa.construct((n, e))
    pem = rsa_key.exportKey()
    return pem


def sha1(data):
    return hashlib.sha1(data).digest()


def sha1_hex(data):
    return hashlib.sha1(data).hexdigest()

