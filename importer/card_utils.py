#!/usr/bin/python -u
import time
import shlex
import os
import sys
import types
import utils
import base64
import math
import subprocess
import threading
import socket
import hashlib
import traceback
from smartcard.System import readers
from smartcard.util import toHexString
from Crypto.Util.py3compat import *
from Crypto.Util.number import long_to_bytes, bytes_to_long, size, ceil_div


def format_data(data):
    str_res = ''
    for x in data:
        if isinstance(x, (types.IntType, types.LongType)):
            str_res += '%02X ' % x
        elif isinstance(x, types.StringTypes):
            str_res += '%02X ' % ord(x)
        else:
            raise ValueError('Unknown type: ', x)
    return str_res.strip()


def get_2bytes(data, offset=0):
    return (data[offset] << 8) | data[offset + 1]


def is_continue_status(sw):
    return (sw >> 8) == 0x61


def get_continue_bytes(sw):
    if is_continue_status(sw):
        return sw & 0xff
    return None


def hamming_weight(n):
    return bin(n).count("1")


def fix_parity_bits_3des(key_bits):
    ln = len(key_bits)
    res_key = ['0'] * ln

    for i in range(0, ln):
        x = long(ord(key_bits[i]))
        hw = hamming_weight(x >> 1)
        if (hw % 2) == 0:
            res_key[i] = chr(x | 0x1)
        else:
            res_key[i] = chr(x & (~0x1))

    return ''.join(res_key)


def add_parity_bits_3des(key_bits):
    ln = len(key_bits)
    if ((ln*8) % 7.0) != 0:
        raise ValueError('The key does not have correct size for adding parity bits')

    new_size = ln*8/7
    res_key = [0L] * new_size
    key_long = bytes_to_long(key_bits)
    for i in range(0, new_size):
        x = key_long & 0x7F
        p = 1 if hamming_weight(x) % 2 == 0 else 0
        res_key[new_size - i - 1] = x << 1 | p
        key_long >>= 7

    res = ''.join([chr(int(x)) for x in res_key])
    return res


def remove_parity_bits_3des(key_bits):
    ln = len(key_bits)
    if ((ln*7) % 8.0) != 0:
        raise ValueError('Invalid key size to remove the parity bits')

    new_size = ln*7/8
    res_key = [0L] * new_size

    key_new_long = 0L
    for i in range(0, ln):
        x = long(ord(key_bits[i])) >> 1
        key_new_long = (key_new_long << 7) | (x & 0x7f)

    for i in range(0, new_size):
        x = key_new_long & 0xff
        res_key[new_size - i - 1] = x
        key_new_long >>= 8

    res = ''.join([chr(int(x)) for x in res_key])
    return res


class KeyType(object):
    def __init__(self, name=None, id=None, key_len=None, kcv_fnc=None, *args, **kwargs):
        self.name = name
        self.id = id
        self.key_len = key_len
        self.kcv_fnc = kcv_fnc

    def process_key(self, key_hex):
        return key_hex

    def __repr__(self):
        return self.name


class KeyType3DES(KeyType):
    def __init__(self, *args, **kwargs):
        super(KeyType3DES, self).__init__(*args, **kwargs)

    def process_key(self, key_hex):
        ln = len(key_hex.strip())
        if ln % 2 != 0:
            raise ValueError('Key value hex-coding has odd number of digits')
        ln /= 2

        key_bits = base64.b16decode(key_hex, True)

        # Fix parity bits
        if ln == self.key_len:
            key_bits = fix_parity_bits_3des(key_bits)
            return base64.b16encode(key_bits)

        # Add parity bits
        non_parity_len = self.key_len - self.key_len/8
        if ln != non_parity_len:
            raise ValueError('Key Type %s is not neither %s B nor %s B long' % (self.name, self.key_len, non_parity_len))

        key_bits = add_parity_bits_3des(key_bits)
        return base64.b16encode(key_bits)


KEY_TYPE_AES_128 = KeyType(name="AES-128", id=0x01, key_len=16, kcv_fnc=utils.compute_kcv_aes)
KEY_TYPE_AES_256 = KeyType(name="AES-256", id=0x10, key_len=32, kcv_fnc=utils.compute_kcv_aes)
KEY_TYPE_3DES_112 = KeyType3DES(name="3DES-112", id=0x20, key_len=16, kcv_fnc=utils.compute_kcv_3des)
KEY_TYPE_3DES_168 = KeyType3DES(name="3DES-168", id=0x40, key_len=24, kcv_fnc=utils.compute_kcv_3des)


def get_key_types():
    return [KEY_TYPE_AES_128, KEY_TYPE_AES_256, KEY_TYPE_3DES_112, KEY_TYPE_3DES_168]


def get_key_type(type_idx):
    if type_idx is None:
        return None

    key_types = get_key_types()
    if type_idx >= len(key_types):
        return None

    return key_types[type_idx]


class KeyShareInfo(object):
    """
    Key share info returned by the card
    """
    def __init__(self, *args, **kwargs):
        self.message = None
        self.message_str = None
        self.used = None
        self.share_len = None
        self.kcv1 = None
        self.kcv2 = None
        self.key_type = None

    def parse_info(self, data):
        """1B - used/unused, 1B - key type, 2B - share length, 2B - KCV1, 2B - KCV2"""
        if len(data) < 8:
            raise ValueError('KeyShare info is supposed to have at least 7 Bytes')

        self.used = data[0] != 0
        self.key_type = data[1]
        self.share_len = get_2bytes(data, 2)
        self.kcv1 = get_2bytes(data, 4)
        self.kcv2 = get_2bytes(data, 6)

    def parse_message(self, data):
        """ASCII text"""
        self.message = data

        if data is not None:
            self.message_str = ''.join([chr(x) for x in data])
        pass

    def kcv_data(self):
        pass

    def __repr__(self):
        return 'KeyShareInfo{type: %s, used: %s, share_len: %d (0x%x), kcv1: 0x%04X, kcv2: 0x%04X, message: \"%s\"}' \
               % (self.key_type, self.used, self.share_len, self.share_len,
                  self.kcv1, self.kcv2, self.message_str)


class Logs(object):
    """
    Log records
    """
    def __init__(self, *args, **kwargs):
        self.lines = []
        self.overflows = None
        self.signature = None
        self.container = None

    def add(self, line):
        self.lines.append(line)

    def sort(self):
        """
        Sorts log lines from the latest to the newest
        """

        # Overflows total ID computation.
        # The last used log entry is the latest.
        # Scan logs in DESC ordering, if there is a big shift compared to the previous ID,
        # overflow happened. Overflow is up-to-date for the last record only. Fot others it has to
        # be recomputed.
        lines = self.lines
        max_id = None
        offset = 0L
        for idx in range(len(lines)-1, -1, -1):
            clog = lines[idx]
            if not clog.used:
                continue

            clog.id |= self.overflows << 16
            clog.id -= offset
            if max_id is None:
                max_id = clog.id
                continue

            diff = abs(lines[idx+1].id - lines[idx].id)
            if diff >= 0x7fffL:
                offset += 0x10000L
                clog.id -= offset

        # self.lines = sorted(self.lines, key=lambda x: x.id, reverse=False)

    def __repr__(self):
        return 'Logs{entries: %s, overflows: 0x%x, lines: %s, signature: %s}' \
               % (len(self.lines), self.overflows, self.lines, self.signature)


class LogLine(object):
    """
    Log line returned by the card
    """
    def __init__(self, *args, **kwargs):
        self.used = None
        self.status = None
        self.raw_id = None
        self.orig_id = None
        self.id = None
        self.total_id = None
        self.len = None
        self.operation = None
        self.share_id = None
        self.uoid = None

    def parse_line(self, data, logs=None):
        """
        <1B - used/not> | <2B - log entry status > | <2B - item ID> | <2B - msg length> | <8B - message>

        Message:
        <1B - operation ID> | <1B - share ID> | <2B UOID high> | <2B UOID low>
        :param data:
        :return:
        """
        if len(data) < 7:
            raise ValueError('LogLine is supposed to have at least 15 Bytes')

        self.used = data[0] != 0
        self.status = get_2bytes(data, 1)
        self.raw_id = long(get_2bytes(data, 3))
        self.len = get_2bytes(data, 5)
        self.operation = data[7]
        self.share_id = data[8]
        self.uoid = (get_2bytes(data, 9) << 16) | get_2bytes(data, 11)
        self.id = self.raw_id - 0x8000
        self.orig_id = self.id

    def __repr__(self):
        return 'LogLine{used: %s, status: %d (0x%x), id: 0x%x, len: %d (0x%x), op: 0x%x, share_id: %d, uoid: %08x}' \
               % (self.used, self.status, self.status, self.id, self.len, self.len, self.operation,
                  self.share_id, self.uoid)


class RSAPublicKey(object):
    """
    Public key exported by the card
    """
    def __init__(self, *args, **kwargs):
        self.n = None
        self.e = None

    def parse(self, data):
        """
        0x81 | 2Blen | exp | 0x82 | 2Blen | modulus
        :param data:
        :return:
        """
        if len(data) < 8:
            raise ValueError('LogLine is supposed to have at least 15 Bytes')

        # TLV parser
        tlen = len(data)
        tag, clen, idx = 0, 0, 0
        while idx < tlen:
            tag = data[idx]
            clen = get_2bytes(data, idx+1)
            idx += 3
            cdata = data[idx: (idx + clen)]

            if tag == 0x81:
                self.e = long(''.join([('%02x' % x) for x in cdata]), 16)
            elif tag == 0x82:
                self.n = long(''.join([('%02x' % x) for x in cdata]), 16)
            idx += clen

    def __repr__(self):
        return 'RSAPubKey{n: %x, e: %x}' % (self.n, self.e)


