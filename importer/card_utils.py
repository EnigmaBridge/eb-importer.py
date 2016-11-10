#!/usr/bin/python -u
import time
import shlex
import os
import sys
import types
import subprocess
import threading
import socket
import hashlib
import traceback
from datetime import datetime
from smartcard.System import readers
from smartcard.util import toHexString


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


def get_key_types():
    return ['AES', '3DES']


def get_key_type(type_idx):
    if type_idx is None:
        return None

    key_types = get_key_types()
    if type_idx >= len(key_types):
        return None

    return key_types[type_idx]


def is_continue_status(sw):
    return (sw & 0x6100) == 0x6100


def get_continue_bytes(sw):
    if is_continue_status(sw):
        return sw & 0xff
    return None


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
        """1B - used/unused, 2B - share length, 2B - KCV1, 2B - KCV2"""
        if len(data) < 7:
            raise ValueError('KeyShare info is supposed to have at least 7 Bytes')

        self.used = data[0] != 0
        self.share_len = get_2bytes(data, 1)
        self.kcv1 = get_2bytes(data, 3)
        self.kcv2 = get_2bytes(data, 5)

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

