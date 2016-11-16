#!/usr/bin/python -u
import time
import os
import sys
import types
import utils
import base64
import math
import hashlib
import traceback
import logging
import errors
from smartcard.System import readers
from smartcard.util import toHexString, toBytes, PACK
from Crypto.Util.py3compat import *
from Crypto.Util.number import long_to_bytes, bytes_to_long, size, ceil_div


logger = logging.getLogger(__name__)


operation_logs = {
    0x31:	'SET KEY SHARE      ',
    0x32:   'CREATE USER OBJECT ',
    0x33:   'ERASE SHARES       ',
    0x35:   'GET KEY SHARES INFO'
}


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


def get_key_type(type_idx=None, id=None):
    if type_idx is None and id is None:
        return None

    key_types = get_key_types()

    if type_idx is not None:
        if type_idx >= len(key_types):
            return None

        return key_types[type_idx]

    if id is not None:
        for t in key_types:
            if t.id == id:
                return t


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
        self.lines_all = []
        self.overflows = None
        self.signature = None
        self.container = None
        self.max_idx = None
        self.max_id = None
        self.was_sorted = False

    def add(self, line):
        self.lines.append(line)

    def process(self):
        """
        Sorts log lines from the latest to the newest
        """
        if self.was_sorted:
            return

        # Overflows total ID computation.
        # The last used log entry is not the latest - round robin buffering is used.
        all_used = True
        for x in self.lines:
            if not x.used:
                all_used = False
                break

        # If all log lines are used - find the minimum index and start looping from there
        if all_used:
            tmp_lines = self.lines
            ln = len(tmp_lines)

            # Finding the oldest log record
            # overflow happened? if max(x) - min(x) >= 0x7fff/2 (take also round robin into account)
            overflow_happened = (max(tmp_lines, key=lambda x: x.id).id
                                 - min(tmp_lines, key=lambda x: x.id).id) > 0x7fffL/2
            if overflow_happened:
                # If overflow - find the lowes from the high numbers.
                min_id_idx = min([x for x in range(ln) if tmp_lines[x].id >= 0x7fffL], key=lambda x: tmp_lines[x].id)
            else:
                # No overflow - find index with minimal ID
                min_id_idx = min(range(ln), key=lambda x: tmp_lines[x].id)

            self.lines = [tmp_lines[min_id_idx]]
            idx = min_id_idx + 1

            # Read from the minimum element - so the sorting from oldest to newest (also with overflow) is fixed
            while idx != min_id_idx:
                self.lines.append(tmp_lines[idx])
                idx = (idx + 1) % ln
            pass

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
                self.max_idx = idx
                self.max_id = max_id
                continue

            diff = abs(lines[idx+1].id - lines[idx].id)
            if diff >= 0x7fffL/2:
                offset += 0x10000L
                clog.id -= offset

        # Make lines contain only used entries
        self.lines_all = self.lines
        self.lines = [x for x in self.lines_all if x.used]
        self.was_sorted = True

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
        self.data = None

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
        self.data = (get_2bytes(data, 9) << 16) | get_2bytes(data, 11)
        self.id = self.raw_id - 0x8000
        self.orig_id = self.id

    def __repr__(self):
        return 'LogLine{used: %s, status: %d (0x%x), id: 0x%x, len: %d (0x%x), op: 0x%x, share_id: %d, data: %08x}' \
               % (self.used, self.status, self.status, self.id, self.len, self.len, self.operation,
                  self.share_id, self.data)


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


class EBCardReader(object):
    """
    EB Card reader info
    """
    def __init__(self, reader=None, card_ok=False, *args, **kwargs):
        self.reader = reader
        self.card_ok = card_ok
        self.import_applet_ok = False
        self.card_id = None


class EBCard(object):
    """
    EB Card utils
    """
    def __init__(self, reader=None, connection=None, *args, **kwargs):
        self.card = reader
        self.connection = connection
        self.debug = False

    def get_shares(self):
        res, sw = self.send_get_shares()
        if sw != 0x9000:
            logger.error('Could not get key shares info, code: %04X' % sw)
            raise errors.InvalidResponse('Could not get key shares info, code: %04X' % sw)

        key_shares = []
        cur_share = None

        # TLV parser
        tlen = len(res)
        tag, clen, idx = 0, 0, 0
        while idx < tlen:
            tag = res[idx]
            clen = get_2bytes(res, idx+1)
            idx += 3
            cdata = res[idx: (idx + clen)]

            if tag == 0xa9:
                # KeyShare info
                if cur_share is not None:
                    key_shares.append(cur_share)

                cur_share = KeyShareInfo()
                cur_share.parse_info(cdata)

            elif tag == 0xad:
                # KeyShare message
                cur_share.parse_message(cdata)

            idx += clen
        pass

        if cur_share is not None:
            key_shares.append(cur_share)

        return key_shares

    def get_logs(self, limit=None):
        res, sw = self.send_get_logs()
        if sw != 0x9000:
            logger.error('Could not get logs, code: %04X' % sw)
            raise errors.InvalidResponse('Could not get logs, code: %04X' % sw)

        logs = Logs()

        # TLV parser
        tlen = len(res)
        tag, clen, idx = 0, 0, 0
        while idx < tlen:
            tag = res[idx]
            clen = get_2bytes(res, idx+1)
            idx += 3
            cdata = res[idx: (idx + clen)]

            if tag == 0xae:
                # Log container
                entries = get_2bytes(cdata)
                logs.overflows = get_2bytes(cdata, 2)

                # Store the whole container for signature verification
                logs.container = cdata

                # Extract each log line record
                for entry_idx in range(0, entries):
                    offset = 4 + entry_idx * 15
                    cline = cdata[offset:offset+15]

                    cur_log = LogLine()
                    cur_log.parse_line(cline, logs)
                    logs.add(cur_log)

            elif tag == 0xab:
                # Signature
                logs.signature = cdata

            idx += clen

        # Fix the ordering w.r.t. overflows counter
        logs.process()
        return logs

    def get_pubkey(self):
        res, sw = self.send_get_pubkey()
        if sw != 0x9000:
            logger.error('Could not get public key, code: %04X' % sw)
            raise errors.InvalidResponse('Could not get public key, code: %04X' % sw)

        pk = RSAPublicKey()
        pk.parse(res)
        return pk

    def get_seed_pubkey(self):
        res, sw = self.send_get_seed_pubkey()
        if sw != 0x9000:
            logger.error('Could not get public key, code: %04X' % sw)
            raise errors.InvalidResponse('Could not get public key, code: %04X' % sw)

        pk = RSAPublicKey()
        pk.parse(res)
        return pk

    def connect_card(self):
        try:
            self.connection = self.card.createConnection()
            self.connection.connect()
        except Exception as e:
            logger.error('Exception in opening a connection: %s' % e)
            if self.debug:
                traceback.print_exc()
            raise e

    def select_importcard(self):
        resp, sw = self.select_applet([0x31, 0x32, 0x33, 0x34, 0x35, 0x36])
        if sw != 0x9000:
            raise errors.InvalidApplet('Could not select import card applet. Error: %04X' % sw)

        return resp, sw

    def select_applet(self, id):
        select = [0x00, 0xA4, 0x04, 0x00, len(id)]

        resp, sw = self.transmit_long(select + id)
        logger.debug('Selecting applet, response: %s, code: %04X' % (resp, sw))
        return resp, sw

    def send_add_share(self, data):
        res, sw = self.transmit_long([0xb6, 0x31, 0x0, 0x0, len(data)] + data)
        return res, sw

    def send_get_logs(self):
        res, sw = self.transmit_long([0xb6, 0xe7, 0x0, 0x0, 0x0])
        return res, sw

    def send_continuation(self, code):
        res, sw = self.transmit([0x00, 0xc0, 0x00, 0x00, code])
        return res, sw

    def send_get_shares(self):
        res, sw = self.transmit_long([0xb6, 0x35, 0x0, 0x0, 0x0])
        return res, sw

    def send_erase_shares(self):
        res, sw = self.transmit_long([0xb6, 0x33, 0x0, 0x0, 0x0])
        return res, sw

    def send_get_pubkey(self):
        res, sw = self.transmit_long([0xb6, 0xe1, 0x0, 0x0, 0x0])
        return res, sw

    def send_get_seed_pubkey(self):
        res, sw = self.transmit_long([0xb6, 0xd3, 0x0, 0x0, 0x0])
        return res, sw

    def transmit_long(self, data, **kwargs):
        """
        Transmits data with option of long buffer reading - multiple reads
        :param data:
        :return:
        """
        resp, sw = self.transmit(data)
        cont_bytes = get_continue_bytes(sw)

        # Dump continued data
        while cont_bytes is not None:
            res2, sw2 = self.send_continuation(cont_bytes)
            resp += res2 if res2 is not None else []
            sw = sw2

            if len(res2) != cont_bytes:
                logger.error('Continuation protocol invalid, cont_bytes: %x, got: %x, sw: %x'
                             % (cont_bytes, len(res2), sw2))
                raise errors.InvalidResponse('Data continuation protocol invalid')

            cont_bytes = get_continue_bytes(sw2)

        return resp, sw

    def transmit(self, data):
        logger.debug('Data: %s' % format_data(data))
        resp, sw1, sw2 = self.connection.transmit(data)
        sw = (sw1 << 8) | sw2
        return resp, sw

    @staticmethod
    def build_data_add_share(key_share_arr, share_idx, key_type, txt_desc_hex):
        # 0xa9 | <key length - 2B> | <share index - 1 B> | <key type - 1 B> |<share value> |
        # 0xad | <message length - 2B> | <text message - max 16B>
        data_buff = 'a9%04x%02x%02x' % ((len(key_share_arr) + 2) & 0xffff, (share_idx) & 0xff, key_type.id)
        data_buff += toHexString(key_share_arr, PACK)
        data_buff += 'ad%04x' % len(txt_desc_hex)
        data_buff += ''.join(['%02x' % x for x in txt_desc_hex])
        data_arr = toBytes(data_buff)
        return data_arr

