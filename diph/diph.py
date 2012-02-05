# -*- coding: utf-8 -*-
#
# Copyright (c) 2010-2012 Björn Edström <be@bjrn.se>
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import base64
import difflib
import hashlib
import hmac
import struct
import sys

import Crypto.Cipher.AES as AES


PBKDF2_ROUNDS = 2000
CTR_STEP = 1000
AES_KEY_SIZE = 16
CTR_BLOCK_SIZE = 16


def urandom(n):
    return file('/dev/urandom').read(n)


def xor_string(a, b):
    a, b = iter(a), iter(b)
    c = []
    while True:
        try:
            c.append(chr(ord(a.next()) ^ ord(b.next())))
        except StopIteration:
            break
    return ''.join(c)


def hmac_sha1(key, message):
    return hmac.HMAC(key, message, hashlib.sha1).digest()


def pbkdf2(hmacfunc, password, salt, iterations, derivedlen):
    """Reference implementation of PKBDF2 from PKCS5."""

    def func(P, S, c, i):
        U_prev = hmacfunc(P, S + struct.pack('>L', i))
        res = U_prev
        for cc in xrange(2, c + 1):
            U_c = hmacfunc(P, U_prev)
            res = xor_string(res, U_c)
            U_prev = U_c
        return res
    tmp = ''
    i = 1
    while True:
        tmp += func(password, salt, iterations, i)
        if len(tmp) > derivedlen:
            break
        i += 1
    return tmp[0:derivedlen]


def decrypt_blob(password, bytes):
    nonce, salt, bytes = bytes[:CTR_BLOCK_SIZE], \
        bytes[CTR_BLOCK_SIZE:CTR_BLOCK_SIZE+AES_KEY_SIZE], \
        bytes[CTR_BLOCK_SIZE+AES_KEY_SIZE:]
    key = pbkdf2(hmac_sha1, password, salt, PBKDF2_ROUNDS, AES_KEY_SIZE)
    aes = AES.new(key)
    return crypt_ctr(aes, nonce, 1, bytes)


def encrypt_blob(password, bytes):
    nonce = urandom(CTR_BLOCK_SIZE)
    salt = urandom(AES_KEY_SIZE)
    key = pbkdf2(hmac_sha1, password, salt, PBKDF2_ROUNDS, AES_KEY_SIZE)
    aes = AES.new(key)
    return nonce + salt + crypt_ctr(aes, nonce, 1, bytes)


# http://www.ietf.org/rfc/rfc3686.txt
def crypt_ctr(aes, nonce, cnt, buf):
    # TODO: This implementation is pretty slow.
    L = len(buf)
    assert L < AES_KEY_SIZE * CTR_STEP, 'line too long'
    stream = []
    i = 0
    while i < L:
        ctr_block = ('\x00' * (CTR_BLOCK_SIZE - 8)) + struct.pack('!Q', cnt)
        assert len(ctr_block) == CTR_BLOCK_SIZE

        stream.append(aes.encrypt(xor_string(nonce, ctr_block)))
        cnt += 1
        i += CTR_BLOCK_SIZE

    stream = ''.join(stream)
    return xor_string(buf, stream)


def transform(from_seq, to_seq, pre_func, post_func):
    """Transform map(pre_func, from_seq) to to_seq, keeping the
       structure of from_seq by applying post_func to modifications.

       transform([(0, 'a'), (1, 'b'), (2, 'c')],
                 'acd',
                 lambda T: T[1],
                 lambda s: (None, s)) -> [(0, 'a'), (2, 'c'), (None, 'd')]
    """

    result = from_seq[:]
    while True:
        a = map(pre_func, result)
        b = to_seq
        sm = difflib.SequenceMatcher(None, a, b)
        mod = False
        for op, i1, i2, j1, j2 in sm.get_opcodes():
            if op == 'equal':
                pass
            elif op == 'replace':
                result[i1:i2] = map(post_func, b[j1:j2])
                mod = True
            elif op == 'delete':
                del result[i1:i2]
                mod = True
            elif op == 'insert':
                result[i1:i1] = map(post_func, b[j1:j2])
                mod = True
            if mod:
                break
        if not mod:
            break
    return result


# TODO (bjorn): Document this better.
def encrypt(password, cur, old, decrypt=False, out=sys.stdout):
    """The main encryption routine in diph.

       cur is a buffer for the whole content of the plain text of the
       current version of the file. cur is unused when decrypting, and
       may then be None.

       old is a buffer for the the old cipher text. This may be the
       empty string of no old cipher text exists or you wish to
       re-encrypt the file.
    """

    key = urandom(AES_KEY_SIZE)
    nonce = urandom(CTR_BLOCK_SIZE)
    aes = AES.new(key)
    ctr_data = []
    k_blob = None

    # Attempt to decrypt the old file, if it exists.
    max_cnt = -CTR_STEP
    old_ctr_data = [] # [(counter, buf)]
    if old is not None:
        for line_ in old.split('\n'):
            if not line_:
                continue
            if not line_.startswith('?'):
                print >> out, line_
                continue
            fields = line_.split(' ')

            if fields[0] == '??':
                # Current file format version
                assert fields[1] == 'diph1'

            elif fields[0] == '?k':
                k_blob = line_.strip()
                blob = decrypt_blob(password, base64.b64decode(fields[1]))
                key, nonce = blob[:AES_KEY_SIZE], blob[AES_KEY_SIZE:]
                aes = AES.new(key)

            elif fields[0] == '?c':
                cnt = int(fields[1])
                plain = crypt_ctr(aes, nonce, cnt, base64.b64decode(fields[2]))
                max_cnt = max(max_cnt, cnt)
                old_ctr_data.append((cnt, plain))

                if decrypt:
                    print >> out, plain,

            elif fields[0] == '?m':
                cnt = int(fields[1])
                max_cnt = max(max_cnt, cnt)

    # If this was decrypt-only, we are done.
    if decrypt:
        return

    plain_data = []
    for line in cur.split('\n'):
        if line:
            # Pragmas
            if line.startswith('#diph'):
                fields = line.split()
                if fields[1] == 'ctr':
                    max_cnt = int(fields[2])
            else:
                plain_data.append(line + '\n')

    # This is the clever part.
    ctr_data = transform(old_ctr_data, plain_data, lambda c: c[1], lambda c: (None, c))

    # Give a counter to the changed lines.
    # XXX (bjorn): It is easy to reuse counters here.
    cnt = max_cnt + CTR_STEP
    for i in xrange(len(ctr_data)):
        if ctr_data[i][0] is None:
            ctr_data[i] = (cnt, ctr_data[i][1])
            cnt += CTR_STEP

    cnt_mod = cnt

    # Output
    print >> out, '?? diph1'

    if k_blob:
        print >> out, k_blob
    else:
        print >> out, '?k', base64.b64encode(encrypt_blob(password, key + nonce))

    for cnt, plain in ctr_data:
        print >> out, '?c', cnt, base64.b64encode(crypt_ctr(aes, nonce, cnt, plain))

    print >> out, '?m', cnt_mod


def decrypt(password, buf, out=sys.stdout):
    """Decrypt a file.
    """
    return encrypt(password, None, buf, decrypt=True, out=out)


def encrypt_first(password, buf, out=sys.stdout):
    """Encrypt a file that has not been encrypted before.
    """
    return encrypt(password, buf, '', out=out)
