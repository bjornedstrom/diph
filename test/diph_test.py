# -*- coding: utf-8 -*-
# Copyright (c) 2010-2012 Björn Edström <be@bjrn.se>

import StringIO
import unittest

import diph.diph as diph

def HH(b):
    return b.replace(' ', '').strip().decode('hex')

class CryptoTest(unittest.TestCase):
    def test_pbkdf2(self):
        # http://tools.ietf.org/html/draft-josefsson-pbkdf2-test-vectors-06
        ret =  diph.pbkdf2(diph.hmac_sha1, 'password', 'salt', 1, 20)
        self.assertEquals("0c60c80f961f0e71f3a9b524af6012062fe037a6", ret.encode('hex'))
        ret =  diph.pbkdf2(diph.hmac_sha1,
                           'passwordPASSWORDpassword',
                           'saltSALTsaltSALTsaltSALTsaltSALTsalt',
                           4096, 25)
        self.assertEquals('''3d 2e ec 4f e4 1c 84 9b 80 c8 d8 36 62 c0 e4 4a 8b 29 1a 96 4c f2 f0 70 38'''.replace(' ', '').strip(), ret.encode('hex'))

    def test_aes_ctr_16(self):
        # http://www.ietf.org/rfc/rfc3686.txt

        # Test Vector #2
        aes = diph.AES.new(HH('7E 24 06 78 17 FA E0 D7 43 D6 CE 1F 32 53 91 63'))
        nonce = HH('00 6C B6 DB C0 54 3B 59 DA 48 D9 0B 00 00 00 00')

        ret = diph.crypt_ctr(aes, nonce, 1, HH('00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F'))

        self.assertEquals(HH('51 04 A1 06 16 8A 72 D9 79 0D 41 EE 8E DA D3 88 EB 2E 1E FC 46 DA 57 C8 FC E6 30 DF 91 41 BE 28'), ret)

    def test_aes_ctr_32_7(self):
        # http://www.ietf.org/rfc/rfc3686.txt

        # Test Vector #7
        diph.AES_KEY_SIZE = 32
        try:
            aes = diph.AES.new(HH('77 6B EF F2 85 1D B0 6F 4C 8A 05 42 C8 69 6F 6C 6A 81 AF 1E EC 96 B4 D3 7F C1 D6 89 E6 C1 C1 04'))
            nonce = HH('00 00 00 60 DB 56 72 C9 7A A8 F0 B2 00 00 00 00')

            ret = diph.crypt_ctr(aes, nonce, 1, 'Single block msg')

            self.assertEquals(HH('14 5A D0 1D BF 82 4E C7 56 08 63 DC 71 E3 E0 C0'), ret)

        finally:
            diph.AES_KEY_SIZE = 16

    def test_aes_ctr_32_8(self):
        # http://www.ietf.org/rfc/rfc3686.txt

        # Test Vector #8
        diph.AES_KEY_SIZE = 32
        try:
            aes = diph.AES.new(HH('F6 D6 6D 6B D5 2D 59 BB 07 96 36 58 79 EF F8 86 C6 6D D5 1A 5B 6A 99 74 4B 50 59 0C 87 A2 38 84'))
            nonce = HH('00 FA AC 24 C1 58 5E F1 5A 43 D8 75 00 00 00 00')

            ret = diph.crypt_ctr(aes, nonce, 1, HH('00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F'))

            self.assertEquals(HH('F0 5E 23 1B 38 94 61 2C 49 EE 00 0B 80 4E B2 A9 B8 30 6B 50 8F 83 9D 6A 55 30 83 1D 93 44 AF 1C'), ret)

        finally:
            diph.AES_KEY_SIZE = 16

class DiphTest(unittest.TestCase):
    def setUp(self):
        diph.urandom = lambda n: '\x00' * n

        self.A = """TODO list
* TODO do something
* TODO do something else
"""
        self.A_append = """TODO list
* TODO do something
* TODO do something else
* TODO fix the thing
"""

        self.A_change = """TODO list
* DONE do something
* TODO do something else
"""

        self.A_change2 = """TODO list
* TODO clarified the do something
* TODO do something else
"""

        self.A_merge_conflict = """?? diph1
?k AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAeoneUUjCImyyNqdxLNf6q9BWEd+VRkXtJqiWfgqNIWQ==
?c 0 MqYPm8/mRUj8Rg==
<<<<<<<
?c 3000 gsfiPpVjik15vUvVueYvmvfcU5o=
=======
?c 3000 gsfyPp9pikp6/ErTsuo+lr7GXPUiBN9gd/0+BVWUH/mw9A==
>>>>>>>
?c 2000 PRCsa/6S57O0rn2tLM49kO/Wq0lQ8SgehA==
"""

    def test_urandom(self):
        self.assertEquals('\x00'*16, diph.urandom(16))

    def test_decrypt(self):
        out = StringIO.StringIO()
        diph.encrypt_first('foo', self.A, out=out)
        cipher_text = out.getvalue()

        out = StringIO.StringIO()
        diph.decrypt('foo', cipher_text, out=out)
        plain_text = out.getvalue()

        self.assertEquals(self.A, plain_text)

    def test_change(self):
        out = StringIO.StringIO()
        diph.encrypt_first('foo', self.A, out=out)
        cipher_text_1 = out.getvalue()

        out = StringIO.StringIO()
        diph.encrypt('foo', self.A_change, cipher_text_1, out=out)
        cipher_text_2 = out.getvalue()

        self.assertTrue(cipher_text_1 != cipher_text_2)

    def test_conflict_print(self):
        out = StringIO.StringIO()
        diph.encrypt_first('foo', self.A, out=out)
        cipher_text_1 = out.getvalue()

        out = StringIO.StringIO()
        diph.encrypt('foo', self.A_change, cipher_text_1, out=out)
        cipher_text_2a = out.getvalue()

        out = StringIO.StringIO()
        diph.encrypt('foo', self.A_change2, cipher_text_1, out=out)
        cipher_text_2b = out.getvalue()

        print cipher_text_2a
        print cipher_text_2b

    def test_merge_conflict_out(self):
        out = StringIO.StringIO()
        diph.decrypt('foo', self.A_merge_conflict, out=out)
        plain_text = out.getvalue()

        self.assertEquals("""TODO list
<<<<<<<
* DONE do something
=======
* TODO clarified the do something
>>>>>>>
* TODO do something else
""", plain_text)

if __name__ == '__main__':
    unittest.main()
