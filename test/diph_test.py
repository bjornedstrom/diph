# -*- coding: utf-8 -*-
# Copyright (c) 2010-2012 Björn Edström <be@bjrn.se>

import StringIO
import unittest

import diph.diph as diph

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

        self.A_merge_conflict = """?k AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAeoneUUjCImyyNqdxLNf6q9BWEd+VRkXtJqiWfgqNIWQ==
?c 0 tMnG8X9HcdWcSQ==
<<<<<<<
?c 3000 Kys7oi0mb49hhp0yW9/85WLVkbM=
=======
?c 3000 Kysroicsb4hix5w0UNPt6SvPntyD7VZhpxQgGRxCf8VzCA==
>>>>>>>
?c 2000 TCIIJ1YE9cXX81bze36y22uMiiGFMhFvuA==
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
