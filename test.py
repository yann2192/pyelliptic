#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2014 Yann GUIBET <yannguibet@gmail.com>.
# All rights reserved.
#
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     1. Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#     2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS IS''
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
# IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


import unittest
from binascii import hexlify, unhexlify

from pyelliptic import Cipher, ECC
from pyelliptic import hash as _hash


class TestCipher(unittest.TestCase):
    def setUp(self):
        pass

    def test_aes256ctr(self):
        ciphername = "aes-256-ctr"
        print("\nTEST: AES-256-CTR")

        iv_hex = b"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        iv = unhexlify(iv_hex)
        key_hex = b"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
        key = unhexlify(key_hex)
        plain_hex = b"6bc1bee22e409f96e93d7e117393172a"
        plaintext = unhexlify(plain_hex)

        ctx = Cipher(key, iv, 1, ciphername=ciphername)
        enc = ctx.ciphering(plaintext)
        print(hexlify(enc))

        ctx = Cipher(key, iv, 0, ciphername=ciphername)
        self.assertEqual(plaintext, ctx.ciphering(enc))


    def test_aes256cfb(self):
        print("\nTEST: AES-256-CFB")
        ciphername = "aes-256-cfb"
        key_hex = b"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
        key = unhexlify(key_hex)
        iv_hex = b"000102030405060708090A0B0C0D0E0F"
        iv = unhexlify(iv_hex)
        plain_hex = b"6bc1bee22e409f96e93d7e117393172a"
        plaintext = unhexlify(plain_hex)

        ctx = Cipher(key, iv, 1, ciphername=ciphername)
        enc = ctx.ciphering(plaintext)
        print(hexlify(enc))

        ctx = Cipher(key, iv, 0, ciphername=ciphername)
        self.assertEqual(plaintext, ctx.ciphering(enc))

    def test_aes256cbc(self):
        print("\nTEST: AES-256-CBC")
        ciphername = "aes-256-cbc"
        iv_hex = b"000102030405060708090A0B0C0D0E0F"
        iv = unhexlify(iv_hex)
        key_hex = b"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
        key = unhexlify(key_hex)
        plain_hex = b"6bc1bee22e409f96e93d7e117393172a"
        plaintext = unhexlify(plain_hex)

        ctx = Cipher(key, iv, 1, ciphername=ciphername)
        enc = ctx.ciphering(plaintext)
        print(hexlify(enc))

        ctx = Cipher(key, iv, 0, ciphername=ciphername)
        self.assertEqual(plaintext, ctx.ciphering(enc))


class TestICIES(unittest.TestCase):
    def setUp(self):
        pass

    def test_ecies(self):
        print("\nTEST: ECIES")
        alice = ECC()
        plaintext = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        ciphertext = ECC.encrypt(plaintext, alice.get_pubkey())
        print(hexlify(ciphertext))
        self.assertEqual(plaintext, alice.decrypt(ciphertext))

    def test_ecies_rc4(self):
        print("\nTEST: ECIES/RC4")
        alice = ECC()
        plaintext = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        ciphertext = ECC.encrypt(plaintext, alice.get_pubkey(),
                                 ciphername="rc4")
        print(hexlify(ciphertext))
        self.assertEqual(plaintext, alice.decrypt(ciphertext, ciphername="rc4"))


class TestECDSA(unittest.TestCase):
    def setUp(self):
        pass

    def test_ecdsa(self):
        print("\nTEST: ECDSA")
        alice = ECC()
        plaintext = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        sig = alice.sign(plaintext)
        print(hexlify(sig))
        res = ECC(pubkey_x=alice.pubkey_x,
                  pubkey_y=alice.pubkey_y).verify(sig, plaintext)
        self.assertTrue(res)

    def test_ecdsa2(self):
        print("\nTEST: ECDSA 2")
        alice = ECC()
        plaintext = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        sig = b''.join((b'\x00', alice.sign(plaintext)))
        print(hexlify(sig))
        res = ECC(pubkey_x=alice.pubkey_x,
                  pubkey_y=alice.pubkey_y).verify(sig, plaintext)
        self.assertFalse(res)


class TestEquals(unittest.TestCase):
    def setUp(self):
        pass

    def test_equals(self):
        print("\nTEST: hash.equals")
        a = '\xb5\x85/\xe80\xfa\x04\xdf\x07\x83\x17P\x9dw\x02\x89'

        b = '\xb5\x85/\xe80\xfa\x04\xdf\x07\x83\x17P\x9dw\x02\x89'
        self.assertTrue(_hash.equals(a, b))

        b = '\xb4\x85/\xe80\xfa\x04\xdf\x07\x83\x17P\x9dw\x02\x89'
        self.assertFalse(_hash.equals(a, b))

        b = '\xb5\x85/\xe80\xfa\x04\xdf\x07\x83\x17P\x9dw\x02\x90'
        self.assertFalse(_hash.equals(a, b))

        b = '\xb4\x85/\xe80\xfa\x04\xdf\x07\x83\x17P\x9dw\x02'
        self.assertFalse(_hash.equals(a, b))


if __name__ == "__main__":
    unittest.main()
