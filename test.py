#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2014 Yann GUIBET <yannguibet@gmail.com>
# This program is free software; you can redistribute it
# and/or modify it under the terms of version 3 of the
# GNU General Public License as published by the Free
# Software Foundation
#
# In addition, as a special exception, the author of this
# program gives permission to link the code of its
# release with the OpenSSL project's "OpenSSL" library (or
# with modified versions of it that use the same license as
# the "OpenSSL" library), and distribute the linked
# executables. You must obey the GNU General Public
# License in all respects for all of the code used other
# than "OpenSSL".  If you modify this file, you may extend
# this exception to your version of the file, but you are
# not obligated to do so.  If you do not wish to do so,
# delete this exception statement from your version.
#
# This program is distributed in the hope that it will be
# useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
# PURPOSE.  See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public
# License along with this package; if not, write to the Free
# Software Foundation, Inc., 51 Franklin St, Fifth Floor,
# Boston, MA  02110-1301 USA

from pyelliptic import Cipher, ECC
from binascii import hexlify, unhexlify

print("TEST: AES-256-CTR")
ciphername = "aes-256-ctr"

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
assert ctx.ciphering(enc) == plaintext


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
assert ctx.ciphering(enc) == plaintext


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
assert ctx.ciphering(enc) == plaintext


print("\nTEST: ECIES")
alice = ECC()
plaintext = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ciphertext = ECC.encrypt(plaintext, alice.get_pubkey())
print(hexlify(ciphertext))
assert alice.decrypt(ciphertext) == plaintext


print("\nTEST: ECIES/RC4")
alice = ECC()
plaintext = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ciphertext = ECC.encrypt(plaintext, alice.get_pubkey(), ciphername="rc4")
print(hexlify(ciphertext))
assert alice.decrypt(ciphertext, ciphername="rc4") == plaintext
