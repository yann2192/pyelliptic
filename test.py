#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pyelliptic import Cipher

ciphername = "aes-256-ctr"
iv = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff".decode('hex')
key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4".decode('hex')
plaintext = "6bc1bee22e409f96e93d7e117393172a".decode('hex')

ctx = Cipher(key, iv, 1, ciphername=ciphername)
enc = ctx.ciphering(plaintext)
print enc.encode('hex')

ctx = Cipher(key, iv, 0, ciphername=ciphername)
print ctx.ciphering(enc) == plaintext


ciphername = "aes-256-cfb"
key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4".decode('hex')
iv = "000102030405060708090A0B0C0D0E0F".decode('hex')
plaintext = "6bc1bee22e409f96e93d7e117393172a".decode('hex')

ctx = Cipher(key, iv, 1, ciphername=ciphername)
enc = ctx.ciphering(plaintext)
print enc.encode('hex')

ctx = Cipher(key, iv, 0, ciphername=ciphername)
print ctx.ciphering(enc) == plaintext


ciphername = "aes-256-cbc"
iv = "000102030405060708090A0B0C0D0E0F".decode('hex')
key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4".decode('hex')
plaintext = "6bc1bee22e409f96e93d7e117393172a".decode('hex')

ctx = Cipher(key, iv, 1, ciphername=ciphername)
enc = ctx.ciphering(plaintext)
print enc.encode('hex')

ctx = Cipher(key, iv, 0, ciphername=ciphername)
print ctx.ciphering(enc) == plaintext
