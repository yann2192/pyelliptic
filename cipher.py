#!/usr/bin/env python
# -*- coding: utf-8 -*-

#  Copyright (C) 2011 Yann GUIBET <yannguibet@gmail.com>
#  See LICENSE for details.

from pyelliptic.openssl import openssl


class cipher:
    def __init__(self, key, iv, do, ciphername='aes-256-cbc'): # do == 1 => Encrypt; do == 0 => Decrypt
        self.cipher = openssl.get_cipher(ciphername)
        self.ctx = openssl.EVP_CIPHER_CTX_new()
        self.ciphertext = b""
        self.size = 0
        if do == 1 or do == 0:
            k = openssl.malloc(key, len(key))
            IV = openssl.malloc(iv, len(iv))
            openssl.EVP_CipherInit_ex(self.ctx, self.cipher.get_pointer(), 0, k, IV, do)
        else:
            raise Exception("RTFM ...")

    @staticmethod
    def get_all_cipher():
        return openssl.cipher_algo.keys()

    def update(self, input):
        i = openssl.c_int(0)
        buffer = openssl.malloc(b"", len(input)+self.cipher.get_blocksize())
        inp = openssl.malloc(input,len(input))
        if openssl.EVP_CipherUpdate(self.ctx, openssl.byref(buffer), openssl.byref(i), inp, len(input)) == 0:
            raise Exception("[OpenSSL] EVP_CipherUpdate FAIL ...")
        self.size += i.value
        self.ciphertext += buffer.raw[0:i.value]

    def final(self):
        i = openssl.c_int(0)
        buffer = openssl.malloc(self.ciphertext, len(self.ciphertext)+self.cipher.get_blocksize())
        if (openssl.EVP_CipherFinal_ex(self.ctx, openssl.byref(buffer,self.size), openssl.byref(i))) == 0:
            raise Exception("[OpenSSL] EVP_CipherFinal_ex FAIL ...")
        self.size += i.value
        return buffer.raw[0:self.size]

    def ciphering(self, input):
        self.update(input)
        return self.final()

    def __del__(self):
        openssl.EVP_CIPHER_CTX_cleanup(self.ctx)
        openssl.EVP_CIPHER_CTX_free(self.ctx)
