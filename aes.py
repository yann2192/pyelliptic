#!/usr/bin/env python
# -*- coding: utf-8 -*-

#  Copyright (C) 2011 Yann GUIBET <yannguibet@gmail.com>
#  See LICENSE for details.

from pyelliptic.openssl import openssl


class aes:
    def __init__(self, key, iv, do, mode='cfb'): # do == 1 => Encrypt; do == 0 => Decrypt
        self.ctx = openssl.EVP_CIPHER_CTX_new()
        self.ciphertext = b""
        self.size = 0
        if do == 1 or do == 0:
            k = openssl.malloc(key, len(key))
            IV = openssl.malloc(iv, len(iv))
            if mode == 'cbc':
                openssl.EVP_CipherInit_ex(self.ctx, openssl.EVP_aes_256_cbc(), 0, k, IV, do)
            elif mode == 'cfb':
                openssl.EVP_CipherInit_ex(self.ctx, openssl.EVP_aes_256_cfb128(), 0, k, IV, do)
            else:
                raise Exception("Unknown mode")
        else:
            raise Exception("RTFM ...")

    def update(self, input):
        i = openssl.c_int(0)
        buffer = openssl.malloc(b"", len(input)+16)
        inp = openssl.malloc(input,len(input))
        if openssl.EVP_CipherUpdate(self.ctx, openssl.byref(buffer), openssl.byref(i), inp, len(input)) == 0:
            raise Exception("[OpenSSL] EVP_CipherUpdate FAIL ...")
        self.size += i.value
        self.ciphertext += buffer.raw[0:i.value]

    def final(self):
        i = openssl.c_int(0)
        buffer = openssl.malloc(self.ciphertext, len(self.ciphertext)+16)
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
