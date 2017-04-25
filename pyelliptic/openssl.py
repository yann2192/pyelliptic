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

import sys
import ctypes
import ctypes.util

OpenSSL = None


class CipherName:
    def __init__(self, name, pointer, blocksize):
        self._name = name
        self._pointer = pointer
        self._blocksize = blocksize

    def __str__(self):
        return ("Cipher : %s | Blocksize : %s | Fonction pointer : %s" %
                (self._name, str(self._blocksize), str(self._pointer)))

    def get_pointer(self):
        return self._pointer()

    def get_name(self):
        return self._name

    def get_blocksize(self):
        return self._blocksize


class _OpenSSL:
    """
    Wrapper for OpenSSL using ctypes
    """
    def __init__(self, library):
        """
        Build the wrapper
        """
        self._lib = ctypes.CDLL(library)

        self.pointer = ctypes.pointer
        self.c_int = ctypes.c_int
        self.byref = ctypes.byref
        self.create_string_buffer = ctypes.create_string_buffer

        self.ERR_error_string = self._lib.ERR_error_string
        self.ERR_error_string.restype = ctypes.c_char_p
        self.ERR_error_string.argtypes = [ctypes.c_ulong, ctypes.c_char_p]

        self.ERR_get_error = self._lib.ERR_get_error
        self.ERR_get_error.restype = ctypes.c_ulong
        self.ERR_get_error.argtypes = []

        self.EVP_CipherInit_ex = self._lib.EVP_CipherInit_ex
        self.EVP_CipherInit_ex.restype = ctypes.c_int
        self.EVP_CipherInit_ex.argtypes = [ctypes.c_void_p,
                                           ctypes.c_void_p, ctypes.c_void_p]

        self.EVP_CIPHER_CTX_new = self._lib.EVP_CIPHER_CTX_new
        self.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
        self.EVP_CIPHER_CTX_new.argtypes = []

        # Cipher
        self.EVP_aes_128_cfb128 = self._lib.EVP_aes_128_cfb128
        self.EVP_aes_128_cfb128.restype = ctypes.c_void_p
        self.EVP_aes_128_cfb128.argtypes = []

        self.EVP_aes_256_cfb128 = self._lib.EVP_aes_256_cfb128
        self.EVP_aes_256_cfb128.restype = ctypes.c_void_p
        self.EVP_aes_256_cfb128.argtypes = []

        self.EVP_aes_128_cbc = self._lib.EVP_aes_128_cbc
        self.EVP_aes_128_cbc.restype = ctypes.c_void_p
        self.EVP_aes_128_cbc.argtypes = []

        self.EVP_aes_256_cbc = self._lib.EVP_aes_256_cbc
        self.EVP_aes_256_cbc.restype = ctypes.c_void_p
        self.EVP_aes_256_cbc.argtypes = []

        try:
            self.EVP_aes_128_ctr = self._lib.EVP_aes_128_ctr
        except AttributeError:
            pass
        else:
            self.EVP_aes_128_ctr.restype = ctypes.c_void_p
            self.EVP_aes_128_ctr.argtypes = []

        try:
            self.EVP_aes_256_ctr = self._lib.EVP_aes_256_ctr
        except AttributeError:
            pass
        else:
            self.EVP_aes_256_ctr.restype = ctypes.c_void_p
            self.EVP_aes_256_ctr.argtypes = []

        self.EVP_aes_128_ofb = self._lib.EVP_aes_128_ofb
        self.EVP_aes_128_ofb.restype = ctypes.c_void_p
        self.EVP_aes_128_ofb.argtypes = []

        self.EVP_aes_256_ofb = self._lib.EVP_aes_256_ofb
        self.EVP_aes_256_ofb.restype = ctypes.c_void_p
        self.EVP_aes_256_ofb.argtypes = []

        self.EVP_bf_cbc = self._lib.EVP_bf_cbc
        self.EVP_bf_cbc.restype = ctypes.c_void_p
        self.EVP_bf_cbc.argtypes = []

        self.EVP_bf_cfb64 = self._lib.EVP_bf_cfb64
        self.EVP_bf_cfb64.restype = ctypes.c_void_p
        self.EVP_bf_cfb64.argtypes = []

        self.EVP_rc4 = self._lib.EVP_rc4
        self.EVP_rc4.restype = ctypes.c_void_p
        self.EVP_rc4.argtypes = []

        self.EVP_CIPHER_CTX_reset = self._lib.EVP_CIPHER_CTX_reset
        self.EVP_CIPHER_CTX_reset.restype = ctypes.c_int
        self.EVP_CIPHER_CTX_reset.argtypes = [ctypes.c_void_p]

        self.EVP_CIPHER_CTX_free = self._lib.EVP_CIPHER_CTX_free
        self.EVP_CIPHER_CTX_free.restype = None
        self.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]

        self.EVP_CipherUpdate = self._lib.EVP_CipherUpdate
        self.EVP_CipherUpdate.restype = ctypes.c_int
        self.EVP_CipherUpdate.argtypes = [ctypes.c_void_p,
                                          ctypes.c_void_p,
                                          ctypes.c_void_p,
                                          ctypes.c_void_p,
                                          ctypes.c_int]

        self.EVP_CipherFinal_ex = self._lib.EVP_CipherFinal_ex
        self.EVP_CipherFinal_ex.restype = ctypes.c_int
        self.EVP_CipherFinal_ex.argtypes = 3 * [ctypes.c_void_p]

        self.EVP_DigestInit = self._lib.EVP_DigestInit
        self.EVP_DigestInit.restype = ctypes.c_int
        self._lib.EVP_DigestInit.argtypes = 2 * [ctypes.c_void_p]

        self.EVP_DigestInit_ex = self._lib.EVP_DigestInit_ex
        self.EVP_DigestInit_ex.restype = ctypes.c_int
        self._lib.EVP_DigestInit_ex.argtypes = 3 * [ctypes.c_void_p]

        self.EVP_DigestUpdate = self._lib.EVP_DigestUpdate
        self.EVP_DigestUpdate.restype = ctypes.c_int
        self.EVP_DigestUpdate.argtypes = [ctypes.c_void_p,
                                          ctypes.c_void_p,
                                          ctypes.c_int]

        self.EVP_DigestFinal = self._lib.EVP_DigestFinal
        self.EVP_DigestFinal.restype = ctypes.c_int
        self.EVP_DigestFinal.argtypes = [ctypes.c_void_p,
                                         ctypes.c_void_p, ctypes.c_void_p]

        self.EVP_DigestFinal_ex = self._lib.EVP_DigestFinal_ex
        self.EVP_DigestFinal_ex.restype = ctypes.c_int
        self.EVP_DigestFinal_ex.argtypes = [ctypes.c_void_p,
                                            ctypes.c_void_p, ctypes.c_void_p]

        self.RAND_bytes = self._lib.RAND_bytes
        self.RAND_bytes.restype = ctypes.c_int
        self.RAND_bytes.argtypes = [ctypes.c_void_p, ctypes.c_int]

        self.EVP_sha256 = self._lib.EVP_sha256
        self.EVP_sha256.restype = ctypes.c_void_p
        self.EVP_sha256.argtypes = []

        self.EVP_sha512 = self._lib.EVP_sha512
        self.EVP_sha512.restype = ctypes.c_void_p
        self.EVP_sha512.argtypes = []

        self.HMAC = self._lib.HMAC
        self.HMAC.restype = ctypes.c_void_p
        self.HMAC.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int,
                              ctypes.c_void_p, ctypes.c_int,
                              ctypes.c_void_p, ctypes.c_void_p]

        try:
            self.PKCS5_PBKDF2_HMAC = self._lib.PKCS5_PBKDF2_HMAC
        except:
            # The above is not compatible with all versions of OSX.
            self.PKCS5_PBKDF2_HMAC = self._lib.PKCS5_PBKDF2_HMAC_SHA1
        self.PKCS5_PBKDF2_HMAC.restype = ctypes.c_int
        self.PKCS5_PBKDF2_HMAC.argtypes = [ctypes.c_void_p, ctypes.c_int,
                                           ctypes.c_void_p, ctypes.c_int,
                                           ctypes.c_int, ctypes.c_void_p,
                                           ctypes.c_int, ctypes.c_void_p]

        self._set_ciphers()

    def _set_ciphers(self):
        self.cipher_algo = {
            'aes-128-cbc': CipherName('aes-128-cbc',
                                      self.EVP_aes_128_cbc,
                                      16),
            'aes-256-cbc': CipherName('aes-256-cbc',
                                      self.EVP_aes_256_cbc,
                                      16),
            'aes-128-cfb': CipherName('aes-128-cfb',
                                      self.EVP_aes_128_cfb128,
                                      16),
            'aes-256-cfb': CipherName('aes-256-cfb',
                                      self.EVP_aes_256_cfb128,
                                      16),
            'aes-128-ofb': CipherName('aes-128-ofb',
                                      self._lib.EVP_aes_128_ofb,
                                      16),
            'aes-256-ofb': CipherName('aes-256-ofb',
                                      self._lib.EVP_aes_256_ofb,
                                      16),
            # 'aes-128-ctr': CipherName('aes-128-ctr',
            #                           self._lib.EVP_aes_128_ctr,
            #                           16),
            # 'aes-256-ctr': CipherName('aes-256-ctr',
            #                           self._lib.EVP_aes_256_ctr,
            #                           16),
            'bf-cfb': CipherName('bf-cfb',
                                 self.EVP_bf_cfb64,
                                 8),
            'bf-cbc': CipherName('bf-cbc',
                                 self.EVP_bf_cbc,
                                 8),
            'rc4': CipherName('rc4',
                              self.EVP_rc4,
                              # 128 is the initialisation size not block size
                              128),
        }

        if hasattr(self, 'EVP_aes_128_ctr'):
            self.cipher_algo['aes-128-ctr'] = CipherName(
                'aes-128-ctr',
                self._lib.EVP_aes_128_ctr,
                16
            )
        if hasattr(self, 'EVP_aes_256_ctr'):
            self.cipher_algo['aes-256-ctr'] = CipherName(
                'aes-256-ctr',
                self._lib.EVP_aes_256_ctr,
                16
            )

    def get_cipher(self, name):
        """
        returns the OpenSSL cipher instance
        """
        if name not in self.cipher_algo:
            raise Exception("Unknown cipher")
        return self.cipher_algo[name]

    def rand(self, size):
        """
        OpenSSL random function
        """
        buffer = self.malloc(0, size)
        if self.RAND_bytes(buffer, size) != 1:
            raise RuntimeError("OpenSSL RAND_bytes failed")
        return buffer.raw

    def malloc(self, data, size):
        """
        returns a create_string_buffer (ctypes)
        """
        buffer = None
        if data != 0:
            if sys.version_info.major == 3 and isinstance(data, type('')):
                data = data.encode()
            buffer = self.create_string_buffer(data, size)
        else:
            buffer = self.create_string_buffer(size)
        return buffer

    def get_error(self):
        return OpenSSL.ERR_error_string(OpenSSL.ERR_get_error(), None)


libname = ctypes.util.find_library('crypto')
if libname is None:
    # For Windows ...
    libname = ctypes.util.find_library('libeay32.dll')
if libname is None:
    raise Exception("Couldn't load OpenSSL lib ...")
OpenSSL = _OpenSSL(libname)
