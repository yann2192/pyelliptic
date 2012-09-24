#!/usr/bin/env python
# -*- coding: utf-8 -*-

#  Copyright (C) 2011 Yann GUIBET <yannguibet@gmail.com>
#  See LICENSE for details.

from pyelliptic.openssl import OpenSSL


def HMAC(k, m):
    """
    Compute the key and the message with HMAC SHA512
    """
    key = OpenSSL.malloc(k, len(k))
    d = OpenSSL.malloc(m, len(m))
    md = OpenSSL.malloc(0, 64)
    i = OpenSSL.pointer(OpenSSL.c_int(0))
    OpenSSL.HMAC(OpenSSL.EVP_sha512(), key, len(k), d, len(m), md, i)
    return md.raw
