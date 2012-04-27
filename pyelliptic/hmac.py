#!/usr/bin/env python
# -*- coding: utf-8 -*-

#  Copyright (C) 2011 Yann GUIBET <yannguibet@gmail.com>
#  See LICENSE for details.

from pyelliptic.openssl import openssl


def hmac(k, m):
    """
    Compute the key and the message with HMAC SHA512
    """
    key = openssl.malloc(k, len(k))
    d = openssl.malloc(m, len(m))
    md = openssl.malloc(0, 64)
    i = openssl.pointer(openssl.c_int(0))
    openssl.HMAC(openssl.EVP_sha512(), key, len(k), d, len(m), md, i)
    return md.raw
