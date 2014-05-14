#!/usr/bin/env python
# -*- coding: utf-8 -*-

#  Copyright (C) 2011 Yann GUIBET <yannguibet@gmail.com>
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

from pyelliptic.openssl import OpenSSL


def hmac_sha256(k, m):
    """
    Compute the key and the message with HMAC SHA5256
    """
    key = OpenSSL.malloc(k, len(k))
    d = OpenSSL.malloc(m, len(m))
    md = OpenSSL.malloc(0, 32)
    i = OpenSSL.pointer(OpenSSL.c_int(0))
    OpenSSL.HMAC(OpenSSL.EVP_sha256(), key, len(k), d, len(m), md, i)
    return md.raw


def hmac_sha512(k, m):
    """
    Compute the key and the message with HMAC SHA512
    """
    key = OpenSSL.malloc(k, len(k))
    d = OpenSSL.malloc(m, len(m))
    md = OpenSSL.malloc(0, 64)
    i = OpenSSL.pointer(OpenSSL.c_int(0))
    OpenSSL.HMAC(OpenSSL.EVP_sha512(), key, len(k), d, len(m), md, i)
    return md.raw


def pbkdf2(password, salt=None, i=10000, keylen=64):
    if salt is None:
        salt = OpenSSL.rand(8)
    p_password = OpenSSL.malloc(password, len(password))
    p_salt = OpenSSL.malloc(salt, len(salt))
    output = OpenSSL.malloc(0, keylen)
    OpenSSL.PKCS5_PBKDF2_HMAC(p_password, len(password), p_salt,
                              len(p_salt), i, OpenSSL.EVP_sha256(),
                              keylen, output)
    return salt, output.raw
