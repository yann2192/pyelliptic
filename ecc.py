#!/usr/bin/env python
# -*- coding: utf-8 -*-

#  Copyright (C) 2011 Yann GUIBET <yannguibet@gmail.com>
#  See LICENSE for details.

from pyelliptic.openssl import openssl
from pyelliptic.cipher import cipher
from struct import pack, unpack


class ecc:
    def __init__(self, pubkey_x = 0, pubkey_y = 0, privkey = 0):
        self.curve = 734 # == NID_sect571r1
        if pubkey_x != 0 and pubkey_y != 0:
            if self.Check_EC_Key(privkey, pubkey_x, pubkey_y) < 0:
                self.pubkey_x = 0
                self.pubkey_y = 0
                self.privkey = 0
                raise -1
            else:
                self.pubkey_x = pubkey_x
                self.pubkey_y = pubkey_y
                self.privkey = privkey
        else:
            self.privkey, self.pubkey_x, self.pubkey_y = self.Get_EC_PairKey()

    def Get_EC_PairKey(self):
        try:
            pub_key_x = openssl.BN_new()
            pub_key_y = openssl.BN_new()

            key = openssl.EC_KEY_new_by_curve_name(self.curve)
            if key == 0:
                raise Exception("[OpenSSL] EC_KEY_new_by_curve_name FAIL ...")
            if (openssl.EC_KEY_generate_key(key)) == 0:
                raise Exception("[OpenSSL] EC_KEY_generate_key FAIL ...")
            if (openssl.EC_KEY_check_key(key)) == 0:
                raise Exception("[OpenSSL] EC_KEY_check_key FAIL ...")
            priv_key = openssl.EC_KEY_get0_private_key(key)

            group = openssl.EC_KEY_get0_group(key)
            pub_key = openssl.EC_KEY_get0_public_key(key)

            if (openssl.EC_POINT_get_affine_coordinates_GFp(group, pub_key, pub_key_x, pub_key_y, 0)) == 0:
                raise Exception("[OpenSSL] EC_POINT_get_affine_coordinates_GFp FAIL ...")

            privkey = openssl.malloc(0, openssl.BN_num_bytes(priv_key))
            pubkeyx = openssl.malloc(0, openssl.BN_num_bytes(pub_key_x))
            pubkeyy = openssl.malloc(0, openssl.BN_num_bytes(pub_key_y))
            openssl.BN_bn2bin(priv_key,privkey)
            privkey = privkey.raw
            openssl.BN_bn2bin(pub_key_x,pubkeyx)
            pubkeyx = pubkeyx.raw
            openssl.BN_bn2bin(pub_key_y,pubkeyy)
            pubkeyy = pubkeyy.raw
            self.Check_EC_Key(privkey, pubkeyx, pubkeyy)

            return privkey, pubkeyx, pubkeyy

        finally:
            openssl.EC_KEY_free(key)
            openssl.BN_free(pub_key_x)
            openssl.BN_free(pub_key_y)

    def Get_EC_Key(self, pubkey_x, pubkey_y):
        try:
            ecdh_keybuffer = openssl.malloc(0, 32)

            other_key = openssl.EC_KEY_new_by_curve_name(self.curve)
            if other_key == 0:
                raise Exception("[OpenSSL] EC_KEY_new_by_curve_name FAIL ...")

            other_pub_key_x = openssl.BN_bin2bn(pubkey_x, len(pubkey_x), 0)
            other_pub_key_y = openssl.BN_bin2bn(pubkey_y, len(pubkey_y), 0)

            other_group = openssl.EC_KEY_get0_group(other_key)
            other_pub_key = openssl.EC_POINT_new(other_group)

            if (openssl.EC_POINT_set_affine_coordinates_GFp(other_group, other_pub_key, other_pub_key_x, other_pub_key_y, 0)) == 0:
                raise Exception("[OpenSSL] EC_POINT_set_affine_coordinates_GFp FAIL ...")
            if (openssl.EC_KEY_set_public_key(other_key, other_pub_key)) == 0:
                raise Exception("[OpenSSL] EC_KEY_set_public_key FAIL ...")
            if (openssl.EC_KEY_check_key(other_key)) == 0:
                raise Exception("[OpenSSL] EC_KEY_check_key FAIL ...")

            own_key = openssl.EC_KEY_new_by_curve_name(self.curve)
            if own_key == 0:
                raise Exception("[OpenSSL] EC_KEY_new_by_curve_name FAIL ...")
            own_priv_key = openssl.BN_bin2bn(self.privkey, len(self.privkey), 0)

            if (openssl.EC_KEY_set_private_key(own_key, own_priv_key)) == 0:
                raise Exception("[OpenSSL] EC_KEY_set_private_key FAIL ...")

            openssl.ECDH_set_method(own_key, openssl.ECDH_OpenSSL())
            ecdh_keylen = openssl.ECDH_compute_key(ecdh_keybuffer, 32, other_pub_key, own_key, 0)

            if ecdh_keylen != 32:
                raise Exception("[OpenSSL] ECDH keylen FAIL ...")

            return ecdh_keybuffer.raw

        finally:
            openssl.EC_KEY_free(other_key)
            openssl.BN_free(other_pub_key_x)
            openssl.BN_free(other_pub_key_y)
            openssl.EC_POINT_free(other_pub_key)
            openssl.EC_KEY_free(own_key)
            openssl.BN_free(own_priv_key)

    def Check_EC_Key(self, privkey, pubkey_x, pubkey_y):
        try:
            key = openssl.EC_KEY_new_by_curve_name(self.curve)
            if key == 0:
                raise Exception("[OpenSSL] EC_KEY_new_by_curve_name FAIL ...")
            if privkey != 0:
                priv_key = openssl.BN_bin2bn(privkey, len(privkey), 0)
            pub_key_x = openssl.BN_bin2bn(pubkey_x, len(pubkey_x), 0)
            pub_key_y = openssl.BN_bin2bn(pubkey_y, len(pubkey_y), 0)

            if privkey != 0:
                if (openssl.EC_KEY_set_private_key(key, priv_key)) == 0:
                    raise Exception("[OpenSSL] EC_KEY_set_private_key FAIL ...")

            group = openssl.EC_KEY_get0_group(key)
            pub_key = openssl.EC_POINT_new(group)

            if (openssl.EC_POINT_set_affine_coordinates_GFp(group, pub_key, pub_key_x, pub_key_y, 0)) == 0:
                raise Exception("[OpenSSL] EC_POINT_set_affine_coordinates_GFp FAIL ...")
            if (openssl.EC_KEY_set_public_key(key, pub_key)) == 0:
                raise Exception("[OpenSSL] EC_KEY_set_public_key FAIL ...")
            if (openssl.EC_KEY_check_key(key)) == 0:
                raise Exception("[OpenSSL] EC_KEY_check_key FAIL ...")
            return 0

        finally:
            openssl.EC_KEY_free(key)
            openssl.BN_free(pub_key_x)
            openssl.BN_free(pub_key_y)
            openssl.EC_POINT_free(pub_key)
            if privkey != 0: openssl.BN_free(priv_key)

    def Sign(self, inputb):
        try:
            size = len(inputb)
            buff = openssl.malloc(inputb, size)
            digest = openssl.malloc(0, 64)
            md_ctx = openssl.EVP_MD_CTX_create()
            dgst_len = openssl.pointer(openssl.c_int(0))
            siglen = openssl.pointer(openssl.c_int(0))
            sig = openssl.malloc(0, 151)

            key = openssl.EC_KEY_new_by_curve_name(self.curve)
            if key == 0:
                raise Exception("[OpenSSL] EC_KEY_new_by_curve_name FAIL ...")

            priv_key = openssl.BN_bin2bn(self.privkey, len(self.privkey), 0)
            pub_key_x = openssl.BN_bin2bn(self.pubkey_x, len(self.pubkey_x), 0)
            pub_key_y = openssl.BN_bin2bn(self.pubkey_y, len(self.pubkey_y), 0)

            if (openssl.EC_KEY_set_private_key(key, priv_key)) == 0:
                raise Exception("[OpenSSL] EC_KEY_set_private_key FAIL ...")

            group = openssl.EC_KEY_get0_group(key)
            pub_key = openssl.EC_POINT_new(group)

            if (openssl.EC_POINT_set_affine_coordinates_GFp(group, pub_key, pub_key_x, pub_key_y, 0)) == 0:
                raise Exception("[OpenSSL] EC_POINT_set_affine_coordinates_GFp FAIL ...")
            if (openssl.EC_KEY_set_public_key(key, pub_key)) == 0:
                raise Exception("[OpenSSL] EC_KEY_set_public_key FAIL ...")
            if (openssl.EC_KEY_check_key(key)) == 0:
                raise Exception("[OpenSSL] EC_KEY_check_key FAIL ...")

            openssl.EVP_MD_CTX_init(md_ctx)
            openssl.EVP_DigestInit(md_ctx, openssl.EVP_ecdsa())

            if (openssl.EVP_DigestUpdate(md_ctx, buff, size)) == 0:
                raise Exception("[OpenSSL] EVP_DigestUpdate FAIL ...")
            openssl.EVP_DigestFinal(md_ctx, digest, dgst_len)
            openssl.ECDSA_sign(0, digest, dgst_len.contents, sig, siglen, key)
            if (openssl.ECDSA_verify(0, digest, dgst_len.contents, sig, siglen.contents, key)) != 1:
                raise Exception("[OpenSSL] ECDSA_verify FAIL ...")

            return sig.raw

        finally:
            openssl.EC_KEY_free(key)
            openssl.BN_free(pub_key_x)
            openssl.BN_free(pub_key_y)
            openssl.BN_free(priv_key)
            openssl.EC_POINT_free(pub_key)
            openssl.EVP_MD_CTX_destroy(md_ctx)

    def Check_sign(self, sig, inputb):
        try:
            bsig = openssl.malloc(sig, len(sig))
            binputb = openssl.malloc(inputb, len(inputb))
            digest = openssl.malloc(0, 64)
            dgst_len = openssl.pointer(openssl.c_int(0))
            md_ctx = openssl.EVP_MD_CTX_create()

            key = openssl.EC_KEY_new_by_curve_name(self.curve)

            if key == 0:
                raise Exception("[OpenSSL] EC_KEY_new_by_curve_name FAIL ...")

            pub_key_x = openssl.BN_bin2bn(self.pubkey_x, len(self.pubkey_x), 0)
            pub_key_y = openssl.BN_bin2bn(self.pubkey_y, len(self.pubkey_y), 0)
            group = openssl.EC_KEY_get0_group(key)
            pub_key = openssl.EC_POINT_new(group)

            if (openssl.EC_POINT_set_affine_coordinates_GFp(group, pub_key, pub_key_x, pub_key_y, 0)) == 0:
                raise Exception("[OpenSSL] EC_POINT_set_affine_coordinates_GFp FAIL ...")
            if (openssl.EC_KEY_set_public_key(key, pub_key)) == 0:
                raise Exception("[OpenSSL] EC_KEY_set_public_key FAIL ...")
            if (openssl.EC_KEY_check_key(key)) == 0:
                raise Exception("[OpenSSL] EC_KEY_check_key FAIL ...")

            openssl.EVP_MD_CTX_init(md_ctx)
            openssl.EVP_DigestInit(md_ctx, openssl.EVP_ecdsa())
            if (openssl.EVP_DigestUpdate(md_ctx, binputb, len(inputb))) == 0:
                raise Exception("[OpenSSL] EVP_DigestUpdate FAIL ...")

            openssl.EVP_DigestFinal(md_ctx, digest, dgst_len)
            ret = openssl.ECDSA_verify(0, digest, dgst_len.contents, bsig, len(sig), key)

            if ret == -1:
                return False # Fail to Check
            else :
                if ret == 0:
                    return False # Bad signature !
                else:
                    return True # Good
            return False

        finally:
            openssl.EC_KEY_free(key)
            openssl.BN_free(pub_key_x)
            openssl.BN_free(pub_key_y)
            openssl.EC_POINT_free(pub_key)
            openssl.EVP_MD_CTX_destroy(md_ctx)

    def encrypt(self, pubkey_x, pubkey_y, data):
        ciphername = 'aes-256-cbc'
        ephem = ecc()
        key = ephem.Get_EC_Key(pubkey_x, pubkey_y)
        pubkey = pack('!H', len(ephem.pubkey_x))+ephem.pubkey_x+pack('!H', len(ephem.pubkey_y))+ephem.pubkey_y
        iv = openssl.rand(openssl.get_cipher(ciphername).get_blocksize())
        ctx = cipher(key, iv, 1, ciphername)
        return iv + pubkey + ctx.ciphering(data)

    def decrypt(self, data):
        ciphername = 'aes-256-cbc'
        blocksize = openssl.get_cipher(ciphername).get_blocksize()
        iv = data[:blocksize]
        i = blocksize
        tmplen = unpack('!H', data[i:i+2])[0]
        i += 2
        pubkey_x = data[i:i+tmplen]
        i += tmplen
        tmplen = unpack('!H', data[i:i+2])[0]
        i += 2
        pubkey_y = data[i:i+tmplen]
        i += tmplen
        data = data[i:]
        key = self.Get_EC_Key(pubkey_x, pubkey_y)
        ctx = cipher(key, iv, 0, ciphername)
        return ctx.ciphering(data)
