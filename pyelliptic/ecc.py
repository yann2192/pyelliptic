#!/usr/bin/env python
# -*- coding: utf-8 -*-

#  Copyright (C) 2011 Yann GUIBET <yannguibet@gmail.com>
#  See LICENSE for details.

from pyelliptic.openssl import openssl
from pyelliptic.cipher import cipher
from struct import pack, unpack


class ecc:
    """
    Asymmetric encryption with Elliptic Curve Cryptography (ECC)
    ECDH, ECDSA and ECIES

        import pyelliptic

        alice = pyelliptic.ecc() # default curve: sect283r1
        bob = pyelliptic.ecc(curve='sect571r1')

        ciphertext = alice.encrypt("Hello Bob", bob.get_pubkey())
        print bob.decrypt(ciphertext)

        signature = bob.sign("Hello Alice")
        # alice's job :
        print pyelliptic.ecc(pubkey=bob.get_pubkey()).verify(signature, "Hello Alice")

        # ERROR !!!
        try:
            key = alice.get_ecdh_key(bob.get_pubkey())
        except: print("For ECDH key agreement, the keys must be defined on the same curve !")

        alice = pyelliptic.ecc(curve='sect571r1')
        print alice.get_ecdh_key(bob.get_pubkey()).encode('hex')
        print bob.get_ecdh_key(alice.get_pubkey()).encode('hex')

    """
    def __init__(self, pubkey = None, privkey = None, pubkey_x = None, pubkey_y = None, raw_privkey = None, curve = 'sect283r1'):
        """
        For a normal and High level use, specifie pubkey, privkey (if you need) and the curve
        """
        if type(curve) == str:
            self.curve = openssl.get_curve(curve)
        else: self.curve = curve

        if pubkey_x != None and pubkey_y != None:
            self._set_keys(pubkey_x, pubkey_y, raw_privkey)
        elif pubkey != None:
            curve, pubkey_x, pubkey_y, i = ecc._decode_pubkey(pubkey)
            if privkey != None:
                curve2, raw_privkey, i = ecc._decode_privkey(privkey)
                if curve != curve2: raise Exception("Bad ECC keys ...")
            self.curve = curve
            self._set_keys(pubkey_x, pubkey_y, raw_privkey)
        else:
            self.privkey, self.pubkey_x, self.pubkey_y = self._generate()

    def _set_keys(self, pubkey_x, pubkey_y, privkey):
        if self.raw_check_key(privkey, pubkey_x, pubkey_y) < 0:
            self.pubkey_x = None
            self.pubkey_y = None
            self.privkey = None
            raise Exception("Bad ECC keys ...")
        else:
            self.pubkey_x = pubkey_x
            self.pubkey_y = pubkey_y
            self.privkey = privkey

    @staticmethod
    def get_curves():
        """
        static method, returns the list of all the curves available
        """
        return openssl.curves.keys()

    def get_curve(self):
        return openssl.get_curve_by_id(self.curve)

    def get_curve_id(self):
        return self.curve

    def get_pubkey(self):
        """
        High level function which returns curve(2) + len_of_pubkeyX(2) + pubkeyX + len_of_pubkeyY + pubkeyY
        """
        return pack('!H', self.curve)+pack('!H', len(self.pubkey_x))+self.pubkey_x+pack('!H', len(self.pubkey_y))+self.pubkey_y

    def get_privkey(self):
        """
        High level function which returns curve(2) + len_of_privkey(2) + privkey
        """
        return pack('!H', self.curve)+pack('!H', len(self.privkey))+self.privkey

    @staticmethod
    def _decode_pubkey(pubkey):
        i = 0
        curve = unpack('!H', pubkey[i:i+2])[0]
        i += 2
        tmplen = unpack('!H', pubkey[i:i+2])[0]
        i += 2
        pubkey_x = pubkey[i:i+tmplen]
        i += tmplen
        tmplen = unpack('!H', pubkey[i:i+2])[0]
        i += 2
        pubkey_y = pubkey[i:i+tmplen]
        i += tmplen
        return curve, pubkey_x, pubkey_y, i

    @staticmethod
    def _decode_privkey(privkey):
        i = 0
        curve = unpack('!H', privkey[i:i+2])[0]
        i += 2
        tmplen = unpack('!H', privkey[i:i+2])[0]
        i += 2
        privkey = privkey[i:i+tmplen]
        i += tmplen
        return curve, privkey, i

    def _generate(self):
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
            self.raw_check_key(privkey, pubkeyx, pubkeyy)

            return privkey, pubkeyx, pubkeyy

        finally:
            openssl.EC_KEY_free(key)
            openssl.BN_free(pub_key_x)
            openssl.BN_free(pub_key_y)

    def get_ecdh_key(self, pubkey):
        """
        High level function. Compute public key with the local private key and returns a 256bits shared key
        """
        curve, pubkey_x, pubkey_y, i = ecc._decode_pubkey(pubkey)
        if curve != self.curve: raise Exception("ECC keys must be from the same curve !")
        return self.raw_get_ecdh_key(pubkey_x, pubkey_y)

    def raw_get_ecdh_key(self, pubkey_x, pubkey_y):
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

    def check_key(self, privkey, pubkey):
        """
        Check the public key and the private key.
        The private key is optional (replace by None)
        """
        curve, pubkey_x, pubkey_y, i = ecc._decode_pubkey(pubkey)
        if privkey == None:
            raw_privkey = None
            curve2 = curve
        else:
            curve2, raw_privkey, i = ecc._decode_privkey(privkey)
        if curve != curve2: raise Exception("Bad public and private key")
        return self.raw_check_key(raw_privkey, pubkey_x, pubkey_y, curve)

    def raw_check_key(self, privkey, pubkey_x, pubkey_y, curve=None):
        if curve == None: curve = self.curve
        elif type(curve) == str: curve = openssl.get_curve(curve)
        else: curve = curve
        try:
            key = openssl.EC_KEY_new_by_curve_name(curve)
            if key == 0:
                raise Exception("[OpenSSL] EC_KEY_new_by_curve_name FAIL ...")
            if privkey != None:
                priv_key = openssl.BN_bin2bn(privkey, len(privkey), 0)
            pub_key_x = openssl.BN_bin2bn(pubkey_x, len(pubkey_x), 0)
            pub_key_y = openssl.BN_bin2bn(pubkey_y, len(pubkey_y), 0)

            if privkey != None:
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
            if privkey != None: openssl.BN_free(priv_key)

    def sign(self, inputb):
        """
        Sign the input with ECDSA method and returns the signature
        """
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

    def verify(self, sig, inputb):
        """
        Verify the signature with the input and the local public key. Returns a boolean
        """
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

    @staticmethod
    def encrypt(data, pubkey, ephemcurve=None, ciphername='aes-256-cbc'):
        """
        Encrypt data with ECIES method using the public key of the recipient.
        """
        curve, pubkey_x, pubkey_y, i = ecc._decode_pubkey(pubkey)
        return ecc.raw_encrypt(data, pubkey_x, pubkey_y, curve=curve, ephemcurve=ephemcurve, ciphername=ciphername)

    @staticmethod
    def raw_encrypt(data, pubkey_x, pubkey_y, curve='sect283r1', ephemcurve=None, ciphername='aes-256-cbc'):
        if ephemcurve == None: ephemcurve = curve
        ephem = ecc(curve=ephemcurve)
        key = ephem.raw_get_ecdh_key(pubkey_x, pubkey_y)
        pubkey = ephem.get_pubkey()
        iv = openssl.rand(openssl.get_cipher(ciphername).get_blocksize())
        ctx = cipher(key, iv, 1, ciphername)
        return iv + pubkey + ctx.ciphering(data)

    def decrypt(self, data, ciphername='aes-256-cbc'):
        """
        Decrypt data with ECIES method using the local private key
        """
        blocksize = openssl.get_cipher(ciphername).get_blocksize()
        iv = data[:blocksize]
        i = blocksize
        curve, pubkey_x, pubkey_y, i2 = ecc._decode_pubkey(data[i:])
        i += i2
        data = data[i:]
        key = self.raw_get_ecdh_key(pubkey_x, pubkey_y)
        ctx = cipher(key, iv, 0, ciphername)
        return ctx.ciphering(data)

