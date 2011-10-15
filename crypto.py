#!/usr/bin/env python
# -*- coding: utf-8 -*-

#  Copyright (C) 2011 Yann GUIBET <yannguibet@gmail.com>
#  See LICENSE for details.

import sys
from ctypes import *

def LoadLibrary():
	try:
		libcrypto = cdll.LoadLibrary('libcrypto.so')
	except:
		try:
			libcrypto = cdll.LoadLibrary('libeay32.dll')
		except:
			raise Exception("Couldn't load OpenSSL lib ...")
	return libcrypto

libcrypto = LoadLibrary()

class ECC_key:
    def __init__(self, pubkey_x = 0, pubkey_y = 0, privkey = 0):
        self.curve = 734 # == NID_sect571r1
        self.SIZE_ECC_KEY = 72 # With NID_sect571r1
        global libcrypto; self.libcrypto = libcrypto
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
            pub_key_x = self.libcrypto.BN_new()
            pub_key_y = self.libcrypto.BN_new()
            
            while 1:
                key = self.libcrypto.EC_KEY_new_by_curve_name(self.curve)
                if key == 0:
                    raise Exception("[OpenSSL] EC_KEY_new_by_curve_name FAIL ...")
                if (self.libcrypto.EC_KEY_generate_key(key)) == 0:
                    raise Exception("[OpenSSL] EC_KEY_generate_key FAIL ...")
                if (self.libcrypto.EC_KEY_check_key(key)) == 0:
                    raise Exception("[OpenSSL] EC_KEY_check_key FAIL ...")
                priv_key = self.libcrypto.EC_KEY_get0_private_key(key)
                
                group = self.libcrypto.EC_KEY_get0_group(key)
                pub_key = self.libcrypto.EC_KEY_get0_public_key(key)
                
                if (self.libcrypto.EC_POINT_get_affine_coordinates_GFp(group, pub_key, pub_key_x, pub_key_y, 0)) == 0:
                    raise Exception("[OpenSSL] EC_POINT_get_affine_coordinates_GFp FAIL ...")
                privkey = malloc(0, self.SIZE_ECC_KEY)
                pubkeyx = malloc(0, self.SIZE_ECC_KEY)
                pubkeyy = malloc(0, self.SIZE_ECC_KEY)
                self.libcrypto.BN_bn2bin(priv_key,privkey)
                privkey = privkey.raw
                self.libcrypto.BN_bn2bin(pub_key_x,pubkeyx)
                pubkeyx = pubkeyx.raw
                self.libcrypto.BN_bn2bin(pub_key_y,pubkeyy)
                pubkeyy = pubkeyy.raw
                try:
                    self.Check_EC_Key(privkey, pubkeyx, pubkeyy)
                    break
                except:
                    self.libcrypto.EC_KEY_free(key)
                    pass
            return privkey, pubkeyx, pubkeyy
                    
        finally:
            self.libcrypto.EC_KEY_free(key)
            self.libcrypto.BN_free(pub_key_x)
            self.libcrypto.BN_free(pub_key_y)

    def Get_EC_Key(self, pubkey_x, pubkey_y):
        try:
            ecdh_keybuffer = malloc(0, 32)
            
            other_key = self.libcrypto.EC_KEY_new_by_curve_name(self.curve)
            if other_key == 0:
                raise Exception("[OpenSSL] EC_KEY_new_by_curve_name FAIL ...")
            
            other_pub_key_x = self.libcrypto.BN_bin2bn(pubkey_x, self.SIZE_ECC_KEY, 0)
            other_pub_key_y = self.libcrypto.BN_bin2bn(pubkey_y, self.SIZE_ECC_KEY, 0)
            
            other_group = self.libcrypto.EC_KEY_get0_group(other_key)
            other_pub_key = self.libcrypto.EC_POINT_new(other_group)
            
            if (self.libcrypto.EC_POINT_set_affine_coordinates_GFp(other_group, other_pub_key, other_pub_key_x, other_pub_key_y, 0)) == 0:
                raise Exception("[OpenSSL] EC_POINT_set_affine_coordinates_GFp FAIL ...")
            if (self.libcrypto.EC_KEY_set_public_key(other_key, other_pub_key)) == 0:
                raise Exception("[OpenSSL] EC_KEY_set_public_key FAIL ...")
            if (self.libcrypto.EC_KEY_check_key(other_key)) == 0:
                raise Exception("[OpenSSL] EC_KEY_check_key FAIL ...")
            
            own_key = self.libcrypto.EC_KEY_new_by_curve_name(self.curve)
            if own_key == 0:
                raise Exception("[OpenSSL] EC_KEY_new_by_curve_name FAIL ...")
            own_priv_key = self.libcrypto.BN_bin2bn(self.privkey, self.SIZE_ECC_KEY, 0)
            
            if (self.libcrypto.EC_KEY_set_private_key(own_key, own_priv_key)) == 0:
                raise Exception("[OpenSSL] EC_KEY_set_private_key FAIL ...")
            # For 64bits 
            self.libcrypto.ECDH_set_method.argtypes = [c_void_p, c_void_p]
            self.libcrypto.ECDH_OpenSSL.restype = c_void_p
            #
            self.libcrypto.ECDH_set_method(own_key, self.libcrypto.ECDH_OpenSSL())
            ecdh_keylen = self.libcrypto.ECDH_compute_key(ecdh_keybuffer, 32, other_pub_key, own_key, 0)
            
            if ecdh_keylen != 32:
                raise Exception("[OpenSSL] ECDH keylen FAIL ...")
            
            return ecdh_keybuffer.raw
        
        finally:
            self.libcrypto.EC_KEY_free(other_key)
            self.libcrypto.BN_free(other_pub_key_x)
            self.libcrypto.BN_free(other_pub_key_y)
            self.libcrypto.EC_POINT_free(other_pub_key)
            self.libcrypto.EC_KEY_free(own_key)
            self.libcrypto.BN_free(own_priv_key)	


    def Check_EC_Key(self, privkey, pubkey_x, pubkey_y):
        try:
            key = self.libcrypto.EC_KEY_new_by_curve_name(self.curve)
            if key == 0:
                raise Exception("[OpenSSL] EC_KEY_new_by_curve_name FAIL ...")
            if privkey != 0:
                priv_key = self.libcrypto.BN_bin2bn(privkey, self.SIZE_ECC_KEY, 0)
            pub_key_x = self.libcrypto.BN_bin2bn(pubkey_x, self.SIZE_ECC_KEY, 0)
            pub_key_y = self.libcrypto.BN_bin2bn(pubkey_y, self.SIZE_ECC_KEY, 0)
                
            if privkey != 0:
                if (self.libcrypto.EC_KEY_set_private_key(key, priv_key)) == 0:
                    raise Exception("[OpenSSL] EC_KEY_set_private_key FAIL ...")

            group = self.libcrypto.EC_KEY_get0_group(key)
            pub_key = self.libcrypto.EC_POINT_new(group)
            
            if (self.libcrypto.EC_POINT_set_affine_coordinates_GFp(group, pub_key, pub_key_x, pub_key_y, 0)) == 0:
                raise Exception("[OpenSSL] EC_POINT_set_affine_coordinates_GFp FAIL ...")
            if (self.libcrypto.EC_KEY_set_public_key(key, pub_key)) == 0:
                raise Exception("[OpenSSL] EC_KEY_set_public_key FAIL ...")
            if (self.libcrypto.EC_KEY_check_key(key)) == 0:
                raise Exception("[OpenSSL] EC_KEY_check_key FAIL ...")
            return 0

        finally:
            self.libcrypto.EC_KEY_free(key)
            self.libcrypto.BN_free(pub_key_x)
            self.libcrypto.BN_free(pub_key_y)
            self.libcrypto.EC_POINT_free(pub_key)
            if privkey != 0: self.libcrypto.BN_free(priv_key)

    def Sign(self, inputb):
        try:
            size = len(inputb)
            buff = malloc(inputb, size)
            digest = malloc(0, 64)
            md_ctx = self.libcrypto.EVP_MD_CTX_create()
            dgst_len = pointer(c_int(0))
            siglen = pointer(c_int(0))
            sig = malloc(0, 151)
            
            key = self.libcrypto.EC_KEY_new_by_curve_name(self.curve)
            if key == 0:
                raise Exception("[OpenSSL] EC_KEY_new_by_curve_name FAIL ...")
		
            priv_key = self.libcrypto.BN_bin2bn(self.privkey, self.SIZE_ECC_KEY, 0)
            pub_key_x = self.libcrypto.BN_bin2bn(self.pubkey_x, self.SIZE_ECC_KEY, 0)
            pub_key_y = self.libcrypto.BN_bin2bn(self.pubkey_y, self.SIZE_ECC_KEY, 0)
            
            if (self.libcrypto.EC_KEY_set_private_key(key, priv_key)) == 0:
                raise Exception("[OpenSSL] EC_KEY_set_private_key FAIL ...")
            
            group = self.libcrypto.EC_KEY_get0_group(key)
            pub_key = self.libcrypto.EC_POINT_new(group)
            
            if (self.libcrypto.EC_POINT_set_affine_coordinates_GFp(group, pub_key, pub_key_x, pub_key_y, 0)) == 0:
                raise Exception("[OpenSSL] EC_POINT_set_affine_coordinates_GFp FAIL ...")
            if (self.libcrypto.EC_KEY_set_public_key(key, pub_key)) == 0:
                raise Exception("[OpenSSL] EC_KEY_set_public_key FAIL ...")
            if (self.libcrypto.EC_KEY_check_key(key)) == 0:
                raise Exception("[OpenSSL] EC_KEY_check_key FAIL ...")
            
            self.libcrypto.EVP_MD_CTX_init(md_ctx)
            # For 64bits
            self.libcrypto.EVP_DigestInit.argtypes = [c_void_p, c_void_p]
            self.libcrypto.EVP_ecdsa.restype = c_void_p
            #
            self.libcrypto.EVP_DigestInit(md_ctx, self.libcrypto.EVP_ecdsa())
			
            if (self.libcrypto.EVP_DigestUpdate(md_ctx, buff, size)) == 0:
                raise Exception("[OpenSSL] EVP_DigestUpdate FAIL ...")
            self.libcrypto.EVP_DigestFinal(md_ctx, digest, dgst_len)
            self.libcrypto.ECDSA_sign(0, digest, dgst_len.contents, sig, siglen, key) 
            if (self.libcrypto.ECDSA_verify(0, digest, dgst_len.contents, sig, siglen.contents, key)) != 1:
                raise Exception("[OpenSSL] ECDSA_verify FAIL ...")
            
            return sig.raw
        
        finally:
            self.libcrypto.EC_KEY_free(key)
            self.libcrypto.BN_free(pub_key_x)
            self.libcrypto.BN_free(pub_key_y)
            self.libcrypto.BN_free(priv_key)
            self.libcrypto.EC_POINT_free(pub_key)
            self.libcrypto.EVP_MD_CTX_destroy(md_ctx)
                
    def Check_sign(self, sig, inputb):
        try:
            bsig = malloc(sig, len(sig))
            binputb = malloc(inputb, len(inputb))
            digest = malloc(0, 64)
            dgst_len = pointer(c_int(0))
            md_ctx = self.libcrypto.EVP_MD_CTX_create()
            
            key = self.libcrypto.EC_KEY_new_by_curve_name(self.curve)
            
            if key == 0:
                raise Exception("[OpenSSL] EC_KEY_new_by_curve_name FAIL ...")
            
            pub_key_x = self.libcrypto.BN_bin2bn(self.pubkey_x, self.SIZE_ECC_KEY, 0)
            pub_key_y = self.libcrypto.BN_bin2bn(self.pubkey_y, self.SIZE_ECC_KEY, 0)
            group = self.libcrypto.EC_KEY_get0_group(key)
            pub_key = self.libcrypto.EC_POINT_new(group)
            
            if (self.libcrypto.EC_POINT_set_affine_coordinates_GFp(group, pub_key, pub_key_x, pub_key_y, 0)) == 0:
                raise Exception("[OpenSSL] EC_POINT_set_affine_coordinates_GFp FAIL ...")
            if (self.libcrypto.EC_KEY_set_public_key(key, pub_key)) == 0:
                raise Exception("[OpenSSL] EC_KEY_set_public_key FAIL ...")
            if (self.libcrypto.EC_KEY_check_key(key)) == 0:
                raise Exception("[OpenSSL] EC_KEY_check_key FAIL ...")
            
            self.libcrypto.EVP_MD_CTX_init(md_ctx)
            # For 64bits
            self.libcrypto.EVP_DigestInit.argtypes = [c_void_p, c_void_p]
            self.libcrypto.EVP_ecdsa.restype = c_void_p
            #
            self.libcrypto.EVP_DigestInit(md_ctx, self.libcrypto.EVP_ecdsa())
            if (self.libcrypto.EVP_DigestUpdate(md_ctx, binputb, len(inputb))) == 0:
                raise Exception("[OpenSSL] EVP_DigestUpdate FAIL ...")

            self.libcrypto.EVP_DigestFinal(md_ctx, digest, dgst_len)
            ret = self.libcrypto.ECDSA_verify(0, digest, dgst_len.contents, bsig, len(sig), key)
            
            if ret == -1:
                return False # Fail to Check
            else :
                if ret == 0:
                    return False # Bad signature !
                else:
                    return True # Good
            return False
            
        finally:
            self.libcrypto.EC_KEY_free(key)
            self.libcrypto.BN_free(pub_key_x)
            self.libcrypto.BN_free(pub_key_y)
            self.libcrypto.EC_POINT_free(pub_key)
            self.libcrypto.EVP_MD_CTX_destroy(md_ctx)
                
    def encrypt(self, pubkey_x, pubkey_y, data):
        ephem = ECC_key()
        key = ephem.Get_EC_Key(pubkey_x, pubkey_y)
        pubkey = ephem.pubkey_x+ephem.pubkey_y
        iv = rand(16)
        ctx = aes(key, iv, 1, mode='cbc')
        return iv + pubkey + ctx.ciphering(data)
    
    def decrypt(self, data):
        iv = data[:16]
        i = 16 + self.SIZE_ECC_KEY
        pubkey_x = data[16:i]
        pubkey_y = data[i:i+self.SIZE_ECC_KEY]
        data = data[i+self.SIZE_ECC_KEY:]
        key = self.Get_EC_Key(pubkey_x, pubkey_y)
        ctx = aes(key, iv, 0, mode='cbc')
        return ctx.ciphering(data)

def rand(size):
    global libcrypto
    buffer = malloc(0, size)
    libcrypto.RAND_bytes(buffer, size)
    return buffer.raw

def malloc(data, size):
    if data != 0:
        if sys.version_info.major == 3 and type(data) == type(''): data = data.encode()
        buffer = create_string_buffer(data, size)
    else:
        buffer = create_string_buffer(size)
    return buffer

class aes:
	def __init__(self, key, iv, do, mode='cfb'): # do == 1 => Encrypt; do == 0 => Decrypt
            global libcrypto; self.libcrypto = libcrypto
            self.ctx = self.libcrypto.EVP_CIPHER_CTX_new()
            if do == 1 or do == 0:
                k = malloc(key, len(key))
                IV = malloc(iv, len(iv))
                self.libcrypto.EVP_CipherInit_ex.argtypes = [ c_void_p, c_void_p, c_void_p, c_void_p, c_void_p, c_void_p]
                if mode == 'cbc':
                    self.libcrypto.EVP_aes_256_cbc.restype = c_void_p
                    self.libcrypto.EVP_CipherInit_ex(self.ctx, self.libcrypto.EVP_aes_256_cbc(), 0, k, IV, do)
                elif mode == 'cfb':
                    self.libcrypto.EVP_aes_256_cfb128.restype = c_void_p
                    self.libcrypto.EVP_CipherInit_ex(self.ctx, self.libcrypto.EVP_aes_256_cfb128(), 0, k, IV, do)
                else:
                    raise Exception("Unknown mode")
            else:
                raise Exception("RTFM ...")

	def ciphering(self, input):
            i = c_int(len(input))
            buffer = malloc(0, len(input)+16)
            inp = malloc(input,len(input))
            if (self.libcrypto.EVP_CipherUpdate(self.ctx, byref(buffer), byref(i), inp, len(input))) == 0:
                raise Exception("[OpenSSL] EVP_CipherUpdate FAIL ...")
            y = i.value
            i.value = 0
            if (self.libcrypto.EVP_CipherFinal_ex(self.ctx, byref(buffer,y), byref(i))) == 0:
                raise Exception("[OpenSSL] EVP_CipherFinal_ex FAIL ...")
            return buffer.raw[0:i.value+y]

	def __del__(self):
		self.libcrypto.EVP_CIPHER_CTX_cleanup(self.ctx)
		self.libcrypto.EVP_CIPHER_CTX_free(self.ctx)

def Hmac(k, m):
    key = malloc(k, len(k))
    d = malloc(m, len(m))
    md = malloc(0, 64)
    i = pointer(c_int(0))
    global libcrypto
    # For 64bits
    libcrypto.HMAC.argtypes = [ c_void_p, c_void_p, c_int, c_void_p, c_int, c_void_p]
    libcrypto.EVP_sha512.restype = c_void_p
    #
    libcrypto.HMAC(libcrypto.EVP_sha512(), key, len(k), d, len(m), md, i)
    return md.raw
