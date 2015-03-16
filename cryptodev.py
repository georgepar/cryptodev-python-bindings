#!/usr/bin/python

from ctypes import *
from enum import *
from ioctl import *

__u8 = c_ubyte
__u16 = c_ushort
__u32 = c_uint
__u64 = c_ulonglong

CRYPTO_HMAC_MAX_KEY_LEN = 512
CRYPTO_CIPHER_MAX_KEY_LEN = 64

'''
cryptodev_crypto_op_t = c_int

(CRYPTO_DES_CBC,
 CRYPTO_3DES_CBC,
 CRYPTO_BLF_CBC,
 CRYPTO_CAST_CBC,
 CRYPTO_SKIPJACK_CBC,
 CRYPTO_MD5_HMAC,
 CRYPTO_SHA1_HMAC,
 CRYPTO_RIPEMD160_HMAC,
 CRYPTO_MD5_KPDK,
 CRYPTO_SHA1_KPDK,
 CRYPTO_RIJNDAEL128_CBC,
 CRYPTO_ARC4,
 CRYPTO_MD5,
 CRYPTO_SHA1,
 CRYPTO_DEFLATE_COMP,
 CRYPTO_NULL,
 CRYPTO_LZS_COMP,
 CRYPTO_SHA2_256_HMAC,
 CRYPTO_SHA2_384_HMAC,
 CRYPTO_SHA2_512_HMAC,
 CRYPTO_AES_CTR,
 CRYPTO_AES_XTS,
 CRYPTO_AES_ECB,
) = map(c_int, range(1, 24))
CRYPTO_AES_GCM = c_int(50)
CRYPTO_AES_CBC = CRYPTO_RIJNDAEL128_CBC

CRYPTO_CAMELLIA_CBC = c_int(101)
CRYPTO_RIPEMD160 = c_int(102) # value defined here by me
CRYPTO_SHA2_224 = c_int(103)
CRYPTO_SHA2_256 = c_int(104)
CRYPTO_SHA2_384 = c_int(105)
CRYPTO_SHA2_512 = c_int(106)
CRYPTO_SHA2_224_HMAC = c_int(107)
CRYPTO_ALGORITHM_ALL = c_int(108)	# Keep updated - see below 
'''

class cryptodev_crypto_op_t(Enum):
	CRYPTO_DES_CBC = 1
	CRYPTO_3DES_CBC = 2
	CRYPTO_BLF_CBC = 3
	CRYPTO_CAST_CBC = 4
	CRYPTO_SKIPJACK_CBC = 5
	CRYPTO_MD5_HMAC = 6
	CRYPTO_SHA1_HMAC = 7
	CRYPTO_RIPEMD160_HMAC = 8
	CRYPTO_MD5_KPDK = 9
	CRYPTO_SHA1_KPDK = 10
	CRYPTO_RIJNDAEL128_CBC = 11
	CRYPTO_AES_CBC = CRYPTO_RIJNDAEL128_CBC
	CRYPTO_ARC4 = 12
	CRYPTO_MD5 = 13
	CRYPTO_SHA1 = 14
	CRYPTO_DEFLATE_COMP = 15
	CRYPTO_NULL = 16
	CRYPTO_LZS_COMP = 17
	CRYPTO_SHA2_256_HMAC = 18
	CRYPTO_SHA2_384_HMAC = 19
	CRYPTO_SHA2_512_HMAC = 20
	CRYPTO_AES_CTR = 21
	CRYPTO_AES_XTS = 22
	CRYPTO_AES_ECB = 23
	CRYPTO_AES_GCM = 50

	CRYPTO_CAMELLIA_CBC = 101
	CRYPTO_RIPEMD160 = 102 # value defined here by me
	CRYPTO_SHA2_224 = 103
	CRYPTO_SHA2_256 = 104
	CRYPTO_SHA2_384 = 105
	CRYPTO_SHA2_512 = 106
	CRYPTO_SHA2_224_HMAC = 107
	CRYPTO_ALGORITHM_ALL = 108 # Keep updated - see below


CRYPTO_ALGORITHM_MAX = cryptodev_crypto_op_t.CRYPTO_ALGORITHM_ALL - 1

# Values for ciphers
DES_BLOCK_LEN = 8
DES3_BLOCK_LEN = 8
RIJNDAEL128_BLOCK_LEN = 16
AES_BLOCK_LEN = RIJNDAEL128_BLOCK_LEN
CAMELLIA_BLOCK_LEN = 16
BLOWFISH_BLOCK_LEN = 8
SKIPJACK_BLOCK_LEN = 8
CAST128_BLOCK_LEN = 8

# the maximum of the above
EALG_MAX_BLOCK_LEN = 16
# Values for hashes/MAC 
AALG_MAX_RESULT_LEN	= 64

# maximum length of verbose alg names (depends on CRYPTO_MAX_ALG_NAME) 
CRYPTODEV_MAX_ALG_NAME = 64
HASH_MAX_LEN = 64

# input of CIOCGSESSION
class session_op(Structure):
	# Specify either cipher or mac
	_fields_ = [("cipher", __u32),	# cryptodev_crypto_op_t 
				("mac", __u32),		# cryptodev_crypto_op_t 
				("keylen", __u32),
				("key", POINTER(__u8)),
				("mackeylen", __u32),
				("mackey", POINTER(__u8)),
				("ses", __u32)	# session identifier
			   ]

# verbose names for the requested ciphers 
class alg_info(Structure):
	_fields_ = [
				("cra_name", c_char * CRYPTODEV_MAX_ALG_NAME),
			   	("cra_driver_name", c_char * CRYPTODEV_MAX_ALG_NAME)
			   ]

class session_info_op(Structure):
	_fields_ = [
				("ses", __u32),	# session identifier
				("cipher_info", alg_info),
				("hash_info", alg_info),
				("alignmask", __u16),	# alignment constraints 
				("flags", __u32)	# SIOP_FLAGS
			   ]

'''
 * If this flag is set then this algorithm uses
 * a driver only available in kernel (software drivers,
 * or drivers based on instruction sets do not set this flag).
 *
 * If multiple algorithms are involved (as in AEAD case), then
 * if one of them is kernel-driver-only this flag will be set.
'''
SIOP_FLAG_KERNEL_DRIVER_ONLY = 1

COP_ENCRYPT = 0
COP_DECRYPT = 1

# input of CIOCCRYPT
class crypt_op(Structure):
	_fields_ = [
				("ses", __u32),		# session identifier 
				("op", __u16),		# COP_ENCRYPT or COP_DECRYPT  
				("flags", __u16),	# see COP_FLAG
				("len", __u32),		# length of source data
				("src", POINTER(__u8)),	# source data
				("dst", POINTER(__u8)), # pointer to output data 
				# pointer to output data for hash/MAC operations
				("mac", POINTER(__u8)),
				# initialization vector for encryption operations 
				("iv", POINTER(__u8))
			   ]

# input of CIOCAUTHCRYPT
class crypt_auth_op(Structure):
	_fields_ = [				
				("ses", __u32),		# session identifier
				("op", __u16),		# COP_ENCRYPT or COP_DECRYPT 
				("flags", __u16),	# see COP_FLAG_AEAD_* 
				("len", __u32),		# length of source data
				("auth_len", __u32),	# length of auth data
				("auth_src", POINTER(__u8)),	# authenticated-only data
				# The current implementation is more efficient if data are
	 			# encrypted in-place (src==dst). 
				("src", POINTER(__u8)), # data to be encrypted and authenticated
				("dst", POINTER(__u8)), # pointer to output data. Must have
	                         			# space for tag. For TLS this should be at least 
	                         			# len + tag_size + block_size for padding
				("tag", POINTER(__u8)), # where the tag will be copied to. TLS mode
                                 		# doesn't use that as tag is copied to dst.
                                 		# SRTP mode copies tag there.
				("tag_len", __u32), 	# the length of the tag. Use zero for digest size or max tag.
				# initialization vector for encryption operations 
				("iv", POINTER(__u8))
				("iv_len", __u32),	
			   ]

'''
 In plain AEAD mode the following are required:
 *  flags   : 0
 *  iv      : the initialization vector (12 bytes)
 *  auth_len: the length of the data to be authenticated
 *  auth_src: the data to be authenticated
 *  len     : length of data to be encrypted
 *  src     : the data to be encrypted
 *  dst     : space to hold encrypted data. It must have
 *            at least a size of len + tag_size.
 *  tag_size: the size of the desired authentication tag or zero to use
 *            the maximum tag output.
 *
 * Note tag isn't being used because the Linux AEAD interface
 * copies the tag just after data.


 In TLS mode (used for CBC ciphers that required padding) 
 * the following are required:
 *  flags   : COP_FLAG_AEAD_TLS_TYPE
 *  iv      : the initialization vector
 *  auth_len: the length of the data to be authenticated only
 *  len     : length of data to be encrypted
 *  auth_src: the data to be authenticated
 *  src     : the data to be encrypted
 *  dst     : space to hold encrypted data (preferably in-place). It must have
 *            at least a size of len + tag_size + blocksize.
 *  tag_size: the size of the desired authentication tag or zero to use
 *            the default mac output.
 *
 * Note that the padding used is the minimum padding.


In SRTP mode the following are required:
 *  flags   : COP_FLAG_AEAD_SRTP_TYPE
 *  iv      : the initialization vector
 *  auth_len: the length of the data to be authenticated. This must
 *            include the SRTP header + SRTP payload (data to be encrypted) + rest
 *            
 *  len     : length of data to be encrypted
 *  auth_src: pointer the data to be authenticated. Should point at the same buffer as src.
 *  src     : pointer to the data to be encrypted.
 *  dst     : This is mandatory to be the same as src (in-place only).
 *  tag_size: the size of the desired authentication tag or zero to use
 *            the default mac output.
 *  tag     : Pointer to an address where the authentication tag will be copied.
'''
#struct crypt_op flags
COP_FLAG_NONE = 0 << 0 		# totally no flag
COP_FLAG_UPDATE = 1 << 0 	# multi-update hash mode
COP_FLAG_FINAL = 1 << 1 	# multi-update final hash mode
COP_FLAG_WRITE_IV = 1 << 2 	# update the IV during operation
COP_FLAG_NO_ZC = 1 << 3 	# do not zero-copy
COP_FLAG_AEAD_TLS_TYPE = 1 << 4 	# authenticate and encrypt using the 
                                	# TLS protocol rules
COP_FLAG_AEAD_SRTP_TYPE = 1 << 5 	# authenticate and encrypt using the 
                                 	# SRTP protocol rules
COP_FLAG_RESET = 1 << 6 	# multi-update reset the state.
                        	# should be used in combination
                        	# with COP_FLAG_UPDATE


# Stuff for bignum arithmetic and public key
# cryptography - not supported yet by linux
# cryptodev.
CRYPTO_ALG_FLAG_SUPPORTED = 1
CRYPTO_ALG_FLAG_RNG_ENABLE = 2 
CRYPTO_ALG_FLAG_DSA_SHA = 4

class crparam(Structure):
	_fields_ = [
				("crp_op", POINTER(_u8)),
				("crp_nbits", _u32)
			   ]	

CRK_MAXPARAM = 8

# input of CIOCKEY
class crypt_kop(Structure):
	_fields_ = [
				("crk_op", __u32),
				("crk_status", __u32),
				("crk_iparams", __u16),
				("crk_oparams", __u16),
				("crk_pad1", __u32),
				("crk_param", crparam * CRK_MAXPARAM)
			   ]

class cryptodev_crk_op_t(Enum):
	CRK_MOD_EXP = 0
	CRK_MOD_EXP_CRT = 1
	CRK_DSA_SIGN = 2
	CRK_DSA_VERIFY = 3
	CRK_DH_COMPUTE_KEY = 4
	CRK_ALGORITHM_ALL = 5

CRK_ALGORITHM_MAX = CRK_ALGORITHM_ALL - 1

# features to be queried with CIOCASYMFEAT ioctl
CRF_MOD_EXP = 1 << CRK_MOD_EXP
CRF_MOD_EXP_CRT = 1 << CRK_MOD_EXP_CRT
CRF_DSA_SIGN = 1 << CRK_DSA_SIGN
CRF_DSA_VERIFY = 1 << CRK_DSA_VERIFY
CRF_DH_COMPUTE_KEY = 1 << CRK_DH_COMPUTE_KEY

# ioctl's. Compatible with old linux cryptodev.h
CRIOGET = _IOWR('c', 101, __u32)
CIOCGSESSION = _IOWR('c', 102, session_op)
CIOCFSESSION = _IOW('c', 103, __u32)
CIOCCRYPT = _IOWR('c', 104, crypt_op)
CIOCKEY = _IOWR('c', 105, crypt_kop)
CIOCASYMFEAT = _IOR('c', 106, __u32)
CIOCGSESSINFO = _IOWR('c', 107, session_info_op)

# to indicate that CRIOGET is not required in linux
CRIOGET_NOT_NEEDED = 1

# additional ioctls for AEAD
CIOCAUTHCRYPT = _IOWR('c', 109, crypt_auth_op)

# additional ioctls for asynchronous operation.
# These are conditionally enabled since version 1.6.
CIOCASYNCCRYPT = _IOW('c', 110, crypt_op)
CIOCASYNCFETCH = _IOR('c', 111, crypt_op)