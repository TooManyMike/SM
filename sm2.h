/*
* Description: SM2 encryption and signature algorithm
* Author: Mike
* Date: 2018-03-09
*/

#ifndef SM2_H
#define SM2_H

#define SM2_SUCCESS	0
#define SM2_FAIL	1
#define SM2_PRIVATE_KEY_ERROR	2
#define SM2_PUBLIC_KEY_ERROR	3
#define SM2_RANDOM_NUMBER_ERROR	4
#define SM2_RANDOM_NUMBER_IMPROPER	5
#define SM2_LEN		8

/* recommended curve parameters */
static unsigned int p[SM2_LEN] = { 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF };
static unsigned int a[SM2_LEN] = { 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFC };
static unsigned int b[SM2_LEN] = { 0x28E9FA9E, 0x9D9F5E34, 0x4D5A9E4B, 0xCF6509A7, 0xF39789F5, 0x15AB8F92, 0xDDBCBD41, 0x4D940E93 };
static unsigned int n[SM2_LEN] = { 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x7203DF6B, 0x21C6052B, 0x53BBF409, 0x39D54123 };
static unsigned int Gx[SM2_LEN] = { 0x32C4AE2C, 0x1F198119, 0x5F990446, 0x6A39C994, 0x8FE30BBF, 0xF2660BE1, 0x715A4589, 0x334C74C7 };
static unsigned int Gy[SM2_LEN] = { 0xBC3736A2, 0xF4F6779C, 0x59BDCEE3, 0x6B692153, 0xD0A9877C, 0xC62A4740, 0x02DF32E5, 0x2139F0A0 };

#ifdef __cplusplus
extern "C" {
#endif

/***
* transformation between byte string and int32 array, works in both directions
* len: length of int32 array
***/
void ChangeByteOrder(unsigned char *in, unsigned char *out, int len);

/***
* derive SM2 public key from private key
* dB: input private key, random number dB¡Ê[1,n-1]
* PB: output public key
***/
int sm2_get_public_key(unsigned char dB[SM2_LEN * 4], unsigned char PB[SM2_LEN * 8 + 1]);

/***
 * generate SM2 key pair
 * dB: output private key
 * PB: output public key
***/
void sm2_create_key(unsigned char dB[SM2_LEN * 4], unsigned char PB[SM2_LEN * 8 + 1]);

/***
* SM2 encrypt function
* NOTICE: length of out buffer should be at least len + SM2_LEN * 8 + 33 bytes
* PB: public key
* k: random number k¡Ê[1,n-1]
***/
int sm2_encrypt(unsigned char *in, int len, unsigned char *out, unsigned char PB[SM2_LEN * 8 + 1]);
int sm2_encrypt2(unsigned char *in, int len, unsigned char *out, unsigned char PB[SM2_LEN * 8 + 1], unsigned char k[SM2_LEN * 4]);

/***
* SM2 decrypt function
* NOTICE: length of out buffer should be at least len - SM2_LEN * 8 - 33 bytes
* dB: private key
***/
int sm2_decrypt(unsigned char *in, int len, unsigned char *out, unsigned char dB[SM2_LEN * 4]);

/***
* SM2 signature process
* NOTICE: length of out buffer should be at least SM2_LEN * 8 bytes
* in: cascade of distinguishing identifier and signed message
* out: digital signature
* dA: private key
* k: random number k¡Ê[1,n-1]
***/
int sm2_signature(unsigned char *IDA, int IDA_len, unsigned char *message, int message_len, unsigned char *out, unsigned char dA[SM2_LEN * 4]);
int sm2_signature2(unsigned char *IDA, int IDA_len, unsigned char *message, int message_len, unsigned char *out, unsigned char dA[SM2_LEN * 4], unsigned char k[SM2_LEN * 4]);

/***
* SM2 signature verification process
* in: cascade of distinguishing identifier and signed message
* signature: digital signature
* PA: public key
* return false if failed to verify the signature
***/
int sm2_verify(unsigned char *IDA, int IDA_len, unsigned char *message, int message_len, unsigned char *signature, unsigned char PA[SM2_LEN * 8 + 1]);

#ifdef __cplusplus
}
#endif

#endif