/*
* Description: SM4 encryption algorithm
* Author: Mike
* Date: 2017-09-28
*/

#ifndef SM4_H
#define SM4_H

#ifdef __cplusplus
extern "C"{
#endif

/***
 *
 * NOTICE: length of buffer in and out should be at least len bytes, while len shoule be multiples of 16
 * 
 * in and out can be the same buffer, while encrypt or decrypt method will be conducted in place
 *
***/

void sm4_encrypt(unsigned char *in, unsigned char *out, int len, unsigned char key[16]);

void sm4_decrypt(unsigned char *in, unsigned char *out, int len, unsigned char key[16]);

#ifdef __cplusplus
}
#endif

#endif