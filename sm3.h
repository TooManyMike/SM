/*
 * Description: SM3 hash algorithm
 * Author: Mike
 * Date: 2017-07-02
 */

#ifndef SM3_H
#define SM3_H

#ifdef __cplusplus
extern "C" {
#endif

/***
* SM3 hash function for bytes input
* NOTICE: parameter len is the number of bits
***/
void sm3_bytes(unsigned char *input, int len, unsigned char output[32]);

/* SM3 hash function for string input */
void sm3_string(char *input, unsigned char output[32]);

/* SM3 hash function for file input */
int sm3_file(char *path, unsigned char output[32]);

#ifdef __cplusplus
}
#endif

#endif