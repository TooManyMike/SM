#ifndef RAND_H
#define RAND_H

#ifdef __cplusplus
extern "C" {
#endif

/* generate random number of given length */
void sm3_rand(unsigned char* out, int len);

#ifdef __cplusplus
}
#endif

#endif