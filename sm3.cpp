/*
* Description: SM3 hash algorithm
* Author: Mike
* Date: 2017-07-02
*/

#include <stdio.h>
#include <string.h>
#include "sm3.h"

#define ULONG_CONVERT_ENDIAN(ul)	( (ul) << 24 | ((ul) & 0xFF00) << 8 | ((ul) & 0xFF0000) >> 8 | (ul) >> 24 )
#define ROL(x, k)		( (x) << ((k) & 0x1F) | (x) >> (32 - (k) & 0x1F) )

#define IV				{ 0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e }
#define T(j)			( (j) < 16 ? 0x79cc4519 : 0x7a879d8a )
#define FF(j, X, Y, Z)	( (j) < 16 ? (X) ^ (Y) ^ (Z) : ((X) & (Y)) | ((X) & (Z)) | ((Y) & (Z)) )
#define GG(j, X, Y, Z)	( (j) < 16 ? (X) ^ (Y) ^ (Z) : ((X) & (Y)) | (~(X) & (Z)) )
#define P0(X)			( (X) ^ ROL((X), 9) ^ ROL((X), 17) )
#define P1(X)			( (X) ^ ROL((X), 15) ^ ROL((X), 23) )

/* compression function for block */
void CF(unsigned long Vi[8], unsigned char Bi[64])
{
	int j;
	unsigned long W[68];
	unsigned long W_[64];
	unsigned long A = Vi[0];
	unsigned long B = Vi[1];
	unsigned long C = Vi[2];
	unsigned long D = Vi[3];
	unsigned long E = Vi[4];
	unsigned long F = Vi[5];
	unsigned long G = Vi[6];
	unsigned long H = Vi[7];
	unsigned long SS1, SS2, TT1, TT2;
	for (j = 0; j < 16; j++)
	{
		W[j] = ULONG_CONVERT_ENDIAN(*((unsigned long*)Bi + j));
	}
	for (j = 16; j < 68; j++)
	{
		W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROL(W[j - 3], 15)) ^ ROL(W[j - 13], 7) ^ W[j - 6];
	}
	for (j = 0; j < 64; j++)
	{
		W_[j] = W[j] ^ W[j + 4];
	}
	for (j = 0; j < 64; j++)
	{
		SS1 = ROL(ROL(A, 12) + E + ROL(T(j), j), 7);
		SS2 = SS1 ^ ROL(A, 12);
		TT1 = FF(j, A, B, C) + D + SS2 + W_[j];
		TT2 = GG(j, E, F, G) + H + SS1 + W[j];
		D = C;
		C = ROL(B, 9);
		B = A;
		A = TT1;
		H = G;
		G = ROL(F, 19);
		F = E;
		E = P0(TT2);
	}
	Vi[0] ^= A;
	Vi[1] ^= B;
	Vi[2] ^= C;
	Vi[3] ^= D;
	Vi[4] ^= E;
	Vi[5] ^= F;
	Vi[6] ^= G;
	Vi[7] ^= H;
}

/* SM3 hash function for bytes input */
void sm3_bytes(unsigned char *input, int len, unsigned char output[32])
{
	unsigned long V[8] = IV;
	unsigned char padding[64] = { 0 };
	int off = 0;
	while (off * 8 + 512 <= len)
	{
		CF(V, input + off);
		off += 64;
	}
	int r = (len % 512) / 8;
	int s = (len % 512) % 8;
	memcpy(padding, input + off, r);
	off += r;
	if (s == 0)
	{
		padding[r] = 0x80;
	}
	else
	{
		padding[r] = input[off] & (0xFF << (8 - s)) | (1 << (7 - s));
	}
	r++;
	if (r > 56)
	{
		CF(V, padding);
		memset(padding, 0, 64);
	}
	*((unsigned long*)padding + 15) = ULONG_CONVERT_ENDIAN(len);
	CF(V, padding);
	for (int i = 0; i < 8; i++)
	{
		*((unsigned long*)output + i) = ULONG_CONVERT_ENDIAN(V[i]);
	}
}

/* SM3 hash function for string input */
void sm3_string(char *input, unsigned char output[32])
{
	int len = strlen(input) * 8;
	sm3_bytes((unsigned char*)input, len, output);
}

/* SM3 hash function for file input */
int sm3_file(char *path, unsigned char output[32])
{
	int off;
	unsigned long long len = 0;
	unsigned long V[8] = IV;
	unsigned char padding[64] = { 0 };
	unsigned char buf[4096];
	FILE *f;
	size_t n;
	if ((f = fopen(path, "rb")) == NULL)
	{
		return 2;
	}
	while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
	{
		if (ferror(f) != 0)
		{
			fclose(f);
			return ferror(f);
		}
		len += n * 8;
		if (n == sizeof(buf))
		{
			off = 0;
			while (off <= (int)n - 64)
			{
				CF(V, buf + off);
				off += 64;
			}
		}
		else
		{
			break;
		}
	}
	if (ferror(f) != 0)
	{
		fclose(f);
		return ferror(f);
	}
	fclose(f);
	off = 0;
	while (off <= (int)n - 64)
	{
		CF(V, buf + off);
		off += 64;
	}
	int r = n - off;
	memcpy(padding, buf + off, r);
	padding[r] = 0x80;
	r++;
	if (r > 56)
	{
		CF(V, padding);
		memset(padding, 0, 64);
	}
	*((unsigned long*)padding + 14) = ULONG_CONVERT_ENDIAN(len >> 32);
	*((unsigned long*)padding + 15) = ULONG_CONVERT_ENDIAN(len & 0xFFFFFFFF);
	CF(V, padding);
	for (int i = 0; i < 8; i++)
	{
		*((unsigned long*)output + i) = ULONG_CONVERT_ENDIAN(V[i]);
	}
	return 0;
}