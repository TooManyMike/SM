#include <Windows.h>
#include "rand.h"
#include "sm3.h"

inline unsigned __int64 GetTimeStamp()
{
	__asm _emit 0x0F
	__asm _emit 0x31
}

void rand_seed(unsigned char* out, int len)
{
	unsigned __int64 *t = (unsigned __int64*)malloc((8 * len + 1) * sizeof(unsigned __int64));
	int i = 8 * len + 1, j;
	while (--i >= 0)
	{
		Sleep(1);
		t[i] = GetTimeStamp();
	}
	for (i = 0; i < len; i++)
	{
		out[i] = 0;
		for (j = 0; j < 8; j++)
		{
			out[i] |= (((t[8 * i + j] - t[8 * i + j + 1]) & 1) << j);
		}
	}
	free(t);
}

void sm3_rand(unsigned char* out, int len)
{
	unsigned char seed[9];
	rand_seed(seed, 8);
	int i;
	for (i = 0; i < len / 32; i++)
	{
		seed[8] = i;
		sm3_bytes(seed, 72, out + i * 32);
	}
	if (len % 32)
	{
		unsigned char temp[32];
		sm3_bytes(seed, 9, temp);
		memcpy(out + i * 32, temp, len % 32);
	}
}