/*
* Description: SM2 encryption and signature algorithm
* Author: Mike
* Date: 2018-03-09
*/

#include <string>
#include "sm2.h"
#include "sm3.h"
#include "rand.h"

unsigned int minus_p[SM2_LEN];
unsigned int minus_n[SM2_LEN];
int init_minus_p()
{
	for (int i = 0; i < SM2_LEN; i++)
	{
		minus_p[i] = ~p[i];
		minus_n[i] = ~n[i];
	}
	minus_p[SM2_LEN - 1]++;
	minus_n[SM2_LEN - 1]++;
	return 1;
}
int zzz = init_minus_p();

static unsigned int zero[SM2_LEN] = { 0 };
static unsigned int one[SM2_LEN] = { 0, 0, 0, 0, 0, 0, 0, 1 };

typedef struct
{
	unsigned int x[SM2_LEN];
	unsigned int y[SM2_LEN];
} CurvePoint;

bool equal(unsigned int in1[SM2_LEN], unsigned int in2[SM2_LEN])
{
	for (int i = 0; i < SM2_LEN; i++)
	{
		if (in1[i] != in2[i])
			return false;
	}
	return true;
}

bool greater(unsigned int in1[SM2_LEN], unsigned int in2[SM2_LEN])
{
	for (int i = 0; i < SM2_LEN; i++)
	{
		if (in1[i] > in2[i])
			return true;
		else if (in1[i] < in2[i])
			return false;
	}
	return false;
}

/***
* NOTICE: all input arguments of add, sub, mul, inv, div should be smaller than p
***/

void sub(unsigned int in1[SM2_LEN], unsigned int in2[SM2_LEN], unsigned int out[SM2_LEN]);

/* in1 + in2 กิ out (mod p) */
void add(unsigned int in1[SM2_LEN], unsigned int in2[SM2_LEN], unsigned int out[SM2_LEN])
{
	int i = SM2_LEN;
	bool carry1, carry2 = false;
	while (--i >= 0)
	{
		carry1 = carry2 ? in1[i] >= ~in2[i] : in1[i] > ~in2[i];
		out[i] = in1[i] + in2[i] + (carry2 ? 1 : 0);
		carry2 = carry1;
	}
	if (carry2)
		add(out, minus_p, out);
	else if (!greater(p, out))
		sub(out, p, out);
}

/* in1 - in2 กิ out (mod p) */
void sub(unsigned int in1[SM2_LEN], unsigned int in2[SM2_LEN], unsigned int out[SM2_LEN])
{
	int i = SM2_LEN;
	unsigned int temp[SM2_LEN];
	bool carry1, carry2 = false;
	if (!greater(in2, in1))
	{
		while (--i >= 0)
		{
			carry1 = carry2 ? in1[i] <= in2[i] : in1[i] < in2[i];
			out[i] = in1[i] - in2[i] - (carry2 ? 1 : 0);
			carry2 = carry1;
		}
	}
	else
	{
		sub(p, in2, temp);
		add(in1, temp, out);
	}
}

/* in1 กม in2 กิ out (mod p) */
void mul(unsigned int in1[SM2_LEN], unsigned int in2[SM2_LEN], unsigned int out[SM2_LEN])
{
	int i, j;
	unsigned int temp[SM2_LEN] = { 0 };
	for (i = 0; i < SM2_LEN; i++)
	{
		for (j = 31; j >= 0; j--)
		{
			add(temp, temp, temp);
			if (in1[i] & 1 << j)
				add(temp, in2, temp);
		}
	}
	memcpy(out, temp, SM2_LEN * 4);
}

/* in1 กม in2 กิ out (mod p) */
void mul(int in1, unsigned int in2[SM2_LEN], unsigned int out[SM2_LEN])
{
	unsigned int temp[SM2_LEN] = { 0 };
	bool neg = in1 < 0;
	if (neg)
		in1 = -in1;
	for (int i = 30; i >= 0; i--)
	{
		add(temp, temp, temp);
		if (in1 & 1 << i)
			add(temp, in2, temp);
	}
	if (neg)
		sub(zero, temp, temp);
	memcpy(out, temp, SM2_LEN * 4);
}

void leftshift(unsigned int in[SM2_LEN], unsigned int out[SM2_LEN], int s)
{
	int i, j, k;
	j = s / 32;
	k = s % 32;
	unsigned int temp[SM2_LEN] = { 0 };
	if (k == 0)
	{
		memcpy(temp, in + j, (SM2_LEN - j) * 4);
		memcpy(out, temp, SM2_LEN * 4);
		return;
	}
	for (i = 0; i < SM2_LEN - j; i++)
		temp[i] = in[i + j] << k;
	for (i = 0; i < SM2_LEN - j - 1; i++)
		temp[i] += in[i + j + 1] >> (32 - k);
	memcpy(out, temp, SM2_LEN * 4);
}

/* in1 = in2 กม out_s + out_r */
void div(unsigned int in1[SM2_LEN], unsigned int in2[SM2_LEN], unsigned int out_s[SM2_LEN], unsigned int out_r[SM2_LEN])
{
	int i = 0, j, k;
	unsigned int temp_in1[SM2_LEN];
	unsigned int temp_in2[SM2_LEN];
	unsigned int temp_s[SM2_LEN] = { 0 };
	memcpy(temp_in1, in1, SM2_LEN * 4);
	while (true)
	{
		j = i / 32;
		k = 31 - i % 32;
		if (in2[j] & 1 << k)
			break;
		i++;
	}
	for (j = i; j >= 0; j--)
	{
		leftshift(in2, temp_in2, j);
		if (!greater(temp_in2, temp_in1))
		{
			temp_s[SM2_LEN - j / 32 - 1] |= 1 << (j % 32);
			sub(temp_in1, temp_in2, temp_in1);
		}
	}
	memcpy(out_s, temp_s, SM2_LEN * 4);
	memcpy(out_r, temp_in1, SM2_LEN * 4);
}

/* in กม out กิ 1 (mod p) */
void inv(unsigned int in[SM2_LEN], unsigned int out[SM2_LEN])
{
	unsigned int temp1[SM2_LEN];
	unsigned int temp2[SM2_LEN];
	unsigned int temp_s[SM2_LEN];
	unsigned int temp_r[SM2_LEN];
	unsigned int temp_c1[SM2_LEN] = { 0 };
	unsigned int temp_c2[SM2_LEN] = { 0, 0, 0, 0, 0, 0, 0, 1 };
	memcpy(temp1, p, SM2_LEN * 4);
	memcpy(temp2, in, SM2_LEN * 4);
	while (!equal(temp2, one))
	{
		div(temp1, temp2, temp_s, temp_r);
		memcpy(temp1, temp2, SM2_LEN * 4);
		memcpy(temp2, temp_r, SM2_LEN * 4);
		memcpy(temp_r, temp_c2, SM2_LEN * 4);
		mul(temp_c2, temp_s, temp_c2);
		sub(temp_c1, temp_c2, temp_c2);
		memcpy(temp_c1, temp_r, SM2_LEN * 4);
	}
	memcpy(out, temp_c2, SM2_LEN * 4);
}

/* in1 กม inv(in2) กิ out (mod p) */
void div(unsigned int in1[SM2_LEN], unsigned int in2[SM2_LEN], unsigned int out[SM2_LEN])
{
	unsigned int temp[SM2_LEN];
	inv(in2, temp);
	mul(in1, temp, out);
}

bool infinite(CurvePoint *in)
{
	return equal(in->x, zero) && equal(in->y, zero);
}

void add_point(CurvePoint *in1, CurvePoint *in2, CurvePoint *out)
{
	unsigned int lambda[SM2_LEN];
	unsigned int temp[SM2_LEN];
	unsigned int out_x[SM2_LEN];
	unsigned int out_y[SM2_LEN];
	if (infinite(in1))
	{
		memcpy(out, in2, sizeof(CurvePoint));
		return;
	}
	if (infinite(in2))
	{
		memcpy(out, in1, sizeof(CurvePoint));
		return;
	}
	if (equal(in1->x, in2->x))
	{
		add(in1->y, in2->y, temp);
		if (equal(temp, zero))
		{
			memset(out, 0, sizeof(CurvePoint));
			return;
		}
		mul(in1->x, in1->x, lambda);
		mul(3, lambda, lambda);
		add(lambda, a, lambda);
		mul(2, in1->y, temp);
		div(lambda, temp, lambda);
	}
	else
	{
		sub(in2->y, in1->y, lambda);
		sub(in2->x, in1->x, temp);
		div(lambda, temp, lambda);
	}
	mul(lambda, lambda, out_x);
	sub(out_x, in1->x, out_x);
	sub(out_x, in2->x, out_x);
	sub(in1->x, out_x, out_y);
	mul(lambda, out_y, out_y);
	sub(out_y, in1->y, out_y);
	memcpy(out->x, out_x, SM2_LEN * 4);
	memcpy(out->y, out_y, SM2_LEN * 4);
}

void mul_point(unsigned int in1[SM2_LEN], CurvePoint *in2, CurvePoint *out)
{
	int i, j;
	CurvePoint *temp = new CurvePoint;
	memset(temp, 0, sizeof(CurvePoint));
	for (i = 0; i < SM2_LEN; i++)
	{
		for (j = 31; j >= 0; j--)
		{
			add_point(temp, temp, temp);
			if (in1[i] & 1 << j)
				add_point(temp, in2, temp);
		}
	}
	memcpy(out, temp, sizeof(CurvePoint));
	delete temp;
}

void ChangeByteOrder(unsigned char *in, unsigned char *out, int len)
{
	int i, j;
	unsigned char *temp = (unsigned char*)malloc(len * 4);
	for (i = 0; i < len; i++)
	{
		for (j = 0; j < 4; j++)
		{
			temp[i * 4 + j] = in[i * 4 + 3 - j];
		}
	}
	memcpy(out, temp, len * 4);
	free(temp);
}

int sm2_get_public_key(unsigned char dB[SM2_LEN * 4], unsigned char PB[SM2_LEN * 8 + 1])
{
	unsigned int dB_[SM2_LEN];
	ChangeByteOrder(dB, (unsigned char*)dB_, SM2_LEN);
	if (equal(dB_, zero))
		return SM2_PRIVATE_KEY_ERROR;
	if (!greater(n, dB_))
		return SM2_PRIVATE_KEY_ERROR;
	CurvePoint *PB_ = new CurvePoint;
	memcpy(PB_->x, Gx, SM2_LEN * 4);
	memcpy(PB_->y, Gy, SM2_LEN * 4);
	mul_point(dB_, PB_, PB_);
	PB[0] = 0x04;
	ChangeByteOrder((unsigned char*)PB_, PB + 1, SM2_LEN * 2);
	delete PB_;
	return SM2_SUCCESS;
}

void sm2_create_key(unsigned char dB[SM2_LEN * 4], unsigned char PB[SM2_LEN * 8 + 1])
{
	do
	{
		sm3_rand(dB, SM2_LEN * 4);
	} while (sm2_get_public_key(dB, PB) != SM2_SUCCESS);
}

void KDF(CurvePoint *in, unsigned char *out, int len)
{
	int i, j;
	unsigned char temp[8 * SM2_LEN + 4];
	ChangeByteOrder((unsigned char*)in, temp, SM2_LEN * 2);
	for (i = 1; i <= len / 32; i++)
	{
		for (j = 0; j < 4; j++)
		{
			temp[8 * SM2_LEN + j] = *((unsigned char*)&i + 3 - j);
		}
		sm3_bytes(temp, (8 * SM2_LEN + 4) * 8, out + (i - 1) * 32);
	}
	if (len % 32)
	{
		for (j = 0; j < 4; j++)
		{
			temp[8 * SM2_LEN + j] = *((unsigned char*)&i + 3 - j);
		}
		unsigned char temp2[32];
		sm3_bytes(temp, (8 * SM2_LEN + 4) * 8, temp2);
		memcpy(out + (i - 1) * 32, temp2, len % 32);
	}
}

int sm2_encrypt2(unsigned char *in, int len, unsigned char *out, unsigned char PB[SM2_LEN * 8 + 1], unsigned char k[SM2_LEN * 4])
{
	CurvePoint *PB_ = new CurvePoint;
	ChangeByteOrder(PB + 1, (unsigned char*)PB_, SM2_LEN * 2);
	if (!greater(p, PB_->x))
	{
		delete PB_;
		return SM2_PUBLIC_KEY_ERROR;
	}
	if (!greater(p, PB_->y))
	{
		delete PB_;
		return SM2_PUBLIC_KEY_ERROR;
	}
	unsigned int k_[SM2_LEN];
	ChangeByteOrder(k, (unsigned char*)k_, SM2_LEN);
	if (equal(k_, zero))
		return SM2_RANDOM_NUMBER_ERROR;
	if (!greater(n, k_))
		return SM2_RANDOM_NUMBER_ERROR;
	CurvePoint *point = new CurvePoint;
	unsigned char C1[SM2_LEN * 8 + 1];
	unsigned char *C2 = (unsigned char*)malloc(len);
	unsigned char C3[32];
	unsigned char *temp = (unsigned char*)malloc(len + SM2_LEN * 8);
	//get C1
	C1[0] = 0x04;
	memcpy(point->x, Gx, SM2_LEN * 4);
	memcpy(point->y, Gy, SM2_LEN * 4);
	mul_point(k_, point, point);	//get [k]G
	ChangeByteOrder((unsigned char*)point, C1 + 1, SM2_LEN * 2);
	//get C2
	mul_point(k_, PB_, point);		//get [k]PB
	KDF(point, C2, len);
	for (int i = 0; i < len; i++)
	{
		C2[i] ^= in[i];
	}
	//get C3
	ChangeByteOrder((unsigned char*)(point->x), temp, SM2_LEN);
	memcpy(temp + SM2_LEN * 4, in, len);
	ChangeByteOrder((unsigned char*)(point->y), temp + SM2_LEN * 4 + len, SM2_LEN);
	sm3_bytes(temp, (len + SM2_LEN * 8) * 8, C3);
	//joint C1, C2, C3
	memcpy(out, C1, SM2_LEN * 8 + 1);
	memcpy(out + SM2_LEN * 8 + 1, C2, len);
	memcpy(out + SM2_LEN * 8 + 1 + len, C3, 32);
	delete PB_;
	delete point;
	free(C2);
	free(temp);
	return SM2_SUCCESS;
}

int sm2_encrypt(unsigned char *in, int len, unsigned char *out, unsigned char PB[SM2_LEN * 8 + 1])
{
	CurvePoint *PB_ = new CurvePoint;
	ChangeByteOrder(PB + 1, (unsigned char*)PB_, SM2_LEN * 2);
	if (!greater(p, PB_->x))
	{
		delete PB_;
		return SM2_PUBLIC_KEY_ERROR;
	}
	if (!greater(p, PB_->y))
	{
		delete PB_;
		return SM2_PUBLIC_KEY_ERROR;
	}
	delete PB_;
	unsigned char k[SM2_LEN * 4];
	do
	{
		sm3_rand(k, SM2_LEN * 4);
	} while (sm2_encrypt2(in, len, out, PB, k) != SM2_SUCCESS);
	return SM2_SUCCESS;
}

int sm2_decrypt(unsigned char *in, int len, unsigned char *out, unsigned char dB[SM2_LEN * 4])
{
	unsigned int dB_[SM2_LEN];
	ChangeByteOrder(dB, (unsigned char*)dB_, SM2_LEN);
	if (equal(dB_, zero))
		return SM2_PRIVATE_KEY_ERROR;
	if (!greater(n, dB_))
		return SM2_PRIVATE_KEY_ERROR;
	CurvePoint *point = new CurvePoint;
	unsigned char *temp = (unsigned char*)malloc(len - 33);
	unsigned char C3[32];
	ChangeByteOrder(in + 1, (unsigned char*)point, SM2_LEN * 2);	//get [k]G from C1
	mul_point(dB_, point, point);	//get [dB][k]G = [k][dB]G = [k]PB
	//get plain text
	KDF(point, out, len - SM2_LEN * 8 - 33);
	for (int i = 0; i < len - SM2_LEN * 8 - 33; i++)
	{
		out[i] ^= in[i + SM2_LEN * 8 + 1];
	}
	//verify
	ChangeByteOrder((unsigned char*)(point->x), temp, SM2_LEN);
	memcpy(temp + SM2_LEN * 4, out, len - SM2_LEN * 8 - 33);
	ChangeByteOrder((unsigned char*)(point->y), temp + len - SM2_LEN * 4 - 33, SM2_LEN);
	sm3_bytes(temp, (len - 33) * 8, C3);
	delete point;
	free(temp);
	return equal((unsigned int*)C3, (unsigned int*)(in + len - 32)) ? SM2_SUCCESS : SM2_FAIL;
}


/***
* NOTICE: all input arguments of add2, sub2, mul2, inv2, div2 should be smaller than n
***/

void sub2(unsigned int in1[SM2_LEN], unsigned int in2[SM2_LEN], unsigned int out[SM2_LEN]);

/* in1 + in2 กิ out (mod n) */
void add2(unsigned int in1[SM2_LEN], unsigned int in2[SM2_LEN], unsigned int out[SM2_LEN])
{
	int i = SM2_LEN;
	bool carry1, carry2 = false;
	while (--i >= 0)
	{
		carry1 = carry2 ? in1[i] >= ~in2[i] : in1[i] > ~in2[i];
		out[i] = in1[i] + in2[i] + (carry2 ? 1 : 0);
		carry2 = carry1;
	}
	if (carry2)
		add2(out, minus_n, out);
	else if (!greater(n, out))
		sub2(out, n, out);
}

/* in1 - in2 กิ out (mod n) */
void sub2(unsigned int in1[SM2_LEN], unsigned int in2[SM2_LEN], unsigned int out[SM2_LEN])
{
	int i = SM2_LEN;
	unsigned int temp[SM2_LEN];
	bool carry1, carry2 = false;
	if (!greater(in2, in1))
	{
		while (--i >= 0)
		{
			carry1 = carry2 ? in1[i] <= in2[i] : in1[i] < in2[i];
			out[i] = in1[i] - in2[i] - (carry2 ? 1 : 0);
			carry2 = carry1;
		}
	}
	else
	{
		sub2(n, in2, temp);
		add2(in1, temp, out);
	}
}

/* in1 กม in2 กิ out (mod n) */
void mul2(unsigned int in1[SM2_LEN], unsigned int in2[SM2_LEN], unsigned int out[SM2_LEN])
{
	int i, j;
	unsigned int temp[SM2_LEN] = { 0 };
	for (i = 0; i < SM2_LEN; i++)
	{
		for (j = 31; j >= 0; j--)
		{
			add2(temp, temp, temp);
			if (in1[i] & 1 << j)
				add2(temp, in2, temp);
		}
	}
	memcpy(out, temp, SM2_LEN * 4);
}

/* in1 กม in2 กิ out (mod n) */
void mul2(int in1, unsigned int in2[SM2_LEN], unsigned int out[SM2_LEN])
{
	unsigned int temp[SM2_LEN] = { 0 };
	bool neg = in1 < 0;
	if (neg)
		in1 = -in1;
	for (int i = 30; i >= 0; i--)
	{
		add2(temp, temp, temp);
		if (in1 & 1 << i)
			add2(temp, in2, temp);
	}
	if (neg)
		sub2(zero, temp, temp);
	memcpy(out, temp, SM2_LEN * 4);
}

/* in กม out กิ 1 (mod n) */
void inv2(unsigned int in[SM2_LEN], unsigned int out[SM2_LEN])
{
	unsigned int temp1[SM2_LEN];
	unsigned int temp2[SM2_LEN];
	unsigned int temp_s[SM2_LEN];
	unsigned int temp_r[SM2_LEN];
	unsigned int temp_c1[SM2_LEN] = { 0 };
	unsigned int temp_c2[SM2_LEN] = { 0, 0, 0, 0, 0, 0, 0, 1 };
	memcpy(temp1, n, SM2_LEN * 4);
	memcpy(temp2, in, SM2_LEN * 4);
	while (!equal(temp2, one))
	{
		div(temp1, temp2, temp_s, temp_r);
		memcpy(temp1, temp2, SM2_LEN * 4);
		memcpy(temp2, temp_r, SM2_LEN * 4);
		memcpy(temp_r, temp_c2, SM2_LEN * 4);
		mul2(temp_c2, temp_s, temp_c2);
		sub2(temp_c1, temp_c2, temp_c2);
		memcpy(temp_c1, temp_r, SM2_LEN * 4);
	}
	memcpy(out, temp_c2, SM2_LEN * 4);
}

/* in1 กม inv2(in2) กิ out (mod n) */
void div2(unsigned int in1[SM2_LEN], unsigned int in2[SM2_LEN], unsigned int out[SM2_LEN])
{
	unsigned int temp[SM2_LEN];
	inv2(in2, temp);
	mul2(in1, temp, out);
}

int sm2_signature2(unsigned char *IDA, int IDA_len, unsigned char *message, int message_len, unsigned char *out, unsigned char dA[SM2_LEN * 4], unsigned char k[SM2_LEN * 4])
{
	unsigned int dA_[SM2_LEN];
	ChangeByteOrder(dA, (unsigned char*)dA_, SM2_LEN);
	if (equal(dA_, zero))
		return SM2_PRIVATE_KEY_ERROR;
	if (!greater(n, dA_))
		return SM2_PRIVATE_KEY_ERROR;
	unsigned int k_[SM2_LEN];
	ChangeByteOrder(k, (unsigned char*)k_, SM2_LEN);
	if (equal(k_, zero))
		return SM2_RANDOM_NUMBER_ERROR;
	if (!greater(n, k_))
		return SM2_RANDOM_NUMBER_ERROR;
	unsigned char *str = (unsigned char*)malloc(2 + IDA_len + SM2_LEN * 24);
	int entlenA = IDA_len * 8;
	str[0] = entlenA / 0x100;
	str[1] = entlenA % 0x100;
	memcpy(str + 2, IDA, IDA_len);
	unsigned char str2[SM2_LEN * 8];
	ChangeByteOrder((unsigned char*)a, str2, SM2_LEN);
	memcpy(str + 2 + IDA_len, str2, SM2_LEN * 4);
	ChangeByteOrder((unsigned char*)b, str2, SM2_LEN);
	memcpy(str + 2 + IDA_len + SM2_LEN * 4, str2, SM2_LEN * 4);
	ChangeByteOrder((unsigned char*)Gx, str2, SM2_LEN);
	memcpy(str + 2 + IDA_len + SM2_LEN * 8, str2, SM2_LEN * 4);
	ChangeByteOrder((unsigned char*)Gy, str2, SM2_LEN);
	memcpy(str + 2 + IDA_len + SM2_LEN * 12, str2, SM2_LEN * 4);
	CurvePoint *point = new CurvePoint;
	memcpy(point->x, Gx, SM2_LEN * 4);
	memcpy(point->y, Gy, SM2_LEN * 4);
	mul_point(dA_, point, point);
	ChangeByteOrder((unsigned char*)point, str2, SM2_LEN * 2);
	memcpy(str + 2 + IDA_len + SM2_LEN * 16, str2, SM2_LEN * 8);
	unsigned char ZA[32];
	sm3_bytes(str, (2 + IDA_len + SM2_LEN * 24) * 8, ZA);
	free(str);
	str = (unsigned char*)malloc(32 + message_len);
	memcpy(str, ZA, 32);
	memcpy(str + 32, message, message_len);
	unsigned int e[SM2_LEN];
	sm3_bytes(str, (32 + message_len) * 8, (unsigned char*)e);
	free(str);
	ChangeByteOrder((unsigned char*)e, (unsigned char*)e, SM2_LEN);
	memcpy(point->x, Gx, SM2_LEN * 4);
	memcpy(point->y, Gy, SM2_LEN * 4);
	mul_point(k_, point, point);
	unsigned int r[SM2_LEN];
	add2(e, point->x, r);
	delete point;
	if (equal(r, zero))
		return SM2_RANDOM_NUMBER_IMPROPER;
	unsigned int temp[SM2_LEN];
	add2(r, k_, temp);
	if (equal(temp, zero))
		return SM2_RANDOM_NUMBER_IMPROPER;
	unsigned int s[SM2_LEN];
	add2(one, dA_, s);
	inv2(s, s);
	mul2(r, dA_, temp);
	sub2(k_, temp, temp);
	mul2(s, temp, s);
	if (equal(s, zero))
		return SM2_RANDOM_NUMBER_IMPROPER;
	ChangeByteOrder((unsigned char*)r, out, SM2_LEN);
	ChangeByteOrder((unsigned char*)s, out + SM2_LEN * 4, SM2_LEN);
	return SM2_SUCCESS;
}

int sm2_signature(unsigned char *IDA, int IDA_len, unsigned char *message, int message_len, unsigned char *out, unsigned char dA[SM2_LEN * 4])
{
	unsigned int dA_[SM2_LEN];
	ChangeByteOrder(dA, (unsigned char*)dA_, SM2_LEN);
	if (equal(dA_, zero))
		return SM2_PRIVATE_KEY_ERROR;
	if (!greater(n, dA_))
		return SM2_PRIVATE_KEY_ERROR;
	unsigned char k[SM2_LEN * 4];
	do
	{
		sm3_rand(k, SM2_LEN * 4);
	} while (sm2_signature2(IDA, IDA_len, message, message_len, out, dA, k) != SM2_SUCCESS);
	return SM2_SUCCESS;
}

int sm2_verify(unsigned char *IDA, int IDA_len, unsigned char *message, int message_len, unsigned char *signature, unsigned char PA[SM2_LEN * 8 + 1])
{
	CurvePoint *PA_ = new CurvePoint;
	ChangeByteOrder(PA + 1, (unsigned char*)PA_, SM2_LEN * 2);
	if (!greater(p, PA_->x))
	{
		delete PA_;
		return SM2_PUBLIC_KEY_ERROR;
	}
	if (!greater(p, PA_->y))
	{
		delete PA_;
		return SM2_PUBLIC_KEY_ERROR;
	}
	unsigned int r[SM2_LEN];
	ChangeByteOrder(signature, (unsigned char*)r, SM2_LEN);
	if (equal(r, zero))
		return SM2_FAIL;
	if (!greater(n, r))
		return SM2_FAIL;
	unsigned int s[SM2_LEN];
	ChangeByteOrder(signature + SM2_LEN * 4, (unsigned char*)s, SM2_LEN);
	if (equal(s, zero))
		return SM2_FAIL;
	if (!greater(n, s))
		return SM2_FAIL;
	unsigned char *str = (unsigned char*)malloc(2 + IDA_len + SM2_LEN * 24);
	int entlenA = IDA_len * 8;
	str[0] = entlenA / 0x100;
	str[1] = entlenA % 0x100;
	memcpy(str + 2, IDA, IDA_len);
	unsigned char str2[SM2_LEN * 8];
	ChangeByteOrder((unsigned char*)a, str2, SM2_LEN);
	memcpy(str + 2 + IDA_len, str2, SM2_LEN * 4);
	ChangeByteOrder((unsigned char*)b, str2, SM2_LEN);
	memcpy(str + 2 + IDA_len + SM2_LEN * 4, str2, SM2_LEN * 4);
	ChangeByteOrder((unsigned char*)Gx, str2, SM2_LEN);
	memcpy(str + 2 + IDA_len + SM2_LEN * 8, str2, SM2_LEN * 4);
	ChangeByteOrder((unsigned char*)Gy, str2, SM2_LEN);
	memcpy(str + 2 + IDA_len + SM2_LEN * 12, str2, SM2_LEN * 4);
	ChangeByteOrder((unsigned char*)PA_, str2, SM2_LEN * 2);
	memcpy(str + 2 + IDA_len + SM2_LEN * 16, str2, SM2_LEN * 8);
	unsigned char ZA[32];
	sm3_bytes(str, (2 + IDA_len + SM2_LEN * 24) * 8, ZA);
	free(str);
	str = (unsigned char*)malloc(32 + message_len);
	memcpy(str, ZA, 32);
	memcpy(str + 32, message, message_len);
	unsigned int e[SM2_LEN];
	sm3_bytes(str, (32 + message_len) * 8, (unsigned char*)e);
	free(str);
	ChangeByteOrder((unsigned char*)e, (unsigned char*)e, SM2_LEN);
	unsigned int t[SM2_LEN];
	add2(r, s, t);
	if (equal(t, zero))
		return SM2_FAIL;
	CurvePoint *point = new CurvePoint;
	memcpy(point->x, Gx, SM2_LEN * 4);
	memcpy(point->y, Gy, SM2_LEN * 4);
	mul_point(s, point, point);
	mul_point(t, PA_, PA_);
	add_point(point, PA_, point);
	unsigned int R[SM2_LEN];
	add2(e, point->x, R);
	delete PA_;
	delete point;
	return equal(R, r) ? SM2_SUCCESS : SM2_FAIL;
}