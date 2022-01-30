#include "crypto.h"

#define AES_BLOCK_BYTES 16
#define AES_BLOCK_WORDS (AES_BLOCK_BYTES / sizeof(DWORD))
#define ROR32(v, n)  ( (v) << (32 - n) | (v) >> n )

static const BYTE AesKeyV4[] = { 0x05, 0x3D, 0x83, 0x07, 0xF9, 0xE5, 0xF0, 0x88, 0xEB, 0x5E, 0xA6, 0x68, 0x6C, 0xF0, 0x37, 0xC7, 0xE4, 0xEF, 0xD2, 0xD6 };
static const BYTE AesKeyV5[] = { 0xCD, 0x7E, 0x79, 0x6F, 0x2A, 0xB2, 0x5D, 0xCB, 0x55, 0xFF, 0xC8, 0xEF, 0x83, 0x64, 0xC4, 0x70 };
static const BYTE AesKeyV6[] = { 0xA9, 0x4A, 0x41, 0x95, 0xE2, 0x01, 0x43, 0x2D, 0x9B, 0xCB, 0x46, 0x04, 0x05, 0xD8, 0x4A, 0x21 };

static const BYTE SBox[] = {
  0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
  0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
  0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
  0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
  0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
  0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
  0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
  0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
  0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
  0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
  0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
  0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
  0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
  0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
  0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
  0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

void XorBlock(const BYTE* const in, const BYTE* out) // Ensure that this is always 32 bit aligned
{
	for (BYTE i = 0; i < AES_BLOCK_WORDS; i++) ((DWORD*)out)[i] ^= ((DWORD*)in)[i];
}

#define AddRoundKey(d, rk) XorBlock((const BYTE *)rk, (const BYTE *)d)

#define Mul2(word) (((word & 0x7f7f7f7f) << 1) ^ (((word & 0x80808080) >> 7) * 0x1b))
#define Mul3(word) (Mul2(word) ^ word)
#define Mul4(word) (Mul2(Mul2(word)))
#define Mul8(word) (Mul2(Mul2(Mul2(word))))
#define Mul9(word) (Mul8(word) ^ word)
#define MulB(word) (Mul8(word) ^ Mul3(word))
#define MulD(word) (Mul8(word) ^ Mul4(word) ^ word)
#define MulE(word) (Mul8(word) ^ Mul4(word) ^ Mul2(word))

void MixColumnsR(BYTE* state)
{
	for (BYTE i = 0; i < AES_BLOCK_WORDS; i++)
	{
		DWORD word = ((DWORD*)state)[i];
		((DWORD*)state)[i] = MulE(word) ^ ROR32(MulB(word), 8) ^ ROR32(MulD(word), 16) ^ ROR32(Mul9(word), 24);
	}
}

DWORD SubDword(DWORD v)
{
	BYTE* b = (BYTE*)&v;
	for (BYTE i = 0; i < sizeof(DWORD); i++) b[i] = SBox[b[i]];
	return v;
}

int AesInitKey(AesCtx* context, const int version)
{
	const BYTE* Key = NULL;
	int RijndaelKeyBytes = 0;
	switch (version)
	{
	case 4: Key = AesKeyV4; RijndaelKeyBytes = sizeof(AesKeyV4); break;
	case 5: Key = AesKeyV5; RijndaelKeyBytes = sizeof(AesKeyV5); break;
	case 6: Key = AesKeyV6; RijndaelKeyBytes = sizeof(AesKeyV6); break;
	}
	if (!Key || !RijndaelKeyBytes) return 0;

	int RijndaelKeyDwords = RijndaelKeyBytes / sizeof(DWORD);
	context->Rounds = (BYTE)(RijndaelKeyDwords + 6);

	static const DWORD RCon[] = {
	  0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
	  0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000
	};

	DWORD temp;

	memcpy(context->Key, Key, RijndaelKeyBytes);

	for (BYTE i = (BYTE)RijndaelKeyDwords; i < (context->Rounds + 1) << 2; i++)
	{
		temp = context->Key[i - 1];
		if ((i % RijndaelKeyDwords) == 0) temp = BE32(SubDword(ROR32(BE32(temp), 24)) ^ RCon[i / RijndaelKeyDwords]);
		context->Key[i] = context->Key[i - RijndaelKeyDwords] ^ temp;
	}

	BYTE* _p = (BYTE*)context->Key;
	switch (version)
	{
	case 6: _p[4 * 16] ^= 0x73; _p[6 * 16] ^= 0x09; _p[8 * 16] ^= 0xE4; break;
	default: break;
	}

	return 1;
}

void SubBytes(BYTE* block)
{
	for (BYTE i = 0; i < AES_BLOCK_BYTES; i++) block[i] = SBox[block[i]];
}

void ShiftRows(BYTE* state)
{
	BYTE bIn[AES_BLOCK_BYTES];
	memcpy(bIn, state, AES_BLOCK_BYTES);
	for (BYTE i = 0; i < AES_BLOCK_BYTES; i++)
	{
		state[i] = bIn[(i + ((i & 3) << 2)) & 0xf];
	}
}

void MixColumns(BYTE* state)
{
	for (BYTE i = 0; i < AES_BLOCK_WORDS; i++)
	{
		DWORD word = ((DWORD*)state)[i];
		((DWORD*)state)[i] = Mul2(word) ^ ROR32(Mul3(word), 8) ^ ROR32(word, 16) ^ ROR32(word, 24);
	}
}

void AesEncryptBlock(const AesCtx* const context, BYTE* block)
{
	for (BYTE i = 0;; i += 4)
	{
		AddRoundKey(block, &context->Key[i]);
		SubBytes(block);
		ShiftRows(block);
		if (i >= (context->Rounds - 1) << 2) break;
		MixColumns(block);
	}

	AddRoundKey(block, &context->Key[context->Rounds << 2]);
}

void AesCmacV4(BYTE* message, DWORD message_size, BYTE* mac_out)
{
	BYTE mac[AES_BLOCK_BYTES];
	AesCtx context;
	AesInitKey(&context, 4);

	memset(mac, 0, sizeof(mac));
	memset(message + message_size, 0, AES_BLOCK_BYTES);
	message[message_size] = 0x80;

	for (DWORD i = 0; i <= message_size; i += AES_BLOCK_BYTES)
	{
		XorBlock(message + i, mac);
		AesEncryptBlock(&context, mac);
	}

	memcpy(mac_out, mac, AES_BLOCK_BYTES);
}

static const BYTE SBoxR[] = {
  0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
  0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
  0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
  0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
  0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
  0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
  0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
  0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
  0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
  0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
  0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
  0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
  0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
  0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
  0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

#define GetSBoxR(x) SBoxR[x]

void ShiftRowsR(BYTE* state)
{
	BYTE b[AES_BLOCK_BYTES];
	memcpy(b, state, AES_BLOCK_BYTES);
	for (BYTE i = 0; i < AES_BLOCK_BYTES; i++) state[i] = b[(i - ((i & 0x3) << 2)) & 0xf];
}

void SubBytesR(BYTE* block)
{
	for (BYTE i = 0; i < AES_BLOCK_BYTES; i++) block[i] = GetSBoxR(block[i]);
}

void AesEncryptCbc(const AesCtx* const context, BYTE* iv, BYTE* data, DWORD* len)
{
	BYTE pad = (~*len & (AES_BLOCK_BYTES - 1)) + 1;
	memset(data + *len, pad, pad);
	*len += pad;

	if (iv) XorBlock(iv, data);
	AesEncryptBlock(context, data);

	for (DWORD i = *len - AES_BLOCK_BYTES; i > 0; i -= AES_BLOCK_BYTES)
	{
		XorBlock(data, data + AES_BLOCK_BYTES);
		data += AES_BLOCK_BYTES;
		AesEncryptBlock(context, data);
	}
}

void AesDecryptBlock(const AesCtx* const context, BYTE* block)
{
	AddRoundKey(block, &context->Key[context->Rounds << 2]);
	for (BYTE i = (context->Rounds - 1) << 2;; i -= 4)
	{
		ShiftRowsR(block);
		SubBytesR(block);
		AddRoundKey(block, &context->Key[i]);
		if (i == 0) break;
		MixColumnsR(block);
	}
}

void AesDecryptCbc(const AesCtx* const context, BYTE* iv, BYTE* data, DWORD len)
{
	BYTE* cc;
	for (cc = data + len - AES_BLOCK_BYTES; cc > data; cc -= AES_BLOCK_BYTES)
	{
		AesDecryptBlock(context, cc);
		XorBlock(cc - AES_BLOCK_BYTES, cc);
	}

	AesDecryptBlock(context, cc);
	if (iv) XorBlock(iv, cc);
}


struct Sha256Ctx{
	DWORD State[8];
	BYTE Buffer[64];
	DWORD Len;
};

struct Sha256HmacCtx {
	Sha256Ctx ShaCtx;
	BYTE OPad[64];
};

#define F0(x, y, z)  ( ((x) & (y)) | (~(x) & (z)) )
#define F1(x, y, z)  ( ((x) & (y)) | ((x) & (z)) | ((y) & (z)) )

#define SI1(x)  ( ROR32(x, 2 ) ^ ROR32(x, 13) ^ ROR32(x, 22) )
#define SI2(x)  ( ROR32(x, 6 ) ^ ROR32(x, 11) ^ ROR32(x, 25) )
#define SI3(x)  ( ROR32(x, 7 ) ^ ROR32(x, 18) ^ ((x) >> 3 ) )
#define SI4(x)  ( ROR32(x, 17) ^ ROR32(x, 19) ^ ((x) >> 10) )

static const DWORD k[] = {
  0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1,
  0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
  0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786,
  0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
  0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147,
  0x06CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
  0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B,
  0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
  0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A,
  0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
  0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};

void Sha256Init(Sha256Ctx* context)
{
	context->State[0] = 0x6A09E667;
	context->State[1] = 0xBB67AE85;
	context->State[2] = 0x3C6EF372;
	context->State[3] = 0xA54FF53A;
	context->State[4] = 0x510E527F;
	context->State[5] = 0x9B05688C;
	context->State[6] = 0x1F83D9AB;
	context->State[7] = 0x5BE0CD19;
	context->Len = 0;
}

void Sha256ProcessBlock(Sha256Ctx* context, const BYTE* block)
{
	DWORD w[64] = { 0 }, temp1, temp2, i;
	DWORD a = context->State[0]; DWORD b = context->State[1]; DWORD c = context->State[2]; DWORD d = context->State[3];
	DWORD e = context->State[4]; DWORD f = context->State[5]; DWORD g = context->State[6]; DWORD h = context->State[7];

	for (i = 0; i < 16; i++) w[i] = BE32(((DWORD*)block)[i]);
	for (i = 16; i < 64; i++) w[i] = SI4(w[i - 2]) + w[i - 7] + SI3(w[i - 15]) + w[i - 16];

	for (i = 0; i < 64; i++)
	{
		temp1 = h + SI2(e) + F0(e, f, g) + k[i] + w[i];
		temp2 = SI1(a) + F1(a, b, c);

		h = g; g = f; f = e; e = d + temp1;
		d = c; c = b; b = a; a = temp1 + temp2;
	}

	context->State[0] += a; context->State[1] += b; context->State[2] += c; context->State[3] += d;
	context->State[4] += e; context->State[5] += f; context->State[6] += g; context->State[7] += h;
}

void Sha256Update(Sha256Ctx* context, const BYTE* data, DWORD len)
{
	const DWORD b_len = context->Len & 63, r_len = (b_len ^ 63) + 1;

	context->Len += (DWORD)len;

	if (len < r_len)
	{
		memcpy(context->Buffer + b_len, data, len);
		return;
	}

	if (r_len < 64)
	{
		memcpy(context->Buffer + b_len, data, r_len);
		len -= r_len;
		data += r_len;
		Sha256ProcessBlock(context, context->Buffer);
	}

	for (; len >= 64; len -= 64, data += 64) Sha256ProcessBlock(context, data);

	if (len) memcpy(context->Buffer, data, len);
}

void Sha256Finish(Sha256Ctx* context, BYTE* hash)
{
	DWORD b_len = context->Len & 63;

	context->Buffer[b_len] = 0x80;
	if (b_len ^ 63) memset(context->Buffer + b_len + 1, 0, b_len ^ 63);

	if (b_len >= 56)
	{
		Sha256ProcessBlock(context, context->Buffer);
		memset(context->Buffer, 0, 56);
	}

	((unsigned long long*)context->Buffer)[7] = BE64((unsigned long long)context->Len << 3);
	Sha256ProcessBlock(context, context->Buffer);

	for (DWORD i = 0; i < 8; i++) ((DWORD*)hash)[i] = BE32(context->State[i]);
}

void Sha256(const BYTE* data, const DWORD len, BYTE* hash)
{
	Sha256Ctx Ctx;

	Sha256Init(&Ctx);
	Sha256Update(&Ctx, data, len);
	Sha256Finish(&Ctx, hash);
}

void _Sha256HmacInit(Sha256HmacCtx* context, const BYTE* key, DWORD klen)
{
	BYTE IPad[64];

	memset(IPad, 0x36, sizeof(IPad));
	memset(context->OPad, 0x5C, sizeof(context->OPad));

	if (klen > 64)
	{
		BYTE temp[32];
		Sha256(key, klen, temp);
		klen = 32;
		key = temp;
	}

	for (DWORD i = 0; i < klen; i++)
	{
		IPad[i] ^= key[i];
		context->OPad[i] ^= key[i];
	}

	Sha256Init(&context->ShaCtx);
	Sha256Update(&context->ShaCtx, IPad, sizeof(IPad));
}

void _Sha256HmacUpdate(Sha256HmacCtx* context, const BYTE* data, DWORD len)
{
	Sha256Update(&context->ShaCtx, data, len);
}

void _Sha256HmacFinish(Sha256HmacCtx* context, BYTE* hmac)
{
	BYTE temp[32];

	Sha256Finish(&context->ShaCtx, temp);
	Sha256Init(&context->ShaCtx);
	Sha256Update(&context->ShaCtx, context->OPad, sizeof(context->OPad));
	Sha256Update(&context->ShaCtx, temp, sizeof(temp));
	Sha256Finish(&context->ShaCtx, hmac);
}

void Sha256Hmac(const BYTE* key, const BYTE* data, DWORD len, BYTE* hmac)
{
	Sha256HmacCtx context;
	_Sha256HmacInit(&context, key, 16);
	_Sha256HmacUpdate(&context, data, len);
	_Sha256HmacFinish(&context, hmac);
}