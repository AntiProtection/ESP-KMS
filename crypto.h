#pragma once
#include "util.h"

struct AesCtx {
	DWORD  Key[48];
	BYTE Rounds;
};

int AesInitKey(AesCtx* context, const int version);
void AesEncryptCbc(const AesCtx* const context, BYTE* iv, BYTE* data, DWORD* len);
void AesDecryptCbc(const AesCtx* const context, BYTE* iv, BYTE* data, DWORD len);
void AesCmacV4(BYTE* data, DWORD len, BYTE* hash);

void Sha256(const BYTE* data, const DWORD len, BYTE* hash);
void Sha256Hmac(const BYTE* key, const BYTE* data, DWORD len, BYTE* hmac);