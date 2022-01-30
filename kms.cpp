#include "kms.h"
#include "crypto.h"

static RequestCallback_t CreateResponseBase = NULL;
void SetCreateResponseBase(RequestCallback_t requestCallback) { CreateResponseBase = requestCallback; }

int CreateResponseV4(REQUEST_V4* const request, RESPONSE_V4* const response, const char* ipstr)
{
	QWORD hwId_unused;
	CreateResponseBase(&request->RequestBase, &response->ResponseBase, &hwId_unused, ipstr);
	memmove((BYTE*)response->ResponseBase.KmsPID + response->ResponseBase.PIDSize, (BYTE*)response->ResponseBase.KmsPID + sizeof(response->ResponseBase.KmsPID), 36);
	const int size = sizeof(RESPONSE) - (sizeof(response->ResponseBase.KmsPID) - response->ResponseBase.PIDSize);

	AesCmacV4((BYTE*)response, size, (BYTE*)response + size);
	return sizeof(RESPONSE_V4) - sizeof(RESPONSE) + size;
}

int CreateResponseV6(REQUEST_V6* const request, RESPONSE_V6* const response, const char* ipstr)
{
	AesCtx context; int response_size = 0;
	AesInitKey(&context, request->MajorVer);
	AesDecryptCbc(&context, NULL, request->IV, sizeof(REQUEST_V6) - sizeof(request->Version));
	for (int i = 0; i < 16; i++) response->RandomXoredIVs[i] = rand() % 256;
	Sha256(response->RandomXoredIVs, sizeof(response->RandomXoredIVs), response->Hash);

	if (request->MajorVer == 6)
	{
		response->Version = request->Version;
		memcpy(response->XoredIVs, request->IV, sizeof(response->IV));
	}
	if (request->MajorVer == 5) memcpy(response, request, sizeof(response->Version) + sizeof(response->IV));

	for (int i = 0; i < 16; i++) response->RandomXoredIVs[i] ^= request->IV[i];

	QWORD hwId;
	CreateResponseBase(&request->RequestBase, &response->ResponseBase, &hwId, ipstr);
	memmove((BYTE*)response->ResponseBase.KmsPID + response->ResponseBase.PIDSize, (BYTE*)response->ResponseBase.KmsPID + sizeof(response->ResponseBase.KmsPID), 36);
	const int b_size = sizeof(RESPONSE) - (sizeof(response->ResponseBase.KmsPID) - response->ResponseBase.PIDSize);

	if (request->MajorVer == 6) {
		memcpy(response->HWID, &hwId, sizeof(hwId));
		response_size = sizeof(RESPONSE_V6) - sizeof(RESPONSE) + b_size;
	}
	if (request->MajorVer == 5) response_size = sizeof(RESPONSE_V5) - sizeof(RESPONSE) + b_size;
	memmove((BYTE*)&response->ResponseBase + b_size, (BYTE*)&response->ResponseBase + sizeof(RESPONSE), response_size - (sizeof(response->Version) + sizeof(response->IV) + b_size));

	if (request->MajorVer == 6)
	{
		BYTE hash[32];
		QWORD timeSlot = (((*(QWORD*)&request->RequestBase.ClientTime) / 0x00000022816889BD) * 0x000000208CBAB5ED) + 0x3156CD5AC628477A;
		Sha256((BYTE*)&timeSlot, sizeof(timeSlot), hash);
		Sha256Hmac(hash + 16, response->IV, response_size - sizeof(response->Version) - sizeof(response->HMAC), hash);
		memcpy((BYTE*)response + response_size - sizeof(response->HMAC), hash + 16, sizeof(response->HMAC));
	}

	response_size -= sizeof(response->Version);
	AesEncryptCbc(&context, NULL, response->IV, (DWORD*)&response_size);
	response_size += sizeof(response->Version);

	return response_size;
}
