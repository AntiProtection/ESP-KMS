#pragma once
#include "util.h"

#define MAX_REQUEST_SIZE 260
#define MAX_RESPONSE_SIZE 512
#define PID_BUFFER_SIZE 64

#define VERSION_INFO union { DWORD Version; struct { WORD MinorVer; WORD MajorVer; }; }

struct REQUEST {
	VERSION_INFO;
	DWORD VMInfo;          // 0 = client is bare metal / 1 = client is VM
	DWORD LicenseStatus;     // 0 = Unlicensed, 1 = Licensed (Activated), 2 = OOB grace, 3 = OOT grace, 4 = NonGenuineGrace, 5 = Notification, 6 = extended grace
	DWORD BindingExpiration;   // Expiration of the current status in minutes (e.g. when KMS activation or OOB grace expires).
	GUID AppID;           // Can currently be Windows, Office2010 or Office2013 (see kms.c, table AppList).
	GUID ActID;           // Most detailed product list. One product key per ActID (see kms.c, table ExtendedProductList). Is ignored by KMS server.
	GUID KMSID;           // This is actually what the KMS server uses to grant or refuse activation (see kms.c, table BasicProductList).
	GUID CMID;            // Client machine id. Used by the KMS server for counting minimum clients.
	DWORD N_Policy;          // Minimum clients required for activation.
	FILETIME ClientTime;      // Current client time.
	GUID CMID_prev;         // previous client machine id. All zeros, if it never changed.
	WCHAR WorkstationName[64];    // Workstation name. FQDN if available, NetBIOS otherwise.
};

struct RESPONSE {
	VERSION_INFO;
	DWORD PIDSize;         // Size of PIDData in bytes.
	WCHAR KmsPID[PID_BUFFER_SIZE];  // ePID (must include terminating zero)
	GUID CMID;            // Client machine id. Must be the same as in request.
	FILETIME ClientTime;      // Current client time. Must be the same as in request.
	DWORD Count;         // Current activated machines. KMS server counts up to N_Policy << 1 then stops
	DWORD VLActivationInterval;    // Time in minutes when clients should retry activation if it was unsuccessful (default 2 hours)
	DWORD VLRenewalInterval;        // Time in minutes when clients should renew KMS activation (default 7 days)
};

struct REQUEST_V4 {
	REQUEST RequestBase;      // Base request
	BYTE MAC[16];          // Aes 160 bit CMAC
};

struct RESPONSE_V4 {
	RESPONSE ResponseBase;      // Base response
	BYTE MAC[16];          // Aes 160 bit CMAC
};

struct REQUEST_V5 {
	VERSION_INFO;         // unencrypted version info
	BYTE IV[16];         // IV
	REQUEST RequestBase;      // Base Request
	BYTE Pad[4];         // since this struct is fixed, we use fixed PKCS pad bytes
};

typedef REQUEST_V5 REQUEST_V6;    // v5 and v6 requests are identical

struct RESPONSE_V6 {
	VERSION_INFO;
	BYTE IV[16];
	RESPONSE ResponseBase;
	BYTE RandomXoredIVs[16];   // If RequestIV was used for decryption: Random ^ decrypted Request IV ^ ResponseIV. If NULL IV was used for decryption: Random ^ decrypted Request IV
	BYTE Hash[32];         // SHA256 of Random used in RandomXoredIVs
	BYTE HWID[8];          // HwId from the KMS server
	BYTE XoredIVs[16];       // If RequestIV was used for decryption: decrypted Request IV ^ ResponseIV. If NULL IV was used for decryption: decrypted Request IV.
	BYTE HMAC[16];         // V6 Hmac (low 16 bytes only), see kms.c CreateV6Hmac
};

struct RESPONSE_V5 {          // not used except for sizeof(). Fields are the same as RESPONSE_V6
	VERSION_INFO;
	BYTE IV[16];
	RESPONSE ResponseBase;
	BYTE RandomXoredIVs[16];
	BYTE Hash[32];
};

typedef void(*RequestCallback_t)(const REQUEST* const request, RESPONSE* const response, QWORD* const hwId, const char* ipstr);
void SetCreateResponseBase(RequestCallback_t Callback);

int CreateResponseV4(REQUEST_V4* const request, RESPONSE_V4* const response, const char* ipstr);
#define CreateResponseV5 CreateResponseV6
int CreateResponseV6(REQUEST_V6* const request, RESPONSE_V6* const response, const char* ipstr);
