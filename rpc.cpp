#include "rpc.h"
#include "kms.h"
#include "network.h"

/* Data definitions */

// All GUIDs are defined as BYTE[16] here. No big-endian/little-endian byteswapping required.
static const BYTE TransferSyntaxNDR32[] = {
  0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11, 0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60
};

static const BYTE InterfaceUuid[] = {
  0x75, 0x21, 0xc8, 0x51, 0x4e, 0x84, 0x50, 0x47, 0xB0, 0xD8, 0xEC, 0x25, 0x55, 0x55, 0xBC, 0x06
};

static const BYTE TransferSyntaxNDR64[] = {
  0x33, 0x05, 0x71, 0x71, 0xba, 0xbe, 0x37, 0x49, 0x83, 0x19, 0xb5, 0xdb, 0xef, 0x9c, 0xcc, 0x36
};

static const BYTE BindTimeFeatureNegotiation[] = {
  0x2c, 0x1c, 0xb7, 0x6c, 0x12, 0x98, 0x40, 0x45, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

typedef int(*CreateResponse_t)(const void* const, void* const, const char*);

// ReSharper disable CppIncompatiblePointerConversion
static const struct {
	unsigned int  RequestSize;
	CreateResponse_t CreateResponse;
} _Versions[] = {
  { sizeof(REQUEST_V4), (CreateResponse_t)CreateResponseV4 },
  { sizeof(REQUEST_V5), (CreateResponse_t)CreateResponseV5 },
  { sizeof(REQUEST_V6), (CreateResponse_t)CreateResponseV6 }
};
// ReSharper restore CppIncompatiblePointerConversion

static const DWORD CallId = 2; // M$ starts with CallId 2. So we do the same.

/*
   check RPC request for (somewhat) correct size
   allow any size that does not cause CreateResponse to fail badly
*/
unsigned int checkRpcRequestSize(const RPC_REQUEST64* const Request, const unsigned int requestSize, WORD* NdrCtx, WORD* Ndr64Ctx)
{
	WORD Ctx = Request->ContextId;

	// Anything that is smaller than a v4 request is illegal
	if (requestSize < sizeof(REQUEST_V4) + (Ctx != *Ndr64Ctx ? sizeof(RPC_REQUEST) : sizeof(RPC_REQUEST64))) return 0;

	// Get KMS major version
	WORD majorIndex, minor;
	DWORD version;

	if (Ctx != *Ndr64Ctx)
	{
		version = *(DWORD*)Request->Ndr.Data;
	}
	else
	{
		version = *(DWORD*)Request->Ndr64.Data;
	}

	majorIndex = (WORD)(version >> 16) - 4;
	minor = (WORD)(version & 0xffff);

	// Only KMS v4, v5 and v6 are supported
	if (majorIndex >= (sizeof(_Versions) / sizeof(_Versions[0])) || minor)
	{
		return 0;
	}

	// Could check for equality but allow bigger requests to support buggy RPC clients (e.g. wine)
	// Buffer overrun is check by caller.
	return (requestSize >= _Versions[majorIndex].RequestSize);
}

int SendError(RPC_RESPONSE64* const Response, DWORD nca_error)
{
	Response->Error.Code = nca_error;
	Response->Error.Padding = 0;
	Response->AllocHint = 32;
	Response->ContextId = 0;
	return 32;
}

/*
   Handles the actual KMS request from the client.
   Calls KMS functions (CreateResponseV4 or CreateResponseV6) in kms.c
   Returns size of the KMS response packet or 0 on failure.

   The RPC packet size (excluding header) is actually in Response->AllocHint
*/
int rpcRequest(const RPC_REQUEST64* const Request, RPC_RESPONSE64* const Response, const DWORD RpcAssocGroup_unused, WORD* NdrCtx, WORD* Ndr64Ctx, BYTE isValid, const char* remoteIP, const char* port_unused)
{
	int ResponseSize; // <0 = Errorcode (HRESULT)
	BYTE* requestData;
	BYTE* responseData;
	BYTE* pRpcReturnCode;
	int len;

	const WORD Ctx = Request->ContextId;

	if (Ctx == *NdrCtx)
	{
		requestData = (BYTE*)&Request->Ndr.Data;
		responseData = (BYTE*)&Response->Ndr.Data;
	}
	else if (Ctx == *Ndr64Ctx)
	{
		requestData = (BYTE*)&Request->Ndr64.Data;
		responseData = (BYTE*)&Response->Ndr64.Data;
	}
	else
	{
		return SendError(Response, RPC_NCA_UNK_IF);
	}

	ResponseSize = 0x8007000D; // Invalid Data

	if (isValid)
	{
		const WORD majorIndex = ((WORD*)requestData)[1] - 4;
		if (!((ResponseSize = _Versions[majorIndex].CreateResponse(requestData, responseData, remoteIP)))) ResponseSize = 0x8007000D;
	}

	if (Ctx != *Ndr64Ctx)
	{
		if (ResponseSize < 0)
		{
			Response->Ndr.DataSizeMax = Response->Ndr.DataLength = 0;
			len = sizeof(Response->Ndr) - sizeof(Response->Ndr.DataSizeIs);
		}
		else
		{
			Response->Ndr.DataSizeMax = 0x00020000;
			Response->Ndr.DataLength = Response->Ndr.DataSizeIs = ResponseSize;
			len = ResponseSize + sizeof(Response->Ndr);
		}

	}
	else
	{
		if (ResponseSize < 0)
		{
			Response->Ndr64.DataSizeMax = Response->Ndr64.DataLength = 0;
			len = sizeof(Response->Ndr64) - sizeof(Response->Ndr64.DataSizeIs);
		}
		else
		{
			Response->Ndr64.DataSizeMax = 0x00020000ULL;
			Response->Ndr64.DataLength = Response->Ndr64.DataSizeIs = (QWORD)ResponseSize;
			len = ResponseSize + sizeof(Response->Ndr64);
		}
	}

	pRpcReturnCode = ((BYTE*)&Response->Ndr) + len;
	*(DWORD*)pRpcReturnCode = ResponseSize < 0 ? ResponseSize : 0;
	len += sizeof(DWORD);

	// Pad zeros to 32-bit align (seems not neccassary but Windows RPC does it this way)
	const int pad = ((~len & 3) + 1) & 3;
	memset(pRpcReturnCode + sizeof(DWORD), 0, pad);
	len += pad;

	Response->AllocHint = len;
	Response->ContextId = Request->ContextId;

	*((WORD*)&Response->CancelCount) = 0; // CancelCount + Pad1

	return len + 8;
}

/*
   Check, if we receive enough bytes to return a valid RPC bind response
*/
unsigned int checkRpcBindSize(const RPC_BIND_REQUEST* const Request, const unsigned int RequestSize, WORD* NdrCtx_unused, WORD* Ndr64Ctx_unused)
{
	if (RequestSize < sizeof(RPC_BIND_REQUEST)) return 0;

	const unsigned int numCtxItems = Request->NumCtxItems;

	if (RequestSize < sizeof(RPC_BIND_REQUEST) - sizeof(Request->CtxItems[0]) + numCtxItems * sizeof(Request->CtxItems[0])) return 0;

	return 1;
}


/*
   Accepts a bind or alter context request from the client and composes the bind response.
   Needs the socket because the tcp port number is part of the response.
   len is not used here.

   Returns 1 on success.
*/
int rpcBind(const RPC_BIND_REQUEST* const Request, RPC_BIND_RESPONSE* Response, const DWORD RpcAssocGroup, WORD* NdrCtx, WORD* Ndr64Ctx, BYTE packetType, const char* remoteIP_unused, const char* localPort)
{
	unsigned int i;
	const DWORD numCtxItems = Request->NumCtxItems;
	bool IsNDR64possible = false;
	uint_fast8_t portNumberSize;

	// Pad bytes contain apparently random data
	if (packetType == RPC_PT_ALTERCONTEXT_REQ)
	{
		portNumberSize = 0;
		Response->SecondaryAddressLength = 0;
	}
	else
	{
		strcpy((char*)(Response->SecondaryAddress), localPort);
		portNumberSize = (uint_fast8_t)strlen((char*)Response->SecondaryAddress) + 1;
		Response->SecondaryAddressLength = portNumberSize;
	}

	Response->MaxXmitFrag = Request->MaxXmitFrag;
	Response->MaxRecvFrag = Request->MaxRecvFrag;
	Response->AssocGroup = RpcAssocGroup;

	// This is really ugly (but efficient) code to support padding after the secondary address field
	if (portNumberSize < 3)
	{
		Response = (RPC_BIND_RESPONSE*)((BYTE*)Response - 4);
	}

	Response->NumResults = Request->NumCtxItems;

	for (i = 0; i < numCtxItems; i++)
	{
		const struct RPC_BIND_REQUEST::CtxItem* ctxItem = &Request->CtxItems[i];
		if (!memcmp((GUID*)TransferSyntaxNDR32, &ctxItem->TransferSyntax, sizeof(GUID)))
		{
			/*if (packetType == RPC_PT_BIND_REQ)*/
			*NdrCtx = ctxItem->ContextId;
		}

		if (!memcmp((GUID*)TransferSyntaxNDR64, &ctxItem->TransferSyntax, sizeof(GUID)))
		{
			IsNDR64possible = true;

			/*if (packetType == RPC_PT_BIND_REQ)*/
			*Ndr64Ctx = ctxItem->ContextId;
		}
	}

	for (i = 0; i < numCtxItems; i++)
	{
		struct RPC_BIND_RESPONSE::CtxResults* result = Response->Results + i;
		const GUID* ctxTransferSyntax = &Request->CtxItems[i].TransferSyntax;

		WORD nackReason = RPC_ABSTRACTSYNTAX_UNSUPPORTED;

		memset(&result->TransferSyntax, 0, sizeof(GUID));

		const bool isInterfaceUUID = !memcmp(&Request->CtxItems[i].InterfaceUUID, (GUID*)InterfaceUuid, sizeof(GUID));
		if (isInterfaceUUID) nackReason = RPC_SYNTAX_UNSUPPORTED;

		if (isInterfaceUUID && !IsNDR64possible && !memcmp((GUID*)TransferSyntaxNDR32, ctxTransferSyntax, sizeof(GUID)))
		{
			result->SyntaxVersion = 2;
			result->AckResult = result->AckReason = RPC_BIND_ACCEPT;
			memcpy(&result->TransferSyntax, TransferSyntaxNDR32, sizeof(GUID));
			continue;
		}

		if (!memcmp((GUID*)TransferSyntaxNDR64, ctxTransferSyntax, sizeof(GUID)))
		{
			if (isInterfaceUUID && IsNDR64possible)
			{
				result->SyntaxVersion = 1;
				result->AckResult = result->AckReason = RPC_BIND_ACCEPT;
				memcpy(&result->TransferSyntax, TransferSyntaxNDR64, sizeof(GUID));
				continue;
			}
		}

		if (!memcmp(BindTimeFeatureNegotiation, ctxTransferSyntax, 8))
		{
			nackReason = RPC_SYNTAX_UNSUPPORTED;

			result->SyntaxVersion = 0;
			result->AckResult = RPC_BIND_ACK;

			// Features requested are actually encoded in the GUID
			result->AckReason =
				((WORD*)(ctxTransferSyntax))[4] &
				(RPC_BTFN_SEC_CONTEXT_MULTIPLEX | RPC_BTFN_KEEP_ORPHAN);

			continue;
		}


		result->SyntaxVersion = 0;
		result->AckResult = RPC_BIND_NACK;
		result->AckReason = nackReason;
	}

	return sizeof(RPC_BIND_RESPONSE) + numCtxItems * sizeof(RPC_BIND_RESPONSE::CtxResults) - (portNumberSize < 3 ? 4 : 0);
}


//
// Main RPC handling routine
//
typedef unsigned int(*GetResponseSize_t)(const void* const request, const unsigned int requestSize, WORD* NdrCtx, WORD* Ndr64Ctx);
typedef int(*GetResponse_t)(const void* const request, void* response, const DWORD rpcAssocGroup, WORD* NdrCtx, WORD* Ndr64Ctx, BYTE packetType, const char* remoteIP, const char* localPort);

// ReSharper disable CppIncompatiblePointerConversion
static const struct {
	BYTE  ResponsePacketType;
	GetResponseSize_t CheckRequest;
	GetResponse_t GetResponse;
}
_Actions[] = {
  { RPC_PT_BIND_ACK,         (GetResponseSize_t)checkRpcBindSize,    (GetResponse_t)rpcBind    },
  { RPC_PT_RESPONSE,         (GetResponseSize_t)checkRpcRequestSize, (GetResponse_t)rpcRequest },
  { RPC_PT_ALTERCONTEXT_ACK, (GetResponseSize_t)checkRpcBindSize,    (GetResponse_t)rpcBind    },
};
// ReSharper restore CppIncompatiblePointerConversion


/*
  Initializes an RPC request header as needed for KMS, i.e. packet always fits in one fragment.
  size cannot be greater than fragment length negotiated during RPC bind.
*/
void createRpcHeader(RPC_HEADER* header, BYTE packetType, WORD size)
{
	header->PacketType = packetType;
	header->PacketFlags = RPC_PF_FIRST | RPC_PF_LAST;
	header->VersionMajor = 5;
	header->VersionMinor = 0;
	header->AuthLength = 0;
	header->DataRepresentation = 0x00000010; // Little endian, ASCII charset, IEEE floating point
	header->CallId = CallId;
	header->FragLength = size;
}

bool rpcGetRequestHeader(const SOCKET sock, RPC_HEADER& rpcRequestHeader) {
	return _recv(sock, (char*)&rpcRequestHeader, sizeof(rpcRequestHeader));
}
bool rpcGetRequestLength(const RPC_HEADER& rpcRequestHeader, unsigned int& request_len) {
	request_len = rpcRequestHeader.FragLength - sizeof(rpcRequestHeader);
	if (request_len > MAX_REQUEST_SIZE + sizeof(RPC_REQUEST64)) return false;
	return true;
}
bool rpcGetRequest(const SOCKET sock, BYTE* requestBuffer, const unsigned int& request_len) {
	return _recv(sock, (char*)requestBuffer, request_len);
}
bool rpcCreateResponse(WORD& NdrCtx, WORD& Ndr64Ctx, RPC_HEADER& rpcRequestHeader, BYTE* requestBuffer, const unsigned int& request_len, BYTE* responseBuffer, unsigned int& response_len, const DWORD rpcAssocGroup, const char* remoteIP, const char* localPort) {

	uint_fast8_t _a;

	switch (rpcRequestHeader.PacketType)
	{
	case RPC_PT_BIND_REQ:         _a = 0; break;
	case RPC_PT_REQUEST:          _a = 1; break;
	case RPC_PT_ALTERCONTEXT_REQ: _a = 2; break;
	default: return false;
	}

	RPC_HEADER* rpcResponseHeader = (RPC_HEADER*)responseBuffer;
	RPC_RESPONSE* rpcResponse = (RPC_RESPONSE*)(responseBuffer + sizeof(rpcRequestHeader));

	// The request is larger than the buffer size
	if (request_len > MAX_REQUEST_SIZE + sizeof(RPC_REQUEST64)) return false;

	BYTE isValid = (BYTE)_Actions[_a].CheckRequest(requestBuffer, request_len, &NdrCtx, &Ndr64Ctx);
	if (rpcRequestHeader.PacketType != RPC_PT_REQUEST && !isValid) return false;

	// Unable to create a valid response from request
	if (!((response_len = _Actions[_a].GetResponse(requestBuffer, rpcResponse, rpcAssocGroup, &NdrCtx, &Ndr64Ctx, rpcRequestHeader.PacketType != RPC_PT_REQUEST ? rpcRequestHeader.PacketType : isValid, remoteIP, localPort)))) return false;

	memcpy(rpcResponseHeader, &rpcRequestHeader, sizeof(RPC_HEADER));

	if (response_len == 32)
	{
		createRpcHeader(rpcResponseHeader, RPC_PT_FAULT, 0);
		rpcResponseHeader->PacketFlags = RPC_PF_FIRST | RPC_PF_LAST | RPC_PF_NOT_EXEC;
		return false;
	}
	else
	{
		response_len += sizeof(RPC_HEADER);
		rpcResponseHeader->PacketType = _Actions[_a].ResponsePacketType;

		if (rpcResponseHeader->PacketType == RPC_PT_ALTERCONTEXT_ACK)
		{
			rpcResponseHeader->PacketFlags = RPC_PF_FIRST | RPC_PF_LAST;
		}
	}

	rpcResponseHeader->FragLength = (WORD)response_len;
	return true;
}

bool rpcSendResponse(SOCKET sock, BYTE* responseBuffer, const unsigned int& response_len) {
	return _send(sock, (const char*)responseBuffer, response_len);
}
