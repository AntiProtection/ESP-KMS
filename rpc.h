#pragma once
#include "util.h"
#include "libkms.h"

struct RPC_HEADER {
	BYTE   VersionMajor;
	BYTE   VersionMinor;
	BYTE   PacketType;
	BYTE   PacketFlags;
	DWORD  DataRepresentation;
	WORD   FragLength;
	WORD   AuthLength;
	DWORD  CallId;
};


struct RPC_BIND_REQUEST {
	WORD   MaxXmitFrag;
	WORD   MaxRecvFrag;
	DWORD  AssocGroup;
	DWORD  NumCtxItems;
	struct CtxItem {
		WORD   ContextId;
		WORD   NumTransItems;
		GUID   InterfaceUUID;
		WORD   InterfaceVerMajor;
		WORD   InterfaceVerMinor;
		GUID   TransferSyntax;
		DWORD  SyntaxVersion;
	} CtxItems[1];
};

struct RPC_BIND_RESPONSE {
	WORD   MaxXmitFrag;
	WORD   MaxRecvFrag;
	DWORD  AssocGroup;
	WORD   SecondaryAddressLength;
	BYTE   SecondaryAddress[6];
	DWORD  NumResults;
	struct CtxResults {
		WORD   AckResult;
		WORD   AckReason;
		GUID   TransferSyntax;
		DWORD  SyntaxVersion;
	} Results[0];
};


struct RPC_REQUEST {
	DWORD  AllocHint;
	WORD   ContextId;
	WORD   Opnum;
	struct {
		DWORD  DataLength;
		DWORD  DataSizeIs;
	} Ndr;
	BYTE   Data[0];
};

struct RPC_RESPONSE {
	DWORD  AllocHint;
	WORD   ContextId;
	BYTE   CancelCount;
	BYTE   Pad1;
	struct {
		DWORD  DataLength;
		DWORD  DataSizeIs1;
		DWORD  DataSizeIs2;
	} Ndr;
	BYTE   Data[0];
};

struct RPC_REQUEST64 {
	DWORD  AllocHint;
	WORD   ContextId;
	WORD   Opnum;
	union {
		struct {
			DWORD  DataLength;
			DWORD  DataSizeIs;
			BYTE   Data[0];
		} Ndr;
		struct {
			QWORD DataLength;
			QWORD DataSizeIs;
			BYTE     Data[0];
		} Ndr64;
	};
};

struct RPC_RESPONSE64 {
	DWORD  AllocHint;
	WORD   ContextId;
	BYTE   CancelCount;
	BYTE   Pad1;
	union {
		struct {
			DWORD  DataLength;
			DWORD  DataSizeMax;
			union
			{
				DWORD DataSizeIs;
				DWORD status;
			};
			BYTE   Data[0];
		} Ndr;
		struct {
			QWORD DataLength;
			QWORD DataSizeMax;
			union
			{
				QWORD DataSizeIs;
				DWORD    status;
			};
			BYTE     Data[0];
		} Ndr64;
		struct
		{
			DWORD Code;
			DWORD Padding;
		} Error;

	};
};


#define RPC_INVALID_CTX ((WORD)~0)

#define RPC_BIND_ACCEPT (0)
#define RPC_BIND_NACK   (2)
#define RPC_BIND_ACK    (3)

#define RPC_SYNTAX_UNSUPPORTED         (2)
#define RPC_ABSTRACTSYNTAX_UNSUPPORTED (1)
#define RPC_NCA_UNK_IF                 (0x1c010003)

#define RPC_BTFN_SEC_CONTEXT_MULTIPLEX (1)
#define RPC_BTFN_KEEP_ORPHAN           (2)

#define RPC_PT_REQUEST            0
#define RPC_PT_RESPONSE           2
#define RPC_PT_FAULT              3
#define RPC_PT_BIND_REQ          11
#define RPC_PT_BIND_ACK          12
#define RPC_PT_ALTERCONTEXT_REQ  14
#define RPC_PT_ALTERCONTEXT_ACK  15

#define RPC_PF_FIRST			  1
#define RPC_PF_LAST				  2
#define RPC_PF_NOT_EXEC			 32

bool rpcGetRequestHeader(const SOCKET sock, RPC_HEADER& rpcRequestHeader);
bool rpcGetRequestLength(const RPC_HEADER& rpcRequestHeader, unsigned int& request_len);
bool rpcGetRequest(const SOCKET sock, BYTE* requestBuffer, const unsigned int& request_len);
bool rpcCreateResponse(WORD& NdrCtx, WORD& Ndr64Ctx, RPC_HEADER& rpcRequestHeader, BYTE* requestBuffer, const unsigned int& request_len, BYTE* responseBuffer, unsigned int& response_len, const DWORD rpcAssocGroup, const char* ipstr, const char* localPort);
bool rpcSendResponse(SOCKET sock, BYTE* responseBuffer, const unsigned int& response_len);
