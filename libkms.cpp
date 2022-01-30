#include "rpc.h"
#include "libkms.h"

bool _send(SOCKET sock, const char* data, int len)
{
	if (!sock.connected()) return false;
	return len == sock.write(data, len);
}
bool _recv(SOCKET sock, char* data, int len)
{
	if (!sock.connected() || sock.available() < len) return false;
#ifdef ESP32
	return len == sock.read((uint8_t*)data, len);
#elif defined(ESP8266)
	return len == sock.read(data, len);
#endif
}

static DWORD TIMEOUT = 30000;

class ServerTask {
	SOCKET sock;
	WORD NdrCtx = RPC_INVALID_CTX, Ndr64Ctx = RPC_INVALID_CTX;
	RPC_HEADER rpcRequestHeader;
	unsigned int request_len;
	unsigned int response_len;
	BYTE requestBuffer[MAX_REQUEST_SIZE + sizeof(RPC_RESPONSE64)];
	BYTE responseBuffer[MAX_RESPONSE_SIZE + sizeof(RPC_HEADER) + sizeof(RPC_RESPONSE64)];

	int count;
	uint32_t last_time;
	uint32_t rpcAssocGroup;
	String remoteIP;
	String localPort;
public:
	ServerTask(const SOCKET& _sock, uint32_t _rpcAssocGroup, const IPAddress _remoteIP, const uint16_t _localPort) {
		sock = _sock;
		rpcAssocGroup = _rpcAssocGroup;
		remoteIP = _remoteIP.toString();
		localPort = String(_localPort);
		count = 0;
		last_time = millis();
	}
	virtual ~ServerTask() { sock.stop(); }
	bool server_loop() {
		if (!sock.connected()) return false;
		switch (count) {
		case 0: if (!rpcGetRequestHeader(sock, rpcRequestHeader)) break; else last_time = millis(); count++;
		case 1: if (!rpcGetRequestLength(rpcRequestHeader, request_len)) return false; else count++;
		case 2: if (!rpcGetRequest(sock, requestBuffer, request_len)) break; else last_time = millis(); count++;
		case 3: if (!rpcCreateResponse(NdrCtx, Ndr64Ctx, rpcRequestHeader, requestBuffer, request_len, responseBuffer, response_len, rpcAssocGroup, remoteIP.c_str(), localPort.c_str())) return false; else count++;
		case 4: if (!rpcSendResponse(sock, responseBuffer, response_len)) return false; else count = 0;
		}
		if (millis() - last_time > TIMEOUT) return false;
		return true;
	}
};

static int MAX_CLIENTS;
static ServerTask** ServerTasks;
static bool* ClientStatus;
static int ClientCount;

static WiFiServer* ServerSock = nullptr;
static DWORD RpcAssocGroup;

int GetClientCount() { return ClientCount; }
void SetTimeout(int timeout) { TIMEOUT = timeout; }

void StartKMSServer(const int port, const RequestCallback_t requestCallback, uint8_t max_clients) {
	if (ServerSock) return;
	MAX_CLIENTS = max_clients;
	ServerTasks = new ServerTask * [MAX_CLIENTS];
	ClientStatus = new bool[MAX_CLIENTS];
	memset(ClientStatus, false, MAX_CLIENTS);
	SetCreateResponseBase(requestCallback);
#ifdef ESP32
	ServerSock = new WiFiServer(port, max_clients);
#elif defined(ESP8266)
	ServerSock = new WiFiServer(port);
#endif
	ServerSock->begin();
	ClientCount = 0;
	srand(micros());
	RpcAssocGroup = rand();
}

void StopKMSServer() {
	if (!ServerSock) return;
	ServerSock->stop();
	delete ServerSock;
	ServerSock = nullptr;
	for (int i = 0; i < MAX_CLIENTS; i++) if (ClientStatus[i]) delete ServerTasks[i];
	delete[] ServerTasks;
	delete[] ClientStatus;
}

void UpdateKMSServer() {
	if (!ServerSock) return;
	for (int i = 0; i < MAX_CLIENTS; i++) if (ClientStatus[i] && !ServerTasks[i]->server_loop()) { delete ServerTasks[i]; ClientStatus[i] = false; ClientCount--; }

	if (ClientCount >= MAX_CLIENTS) return;
	SOCKET sock = ServerSock->available();
	if (sock && sock.connected()) {
		RpcAssocGroup++;
		ServerTask* task = new ServerTask(sock, RpcAssocGroup, sock.remoteIP(), sock.localPort());
		for (int i = 0; i < MAX_CLIENTS; i++) { if (!ClientStatus[i]) { ServerTasks[i] = task; ClientStatus[i] = true; ClientCount++; break; } }
	}
}
