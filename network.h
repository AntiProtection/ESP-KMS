#include "util.h"

bool _send(SOCKET sock, const char* data, int len)
{
	return len == sock.write(data, len);
}

bool _recv(SOCKET sock, char* data, int len)
{
	if (sock.available() < len) return false;
#ifdef ESP32
	return len == sock.read((uint8_t*)data, len);
#elif defined(ESP8266)
	return len == sock.read(data, len);
#endif
}
