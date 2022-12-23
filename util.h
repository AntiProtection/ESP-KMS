#pragma once
#include <Arduino.h>
#ifdef ESP32
#include <WiFi.h>
#elif defined(ESP8266)
#include <ESP8266WiFi.h>
#endif

typedef WiFiClient SOCKET;

typedef uint64_t	QWORD;
typedef uint32_t	DWORD;
typedef bool	BOOL;
typedef uint8_t	BYTE;
typedef uint16_t	WORD;
typedef char16_t	WCHAR;

struct GUID {
	DWORD  Data1;
	WORD Data2;
	WORD Data3;
	BYTE Data4[8];
};

struct FILETIME {
	DWORD dwLowDateTime;
	DWORD dwHighDateTime;
};

inline WORD BE16(WORD value)
{
	WORD ret;
	ret = value << 8;
	ret |= value >> 8;
	return ret;
}
inline DWORD BE32(DWORD value)
{
	DWORD ret;
	ret = value << 24;
	ret |= (value & 0x0000FF00) << 8;
	ret |= (value & 0x00FF0000) >> 8;
	ret |= value >> 24;
	return ret;
}
inline QWORD BE64(QWORD value)
{
	QWORD ret;
	ret = value << 56;
	ret |= (value & 0x000000000000FF00) << 40;
	ret |= (value & 0x0000000000FF0000) << 24;
	ret |= (value & 0x00000000FF000000) << 8;
	ret |= (value & 0x000000FF00000000) >> 8;
	ret |= (value & 0x0000FF0000000000) >> 24;
	ret |= (value & 0x00FF000000000000) >> 40;
	ret |= value >> 56;
	return ret;
}
