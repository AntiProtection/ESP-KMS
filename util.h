#pragma once
#include <Arduino.h>

typedef unsigned long long	QWORD;
typedef unsigned long       DWORD;
typedef int                 BOOL;
typedef unsigned char       BYTE;
typedef unsigned short      WORD;
typedef wchar_t				WCHAR;

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
