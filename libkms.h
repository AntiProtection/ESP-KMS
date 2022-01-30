#pragma once
#include "kms.h"
#include "util.h"
#ifdef ESP32
#include <WiFi.h>
#elif defined(ESP8266)
#include <ESP8266WiFi.h>
#endif

typedef WiFiClient SOCKET;
bool _send(SOCKET sock, const char* data, int len);
bool _recv(SOCKET sock, char* data, int len); 

void StartKMSServer(const int port, const RequestCallback_t requestCallback, uint8_t max_clients = 4);
void StopKMSServer();
void UpdateKMSServer();
int GetClientCount();
void SetTimeout(int timeout);
