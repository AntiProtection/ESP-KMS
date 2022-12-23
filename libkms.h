#pragma once
#include "kms.h"
#include "util.h"

void StartKMSServer(const int port, const RequestCallback_t requestCallback, uint8_t max_clients = 4);
void StopKMSServer();
void UpdateKMSServer();
int GetClientCount();
void SetTimeout(int timeout);
