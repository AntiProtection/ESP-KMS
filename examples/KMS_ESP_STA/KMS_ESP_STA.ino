#ifdef ESP32
#include <WiFi.h>
#include <ESPmDNS.h>
#elif defined(ESP8266)
#include <ESP8266WiFi.h>
#include <ESP8266mDNS.h>
#endif
#include "libkms.h"

static const char* STA_SSID = "********";
static const char* STA_PASS = "********";
static const char* MDNS_NAME = "KMS";
static const int KMS_PORT = 1688;

static const WCHAR ePID[] = L"00000-00000-000-000000-00-0000-0000.0000-0000000";
static const QWORD HWID = 0x0000000000000000;

void KmsCallback(const REQUEST* const request, RESPONSE* const response, QWORD* const hwId, const char* ipstr)
{
	response->Version = request->Version;
	response->PIDSize = sizeof(ePID);
	memcpy(response->KmsPID, ePID, sizeof(ePID));
	response->CMID = request->CMID;
	response->ClientTime = request->ClientTime;
	response->Count = request->N_Policy;
	response->VLActivationInterval = 120;
	response->VLRenewalInterval = 10800;
	*hwId = HWID;
}

void setup() {
	WiFi.mode(WIFI_STA);
#ifdef ESP32
	WiFi.onEvent([](WiFiEvent_t event, WiFiEventInfo_t info) {
		WiFi.disconnect(true);
		WiFi.begin(STA_SSID, STA_PASS);
		if (WiFi.waitForConnectResult() != WL_CONNECTED) ESP.restart();
		}, SYSTEM_EVENT_STA_DISCONNECTED);
#elif defined(ESP8266)
	WiFi.onStationModeDisconnected([](const WiFiEventStationModeDisconnected& event)
		{
			WiFi.disconnect(true);
			WiFi.begin(STA_SSID, STA_PASS);
			if (WiFi.waitForConnectResult() != WL_CONNECTED) ESP.restart();
		});
#endif
	WiFi.begin(STA_SSID, STA_PASS);
	WiFi.waitForConnectResult();
	MDNS.begin(MDNS_NAME);
	StartKMSServer(KMS_PORT, KmsCallback);
}

void loop() { 
	UpdateKMSServer();
#ifdef ESP8266
	MDNS.update();
#endif
}
