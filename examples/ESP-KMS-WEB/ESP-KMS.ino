#ifdef ESP32
#include <WiFi.h>
#include <ESPmDNS.h>
#elif defined(ESP8266)
#include <ESP8266WiFi.h>
#include <ESP8266mDNS.h>
#endif
#include <WebServer.h>
#include <EEPROM.h>
#include <libkms.h>

static String AP_SSID = "ESP-KMS";
static String AP_PASS = "12345678";
static String STA_SSID;
static String STA_PASS;
static String MDNS_NAME;
static int KMS_PORT = 1688;

static const WCHAR ePID[] = u"00000-00000-000-000000-00-0000-0000.0000-0000000";
static const QWORD HWID = 0x0000000000000000;

WebServer server(80);

const char index_html[] PROGMEM = R"rawliteral(
<!DOCTYPE HTML>
<html>

<head>
    <title>ESP-KMS Configure</title>
    <h1>ESP-KMS Configure</h1>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <script>
        function submitMessage(msg) {
            alert(msg);
            setTimeout(function () { document.location.reload(false); }, 500);
        }
    </script>
</head>

<body>
    <fieldset>     
        <legend>Wi-Fi Setting</legend>
        <form action="/Set_Wi-Fi_SSID" target="hidden-form">
            Wi-Fi SSID <input type="text" name="Wi-Fi_SSID">
            <input type="submit" value="Change" onclick="submitMessage('Wi-Fi SSID was saved.')">
        </form><br>
        <form action="/Set_Wi-Fi_Password" target="hidden-form">
            Wi-Fi Password <input type="text" name="Wi-Fi_Password">
            <input type="submit" value="Change" onclick="submitMessage('Wi-Fi Password was saved.')">
        </form><br>
        <form action="/Set_MDNS" target="hidden-form">
            MDNS <input type="text" name="MDNS">
            <input type="submit" value="Change" onclick="submitMessage('MDNS was saved.')">
        </form><br>
    </fieldset>
    <iframe style="display:none" name="hidden-form"></iframe>
</body>

</html>
)rawliteral";

void KmsCallback(const REQUEST* const request, RESPONSE* const response, QWORD* const hwId, const char* ipstr) {
  response->Version = request->Version;
  response->PIDSize = sizeof(ePID);
  memcpy(response->KmsPID, ePID, response->PIDSize);
  response->CMID = request->CMID;
  response->ClientTime = request->ClientTime;
  response->Count = request->N_Policy;
  response->VLActivationInterval = 120;
  response->VLRenewalInterval = 10800;
  *hwId = HWID;
  Serial.print("Accepted from ");
  Serial.println(ipstr);
}

void setup() {
  Serial.begin(115200);
  EEPROM.begin(160);

  // Use this code for initialize EEPROM
/*
  EEPROM.writeString(0, "Input SSID");
  EEPROM.writeString(32, "Input Password");
  EEPROM.writeString(64, "Input MDNS");
  EEPROM.commit();
*/

  STA_SSID = EEPROM.readString(0);
  STA_PASS = EEPROM.readString(32);
  MDNS_NAME = EEPROM.readString(96);

  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP(AP_SSID.c_str(), AP_PASS.c_str());
  if (STA_PASS.isEmpty()) WiFi.begin(STA_SSID.c_str());
  else WiFi.begin(STA_SSID.c_str(), STA_PASS.c_str());

  MDNS.begin(MDNS_NAME.c_str());

  server.on("/", HTTP_GET, []() {
    server.send(200, "text/html", index_html);
  });
  server.on("/Set_Wi-Fi_SSID", HTTP_GET, []() {
    if (server.hasArg("Wi-Fi_SSID") && server.arg("Wi-Fi_SSID").length() < 32) {
      STA_SSID = server.arg("Wi-Fi_SSID");
      EEPROM.writeString(0, STA_SSID);
      EEPROM.commit();
      if (STA_PASS.isEmpty()) WiFi.begin(STA_SSID.c_str());
      else WiFi.begin(STA_SSID.c_str(), STA_PASS.c_str());
    }
    server.send(200, "text/html", index_html);
  });
  server.on("/Set_Wi-Fi_Password", HTTP_GET, []() {
    if (server.hasArg("Wi-Fi_Password") && server.arg("Wi-Fi_Password").length() < 64) {
      STA_PASS = server.arg("Wi-Fi_Password");
      EEPROM.writeString(32, STA_PASS);
      EEPROM.commit();
      if (STA_PASS.isEmpty()) WiFi.begin(STA_SSID.c_str());
      else WiFi.begin(STA_SSID.c_str(), STA_PASS.c_str());
    }
    server.send(200, "text/html", index_html);
  });
  server.on("/Set_MDNS", HTTP_GET, []() {
    if (server.hasArg("MDNS") && server.arg("MDNS").length() < 64) {
      MDNS_NAME = server.arg("MDNS");
      EEPROM.writeString(96, MDNS_NAME);
      EEPROM.commit();
      MDNS.begin(MDNS_NAME.c_str());
    }
    server.send(200, "text/html", index_html);
  });
  server.onNotFound([]() {
    server.send(404, "text/plain", "Not Found");
  });
  server.begin();

  StartKMSServer(KMS_PORT, KmsCallback);
}

void loop() {
  server.handleClient();
  UpdateKMSServer();
#ifdef ESP8266
  MDNS.update();
#endif
}