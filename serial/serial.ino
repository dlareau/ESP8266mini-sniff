// Credits
// Original RTOS version https://github.com/espressif/esp8266-rtos-sample-code/tree/master/03Wifi/Sniffer_DEMO/sniffer
// Converted to Arduino https://github.com/RandDruid/esp8266-deauth and https://github.com/kripthor/WiFiBeaconJam
// Code refactor and improvements Ray Burnette https://www.hackster.io/rayburne/esp8266-mini-sniff-f6b93a
// This version fixes handling of PROBE packets, further refactors code
// This version compiled on Windows 10/Arduino 1.6.5 for Wemos D1 mini but should work on any ESP8266 28Jul2017
// Tested on SDK version:1.5.4(baaeaebb)
// Using Visual Studio Code and the Arduino extension https://marketplace.visualstudio.com/items?itemName=vsciot-vscode.vscode-arduino

#include <ESP8266WiFi.h>


#include "functions.h"

#define disable 0
#define enable  1

#define MAX_APS_TRACKED 200
#define MAX_CLIENTS_TRACKED 200

managementInfo aps_known[MAX_APS_TRACKED];                    // Array to save MACs of known APs
dataInfo clients_known[MAX_CLIENTS_TRACKED];            // Array to save MACs of known CLIENTs
managementInfo probes_known[MAX_CLIENTS_TRACKED];            // Array to save MACs of known CLIENTs
int aps_known_count = 0;                                  // Number of known APs
int clients_known_count = 0;                              // Number of known CLIENTs
int probes_known_count = 0;
int nothing_new = 0;

unsigned int channel = 1;

void setup() {
  Serial.begin(57600);
  Serial.printf("\n\nSDK version:%s\n\r", system_get_sdk_version());
  Serial.println(F("ESP8266 mini-sniff"));
  Serial.println(F("Type:   /-------MAC------/-----WiFi Access Point SSID-----/  /----MAC---/  Chnl  RSSI"));

  wifi_set_opmode(STATION_MODE);            // Promiscuous works only with station mode
  wifi_set_channel(channel);
  wifi_promiscuous_enable(disable);
  wifi_set_promiscuous_rx_cb(promisc_cb);   // Set up promiscuous callback
  wifi_promiscuous_enable(enable);

}

void loop() {
  channel = 1;
  wifi_set_channel(channel);
  while (true) {
    nothing_new++;                          // Array is not finite, check bounds and adjust if required
    if (nothing_new > 200) {
      nothing_new = 0;
      channel++;
      if (channel == 15) break;             // Only scan channels 1 to 14
      wifi_set_channel(channel);
    }
    delay(1);  // critical processing timeslice for NONOS SDK! No delay(0) yield()
    // Press keyboard ENTER in console with NL active to repaint the screen
    if ((Serial.available() > 0) && (Serial.read() == '\n')) {
      Serial.println("\n-------------------------------------------------------------------------------------\n");
      for (int u = 0; u < clients_known_count; u++) print_client(clients_known[u]);
      for (int u = 0; u < aps_known_count; u++) print_beacon(aps_known[u]);
      for (int u = 0; u < probes_known_count; u++) print_probe(probes_known[u]);
      Serial.println("\n-------------------------------------------------------------------------------------\n");

    }

  }

}

