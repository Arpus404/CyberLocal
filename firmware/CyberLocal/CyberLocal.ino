#include <WiFi.h>
#include <BLEDevice.h>
#include <BLEScan.h>
#include <ArduinoJson.h>

// Arduino ESP32 2.0.17, ArduinoJson 6.21.5, carte ESP32 Dev Module.
// Une ligne JSON par commande/réponse. Scan passif uniquement.
void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  BLEDevice::init("");
  Serial.setTimeout(1000);
}

void replyError(const char* kind) {
  StaticJsonDocument<128> d;
  d["type"] = "scan"; d["kind"] = kind; d["ok"] = false;
  serializeJson(d, Serial); Serial.println();
}

void loop() {
  if (!Serial.available()) { delay(20); return; }
  String line = Serial.readStringUntil('\n');
  if (line.length() > 256) return;
  StaticJsonDocument<256> command;
  if (deserializeJson(command, line)) return;
  String cmd = command["cmd"] | "";
  if (cmd == "hello") {
    Serial.println("{\"type\":\"hello\",\"protocol\":1,\"chip\":\"ESP32\"}");
    return;
  }
  if (cmd != "wifi" && cmd != "ble") return;
  DynamicJsonDocument result(24576);
  result["type"] = "scan"; result["kind"] = cmd; result["ok"] = true;
  JsonArray entries = result.createNestedArray("items");
  if (cmd == "wifi") {
    int n = WiFi.scanNetworks(false, true);
    if (n < 0) { replyError("wifi"); return; }
    for (int i = 0; i < n && i < 50; i++) {
      JsonObject item = entries.createNestedObject();
      item["ssid"] = WiFi.SSID(i); item["bssid"] = WiFi.BSSIDstr(i);
      item["channel"] = WiFi.channel(i); item["rssi_dbm"] = WiFi.RSSI(i);
      item["security_code"] = (int) WiFi.encryptionType(i);
    }
    WiFi.scanDelete();
  } else {
    BLEScan* scanner = BLEDevice::getScan();
    scanner->setActiveScan(false);
    BLEScanResults found = scanner->start(5, false);
    for (int i = 0; i < found.getCount() && i < 50; i++) {
      BLEAdvertisedDevice device = found.getDevice(i);
      JsonObject item = entries.createNestedObject();
      item["name"] = String(device.getName().c_str());
      item["address"] = String(device.getAddress().toString().c_str());
      item["rssi_dbm"] = device.getRSSI();
      item["discovery"] = "BLE passif";
    }
    scanner->clearResults();
  }
  if (result.overflowed()) { replyError(cmd.c_str()); return; }
  serializeJson(result, Serial); Serial.println();
}
