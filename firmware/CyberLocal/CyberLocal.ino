#include <ArduinoJson.h>
#include <BLEDevice.h>
#include <BLEScan.h>
#include <WiFi.h>

// Carte ESP32 Dev Module, Arduino ESP32 2.0.17 et ArduinoJson 6.21.5.
// Le protocole série échange une commande et une réponse JSON par ligne.
// Le Wi-Fi est limité à 2,4 GHz ; le scan Bluetooth est BLE passif.

namespace {

constexpr unsigned long SERIAL_TIMEOUT_MS = 1000;
constexpr int MAX_RESULTS = 50;
constexpr size_t MAX_COMMAND_LENGTH = 256;

void reply_error(const char* kind) {
    StaticJsonDocument<128> response;
    response["type"] = "scan";
    response["kind"] = kind;
    response["ok"] = false;

    serializeJson(response, Serial);
    Serial.println();
}

bool scan_wifi(JsonArray results) {
    const int network_count = WiFi.scanNetworks(false, true);
    if (network_count < 0) {
        reply_error("wifi");
        return false;
    }

    for (int index = 0; index < network_count && index < MAX_RESULTS; ++index) {
        JsonObject network = results.createNestedObject();
        network["ssid"] = WiFi.SSID(index);
        network["bssid"] = WiFi.BSSIDstr(index);
        network["channel"] = WiFi.channel(index);
        network["rssi_dbm"] = WiFi.RSSI(index);
        network["security_code"] = static_cast<int>(WiFi.encryptionType(index));
    }

    WiFi.scanDelete();
    return true;
}

bool scan_ble(JsonArray results) {
    BLEScan* scanner = BLEDevice::getScan();
    scanner->setActiveScan(false);

    BLEScanResults devices = scanner->start(5, false);
    const int device_count = devices.getCount();

    for (int index = 0; index < device_count && index < MAX_RESULTS; ++index) {
        BLEAdvertisedDevice device = devices.getDevice(index);
        JsonObject result = results.createNestedObject();
        result["name"] = String(device.getName().c_str());
        result["address"] = String(device.getAddress().toString().c_str());
        result["rssi_dbm"] = device.getRSSI();
        result["discovery"] = "BLE passif";
    }

    scanner->clearResults();
    return true;
}

void handle_command(const JsonDocument& command) {
    const String kind = command["cmd"] | "";

    if (kind == "hello") {
        Serial.println(
            "{\"type\":\"hello\",\"protocol\":1,\"chip\":\"ESP32\"}"
        );
        return;
    }

    if (kind != "wifi" && kind != "ble") {
        return;
    }

    DynamicJsonDocument response(24576);
    response["type"] = "scan";
    response["kind"] = kind;
    response["ok"] = true;
    JsonArray results = response.createNestedArray("items");

    const bool scan_succeeded =
        kind == "wifi" ? scan_wifi(results) : scan_ble(results);
    if (!scan_succeeded) {
        return;
    }

    if (response.overflowed()) {
        reply_error(kind.c_str());
        return;
    }

    serializeJson(response, Serial);
    Serial.println();
}

}  // namespace

void setup() {
    Serial.begin(115200);
    Serial.setTimeout(SERIAL_TIMEOUT_MS);

    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    BLEDevice::init("");
}

void loop() {
    if (!Serial.available()) {
        delay(20);
        return;
    }

    String line = Serial.readStringUntil('\n');
    if (line.length() > MAX_COMMAND_LENGTH) {
        return;
    }

    StaticJsonDocument<256> command;
    if (deserializeJson(command, line)) {
        return;
    }

    handle_command(command);
}
