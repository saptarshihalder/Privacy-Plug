#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>
#include <MFRC522.h>
#include <SPI.h>

// ----- WiFi Config -----
const char* ssid = "IQOO NET";
const char* password = "Sapt2004";

// MQTT HiveMQ Broker over TLS
const char* mqtt_server = "34907036e79f49899c46b6fec77e7f23.s1.eu.hivemq.cloud";
const int mqtt_port = 8883; // SSL port
const char* mqtt_user = "RFID_1";
const char* mqtt_password = "RFID_rfid_1";

// TLS Certificate (HiveMQ uses a trusted CA; adjust if needed)
const char* root_ca = \
"-----BEGIN CERTIFICATE-----\n"
"MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw\n"
"TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh\n"
"cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4\n"
"WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu\n"
"ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY\n"
"MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc\n"
"h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+\n"
"0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U\n"
"A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW\n"
"T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH\n"
"B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC\n"
"B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv\n"
"KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn\n"
"OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn\n"
"jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw\n"
"qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI\n"
"rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV\n"
"HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq\n"
"hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL\n"
"ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ\n"
"3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK\n"
"NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5\n"
"ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur\n"
"TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC\n"
"jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc\n"
"oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq\n"
"4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA\n"
"mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d\n"
"emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=\n"
"-----END CERTIFICATE-----\n";

// Setup WiFiClientSecure
WiFiClientSecure secureClient;
PubSubClient client(secureClient);

// RFID setup
#define RST_PIN 0
#define SS_PIN  5
MFRC522 mfrc522(SS_PIN, RST_PIN);

// Card-to-device mapping
const char* deviceIDs[] = {"device1", "device2", "device3", "device4"};
const byte cardUIDs[][4] = {
  {0x53, 0x27, 0x10, 0xda},
  {0xCA, 0xFE, 0xBA, 0xBE},
  {0xFE, 0xED, 0xFA, 0xCE},
  {0xBA, 0xAD, 0xF0, 0x0D}
};

// Added special card for enable_permissions
const byte enableCardUID[4] = {0x03, 0x13, 0x08, 0xDA};

void setup() {
  Serial.begin(115200);
  SPI.begin();
  mfrc522.PCD_Init();

  connectToWiFi();
  setupSecureMQTT();
}

void loop() {
  if (!client.connected()) {
    reconnectMQTT();
  }
  client.loop();

  if (mfrc522.PICC_IsNewCardPresent() && mfrc522.PICC_ReadCardSerial()) {
    Serial.print("Card UID: ");
    for (byte i = 0; i < mfrc522.uid.size; i++) {
      Serial.print(mfrc522.uid.uidByte[i], HEX);
      Serial.print(" ");
    }
    Serial.println();

    byte* uid = mfrc522.uid.uidByte;

    // Check if it's the special enable card (03 13 08 DA)
    if (memcmp(uid, enableCardUID, 4) == 0) {
      Serial.println("Matched enable card for device1");
      publishEnableCommand("device1");
    } else {
      // Match the scanned UID against the list of known card UIDs
      for (int i = 0; i < 4; i++) {
        if (memcmp(uid, cardUIDs[i], 4) == 0) {
          Serial.printf("Matched card to %s\n", deviceIDs[i]);
          publishDisableCommand(deviceIDs[i]);
          break;
        }
      }
    }

    mfrc522.PICC_HaltA();
    delay(1000); // Prevent duplicate scans
  }
}

void connectToWiFi() {
  WiFi.begin(ssid, password);
  Serial.print("Connecting to Wi-Fi");
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nWiFi connected");
}

void setupSecureMQTT() {
  secureClient.setCACert(root_ca);  // Use certificate-based TLS
  client.setServer(mqtt_server, mqtt_port);
}

void reconnectMQTT() {
  while (!client.connected()) {
    Serial.print("Connecting to MQTT securely...");
    if (client.connect("ESP32Client", mqtt_user, mqtt_password)) {
      Serial.println("connected.");
    } else {
      Serial.print("failed, rc=");
      Serial.print(client.state());
      delay(2000);
    }
  }
}

void publishDisableCommand(const char* deviceID) {
  char topic[100];
  snprintf(topic, sizeof(topic), "esp32/disable/%s", deviceID);

  const char* message = "disable_permissions";

  if (client.publish(topic, message)) {
    Serial.printf("Published to topic %s: %s\n", topic, message);
  } else {
    Serial.println("Failed to publish.");
  }
}

// New function to publish enable permissions
void publishEnableCommand(const char* deviceID) {
  char topic[100];
  snprintf(topic, sizeof(topic), "esp32/enable/%s", deviceID);

  const char* message = "enable_permissions";

  if (client.publish(topic, message)) {
    Serial.printf("Published to topic %s: %s\n", topic, message);
  } else {
    Serial.println("Failed to publish.");
  }
}
