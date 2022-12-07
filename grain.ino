#include <DHT.h>  
#include <DHT_U.h>  
#include <ESP8266WiFi.h>
#include <PubSubClient.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <stdbool.h>
#include "base64.h"

// Update these with values suitable for your network.
const char* ssid = "Hp123";
const char* password = "pipimimi01";
const char* mqtt_server = "test.mosquitto.org";

#ifndef GRAIN_H
#define GRAIN_H

#define INITCLOCKS 160
#define N(i) (mygrain->NFSR[80-i])
#define L(i) (mygrain->LFSR[80-i])
#define X0 (mygrain->LFSR[3])
#define X1 (mygrain->LFSR[25])
#define X2 (mygrain->LFSR[46])
#define X3 (mygrain->LFSR[64])
#define X4 (mygrain->NFSR[63])

typedef struct
{
  int LFSR[80];
  int NFSR[80];
  const int* p_key;
  int keysize;
  int ivsize;

} grain;

void keysetup(
  grain* mygrain,
  const int* key,
  int keysize,                
  int ivsize);                

void ivsetup(
  grain* mygrain,
  const int* iv);

void keystream_bytes(
  grain* mygrain,
  int* keystream,
  int length);

void encrypt_bytes(
  grain* mygrain,
  const int* plaintext,
  int* ciphertext,
  int msglen);                

void decrypt_bytes(
  grain* mygrain,
  const int* ciphertext,
  int* plaintext,
  int msglen);

#endif


#define DHTPIN D7         
DHT dht(DHTPIN, DHT11);

WiFiClient espClient;
PubSubClient client(espClient);
unsigned long lastMsg = 0;
#define MSG_BUFFER_SIZE  (50)
char msg[MSG_BUFFER_SIZE];
int value = 0;

void setup_wifi() {
  delay(10);
  // We start by connecting to a WiFi network
  Serial.println();
  Serial.print("Connecting to ");
  Serial.println(ssid);

  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  randomSeed(micros());

  Serial.println("");
  Serial.println("WiFi connected");
  Serial.println("IP address: ");
  Serial.println(WiFi.localIP());
}

void callback(char* topic, byte* payload, unsigned int length) {
  Serial.print("Message arrived [");
  Serial.print(topic);
  Serial.print("] ");
  for (int i = 0; i < length; i++) {
    Serial.print((char)payload[i]);
  }
  Serial.println();

  // Switch on the LED if an 1 was received as first character
  if ((char)payload[0] == '1') {
    digitalWrite(BUILTIN_LED, LOW);   // Turn the LED on (Note that LOW is the voltage level
    // but actually the LED is on; this is because
    // it is active low on the ESP-01)
  } else {
    digitalWrite(BUILTIN_LED, HIGH);  // Turn the LED off by making the voltage HIGH
  }

}

void reconnect() {
  // Loop until we're reconnected
  while (!client.connected()) {
    Serial.print("Attempting MQTT connection...");
    // Create a random client ID
    String clientId = "ESP8266Client-";
    clientId += String(random(0xffff), HEX);
    // Attempt to connect
    if (client.connect(clientId.c_str())) {
      Serial.println("connected");
      // Once connected, publish an announcement...
      client.publish("IOTp3nguji4N", "hello world");
      // ... and resubscribe
      client.subscribe("inTopic");
    } else {
      Serial.print("failed, rc=");
      Serial.print(client.state());
      Serial.println(" try again in 5 seconds");
      // Wait 5 seconds before retrying
      delay(5000);
    }
  }
}

void setup() {
  Serial.begin(9600); 
  dht.begin(); 
  
  setup_wifi();
  client.setServer(mqtt_server, 1883);
  client.setCallback(callback);
}



int grain_keystream(grain* mygrain) {
  int i,NBit,LBit,outbit;
  /* Calculate feedback and output bits */
  outbit = N(79)^N(78)^N(76)^N(70)^N(49)^N(37)^N(24) ^ X1 ^ X4 ^ X0&X3 ^ X2&X3 ^ X3&X4 ^ X0&X1&X2 ^ X0&X2&X3 ^ X0&X2&X4 ^ X1&X2&X4 ^ X2&X3&X4;

  NBit=L(80)^N(18)^N(20)^N(28)^N(35)^N(43)^N(47)^N(52)^N(59)^N(66)^N(71)^N(80)^
      N(17)&N(20) ^ N(43)&N(47) ^ N(65)&N(71) ^ N(20)&N(28)&N(35) ^ N(47)&N(52)&N(59) ^ N(17)&N(35)&N(52)&N(71)^
      N(20)&N(28)&N(43)&N(47) ^ N(17)&N(20)&N(59)&N(65) ^ N(17)&N(20)&N(28)&N(35)&N(43) ^ N(47)&N(52)&N(59)&N(65)&N(71)^
      N(28)&N(35)&N(43)&N(47)&N(52)&N(59);
  LBit=L(18)^L(29)^L(42)^L(57)^L(67)^L(80);
  /* Update registers */
  for (i=1;i<(mygrain->keysize);++i) {
    mygrain->NFSR[i-1]=mygrain->NFSR[i];
    mygrain->LFSR[i-1]=mygrain->LFSR[i];
  }
  mygrain->NFSR[(mygrain->keysize)-1]=NBit;
  mygrain->LFSR[(mygrain->keysize)-1]=LBit;
  return outbit;
}

void keysetup(
  grain* mygrain,
  const int* key,
  int keysize,      /* Key size in bits. */
  int ivsize)     /* IV size in bits. */
{
  mygrain->p_key=key;
  mygrain->keysize=keysize;
  mygrain->ivsize=ivsize;
}

void ivsetup(
  grain* mygrain,
  const int* iv)
{
  int i,j;
  int outbit;
  /* load registers */
  for (i=0;i<(mygrain->ivsize)/8;++i) {
    for (j=0;j<8;++j) {
      mygrain->NFSR[i*8+j]=((mygrain->p_key[i]>>j)&1);
      mygrain->LFSR[i*8+j]=((iv[i]>>j)&1);
    }
  }
  for (i=(mygrain->ivsize)/8;i<(mygrain->keysize)/8;++i) {
    for (j=0;j<8;++j) {
      mygrain->NFSR[i*8+j]=((mygrain->p_key[i]>>j)&1);
      mygrain->LFSR[i*8+j]=1;
    }
  }
  /* do initial clockings */
  for (i=0;i<INITCLOCKS;++i) {
    outbit=grain_keystream(mygrain);
    mygrain->LFSR[79]^=outbit;  /* LFSR[79] = LFSR[79] ^ outbit */
    mygrain->NFSR[79]^=outbit;  /* NFSR[79] = NFSR[79] ^ outbit */
  }
}

void keystream_bytes(
  grain* mygrain,
  int* keystream,
  int msglen)
{
  int i,j;
  for (i = 0; i < msglen; ++i) {
    keystream[i]=0;
    for (j = 0; j < 8; ++j) {
      keystream[i]|=(grain_keystream(mygrain)<<j);
    }
  }
}
void encrypt_bytes(
  grain* mygrain,
  const int* plaintext,
  int* ciphertext,
  int msglen)
{
  int i,j;
  int k;
  for (i = 0; i < msglen; ++i) {
    k=0;
    for (j = 0; j < 8; ++j) {
      k|=(grain_keystream(mygrain)<<j);
    }
    ciphertext[i]=plaintext[i]^k;
  }
}

void decrypt_bytes(
  grain* mygrain,
  const int* ciphertext,
  int* plaintext,
  int msglen)
{
  int i,j;
  int k=0;
  for (i = 0; i < msglen; ++i) {
    k=0;
    for (j = 0; j < 8; ++j) {
      k|=(grain_keystream(mygrain)<<j);
    }
    plaintext[i]=ciphertext[i]^k;
  }
}

void printData(int *key, int *IV, int *ks, int *pt, int *et, int *dt, int sizeOfPlaintext) {
  int i; char sykey[256], syIV[256], syks[256], sypt[256], syet[256], sydt[256];

  Serial.print("\nkey            : ");
  for (i=0;i<8;++i){ sprintf(sykey,"%02X ",(int)key[i]); Serial.print(sykey);}
  Serial.print("\nIV             : ");
  for (i=0;i<8;++i){ sprintf(syIV, "%02x ",(int)IV[i]); Serial.print(syIV);}
  Serial.print("\nkeystream      : ");
  for (i=0;i<8;++i) { sprintf(syks, "%02x ",(int)ks[i]); Serial.print(syks);}
  Serial.print("\nplaintext      : ");
  for (i=0;i<sizeOfPlaintext;i++){ sprintf(sypt,"%02x ",(int)pt[i]); Serial.print(sypt);}
  Serial.print("\nencrypted text : ");
  for (i=0;i<sizeOfPlaintext;i++){ sprintf(syet, "%02X ",(int)et[i]); Serial.print(syet);}
  Serial.print("\ndecrypted text : ");
  for (i=0;i<sizeOfPlaintext;i++){ sprintf(sydt, "%02x ",(int)dt[i]); Serial.print(sydt);}
  Serial.println("\n----------------------------------------------");
}

int* convertToHexInt(int *result, char *str) {

    for (int i = 0; i < strlen(str); i++)
    {
        char temp[5] = "";
        sprintf(temp, "%#02X", str[i]);
        int number = (int)strtol(temp, NULL, 0);
        result[i] = number;
    }
   
    return result;
}

void loop() {

// koneksi wifi
  if (!client.connected()) {
    reconnect();
  }
  client.loop();

  float t = dht.readTemperature();
  Serial.print(F("Suhu : "));
  Serial.print(t);
  Serial.println(F("°C "));
  delay(10000);
  
    char result[256];
      int i;
      char rdm[256] = " ";
      for (i = 0; i < 4; i++) {
        char randomletter = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890"[random () % 62];
        strncat(rdm, &randomletter, 1);
      }
    sprintf(result, "%s", rdm);

    char key[10] = "syafa123"; //kunci 
    char text[8]; 
    sprintf(text, "%.2f", t);
    
    strcat(text, ";");
    strcat(text, result);
    Serial.println(text); //data digabung dengan random string disimpan pada var text
    
    int resultKey[8];
    int resultText[8];
    int* key1 = convertToHexInt(resultKey, key); //mengubah key menjadi bilangan hex
    int* plaintext = convertToHexInt(resultText, text); //mengubah text menjadi bilangan hex
  
  int sizeOfPlaintext=8;
  int encrypted_text[8];
  int decrypted_text[8];

  grain mygrain;
  int IV1[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      ks[8];

  int n=1;

  keysetup(&mygrain,key1,80,64);
  ivsetup(&mygrain,IV1);
  keystream_bytes(&mygrain,ks,8);
  grain mygrain2 = mygrain;
  encrypt_bytes(&mygrain,plaintext,encrypted_text,8);
  decrypt_bytes(&mygrain2,encrypted_text,decrypted_text,8);
  printData(key1,IV1,ks, plaintext, encrypted_text, decrypted_text, 8);

//mengambil data hasil enkripsi untuk dikirimkan ke mqtt
  Serial.print("\n");
  char hasil[255];
  for (i=0;i<8;i++){ 
    sprintf(hasil, "%02X",(int)encrypted_text[i]); 
    Serial.print(hasil);
  }
  Serial.print("------------------------------");

  //mengambil data yang akan dikirim
  char *algoritma = "Grain V1";
  String data = String(hasil) + "," + String(algoritma);

  //mengubah string jadi char agar bisa dikirim ke mqtt
  int str_len = data.length() + 1; 
  char data_array[str_len];
  data.toCharArray(data_array, str_len);

  client.publish("IOTp3nguji4N", data_array);

}
