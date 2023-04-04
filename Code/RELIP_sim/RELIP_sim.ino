/*
  RELIP - Simulator
  Feil Charel
  BTS-IOT 2
  2022/2023
*/

#include <Crypto.h>
#include <AES.h>
#include <GCM.h>

#define REQ_PIN D1  //set data request pin

//variables for nonblocking delay
int prevMillis = 0;
int interval = 10000;

const unsigned int MAX_PLAINTEXT_LEN = 1200;

// Text to encrypt:
const char mytext[MAX_PLAINTEXT_LEN] = R"(
/Lux5\253663653_B

1-3:0.2.8(42)
0-0:1.0.0(230315155342W)
0-0:42.0.0(53414731303330373030303236353638)
1-0:1.8.0(000017.901*kWh)
1-0:2.8.0(055437.011*kWh)
1-0:3.8.0(001080.968*kvarh)
1-0:4.8.0(000828.854*kvarh)
1-0:1.7.0(00.000*kW)
1-0:2.7.0(03.454*kW)
1-0:3.7.0(00.025*kvar)
1-0:4.7.0(00.000*kvar)
0-0:17.0.0(069.0*kVA)
1-0:9.7.0(00.000*kVA)
1-0:10.7.0(03.450*kVA)
1-1:31.4.0(100*A)(-100*A)
0-0:96.3.10(1)
0-1:96.3.10(0)
0-2:96.3.10(0)
0-0:96.7.21(00914)
1-0:32.32.0(00011)
1-0:52.32.0(00012)
1-0:72.32.0(00011)
1-0:32.36.0(00001)
1-0:52.36.0(00001)
1-0:72.36.0(00001)
0-0:96.13.0()
0-0:96.13.2()
0-0:96.13.3()
0-0:96.13.4()
0-0:96.13.5()
1-0:32.7.0(236.0*V)
1-0:52.7.0(233.0*V)
1-0:72.7.0(235.0*V)
1-0:31.7.0(004*A)
1-0:51.7.0(004*A)
1-0:71.7.0(004*A)
1-0:21.7.0(00.000*kW)
1-0:41.7.0(00.000*kW)
1-0:61.7.0(00.000*kW)
1-0:22.7.0(01.160*kW)
1-0:42.7.0(01.146*kW)
1-0:62.7.0(01.147*kW)
1-0:23.7.0(00.007*kvar)
1-0:43.7.0(00.007*kvar)
1-0:63.7.0(00.010*kvar)
1-0:24.7.0(00.000*kvar)
1-0:44.7.0(00.000*kvar)
1-0:64.7.0(00.000*kvar)
!6B4A)"/*R"(
/Lux5\Charel
1-3:0.2.8(42)
0-0:1.0.0(221231160517W)
0-0:42.0.0(53414731303330373030313931333639)
1-0:1.8.0(20000*kWh)
1-0:2.8.0(012183.984*kWh)
1-0:3.8.0(003428.126*kvarh)
1-0:4.8.0(010884.835*kvarh)
1-0:1.7.0(02.606*kW)
1-0:2.7.0(00.000*kW)
1-0:3.7.0(01.006*kvar)
1-0:4.7.0(00.000*kvar)
0-0:17.0.0(069.0*kVA)
1-0:9.7.0(02.808*kVA)
1-0:10.7.0(00.000*kVA)
1-1:31.4.0(100*A)(-100*A)
0-0:96.3.10(1)
0-1:96.3.10(0)
0-2:96.3.10(0)
0-0:96.7.21(00031)
1-0:32.32.0(00006)
1-0:52.32.0(00005)
1-0:72.32.0(00004)
1-0:32.36.0(00000)
1-0:52.36.0(00000)
1-0:72.36.0(00000)
0-0:96.13.0()
0-0:96.13.2()
0-0:96.13.3()
0-0:96.13.4()
0-0:96.13.5()
1-0:32.7.0(232.0*V)
1-0:52.7.0(229.0*V)
1-0:72.7.0(231.0*V)
1-0:31.7.0(004*A)
1-0:51.7.0(004*A)
1-0:71.7.0(003*A)
1-0:21.7.0(01.005*kW)
1-0:41.7.0(00.925*kW)
1-0:61.7.0(00.675*kW)
1-0:22.7.0(00.000*kW)
1-0:42.7.0(00.000*kW)
1-0:62.7.0(00.000*kW)
1-0:23.7.0(00.272*kvar)
1-0:43.7.0(00.369*kvar)
1-0:63.7.0(00.364*kvar)
1-0:24.7.0(00.000*kvar)
1-0:44.7.0(00.000*kvar)
1-0:64.7.0(00.000*kvar)
!AF4A
)"*/;
const char myvname[] = "AES-128 GCM";                 // vector name
char mykey[] = "EBD3E604BA79E1D7CF9D2D1AB1033204";    // Key for SAG1030700089067 (16 byte)
char myAAD[] = "3000112233445566778899AABBCCDDEEFF";  // 17 byte (in Hex 34 character)
char myIV[] = "46656943680067C800000000";             // "SAGgp + "0x0067C8" + 4 byte counter

struct Vector_GCM {
  const char *name;
  static const byte keysize = 16;
  unsigned int datasize;
  static const byte authsize = 17;
  static const byte ivsize = 12;
  static const byte tagsize = 12;
  byte key[keysize];
  byte plaintext[MAX_PLAINTEXT_LEN];
  byte ciphertext[MAX_PLAINTEXT_LEN];
  byte authdata[authsize];
  byte iv[ivsize];
  byte tag[tagsize];
};

unsigned long counter = 0;

Vector_GCM my_vector;

void setup() {
  //Begin serial at baud rate 115200bit/s and 8n1
  Serial.begin(115200, SERIAL_8N1);
  //define data request pin as input
  pinMode(REQ_PIN, INPUT);
  delay(2500);

  // initialise the vector
  if (init_vector_GCM_encryption(my_vector, myvname, mykey, mytext, myAAD, myIV) != 0) {
    //reset ESP if vector initialisation failed
    ESP.reset();
  }
  delay(2500);
}

void loop() {
  //check if nonblocking delay has passed and if data is requested
  if ((digitalRead(REQ_PIN) == LOW) && (millis() >= prevMillis + interval)) {
    prevMillis = millis();

    /****** encrypt ******/
    encrypt_text(my_vector);

    //begin to write
    //starting byte
    Serial.write(0xDB);
    //calculate title length
    unsigned int titleLen = my_vector.ivsize - 4;
    Serial.write(titleLen);
    //write iv to Serial
    for (byte i = 0; i < my_vector.ivsize - 4; i++) {
      Serial.write(my_vector.iv[i]);
    }
    //write 0x82? because it's needed
    Serial.write(0x82);

    //calculate total length
    uint16_t totalLen = 17 + my_vector.datasize;

    //total length (16bit) needed to be split in 2 to write each byte separately to Serial
    Serial.write(highByte(totalLen));
    Serial.write(lowByte(totalLen));

    //write the Security byte
    Serial.write(0x30);
    //write counter to serial
    for (int i = 8; i < my_vector.ivsize; i++) {
      Serial.write(my_vector.iv[i]);
    }
    //write ciphertext to serial
    for (unsigned int i = 0; i < my_vector.datasize; i++) {
      Serial.write(my_vector.ciphertext[i]);
    }
    //add the tag to the end
    for (byte i = 0; i < my_vector.tagsize; i++) {
      Serial.write(my_vector.tag[i]);
    }
    //end

    /****** increment counter ******/
    increment_counter(my_vector, counter);
  }
  //yield to feed the watchdog
  yield();
}

// initialize the vector_structure from c-strings
int init_vector_GCM_encryption(Vector_GCM &vect, const char *vect_name, char *key,
                               const char *plaintext, char *aad, char *iv) {
  if (strlen(key) != (vect.keysize * 2)) {
    return -1;
  }
  if (strlen(aad) != (vect.authsize * 2)) {
    return -1;
  }
  if (strlen(iv) != (vect.ivsize * 2)) {
    return -1;
  }
  vect.name = vect_name;                     // init vector name
  c_string_hexbytes_2_bytes(key, vect.key);  // array passed by ref
  vect.datasize = strlen(plaintext);         // init plaintext
  for (unsigned int i = 0; i < vect.datasize; i++) {
    vect.plaintext[i] = mytext[i];
    yield();
  }
  c_string_hexbytes_2_bytes(aad, vect.authdata);  // array passed by ref
  c_string_hexbytes_2_bytes(iv, vect.iv);         // array passed by ref
  return 0;
}

void encrypt_text(Vector_GCM &vect) {
  GCM<AES128> *gcmaes128 = 0;
  gcmaes128 = new GCM<AES128>();
  gcmaes128->setKey(vect.key, gcmaes128->keySize());
  gcmaes128->setIV(vect.iv, vect.ivsize);
  gcmaes128->encrypt(vect.ciphertext, vect.plaintext, vect.datasize);
  gcmaes128->computeTag(vect.tag, vect.tagsize);
  delete gcmaes128;
}

void decrypt_text(Vector_GCM &vect) {
  GCM<AES128> *gcmaes128 = 0;
  gcmaes128 = new GCM<AES128>();
  gcmaes128->setKey(vect.key, gcmaes128->keySize());
  gcmaes128->setIV(vect.iv, vect.ivsize);
  gcmaes128->decrypt(vect.plaintext, vect.ciphertext, vect.datasize);
  delete gcmaes128;
}

void increment_counter(Vector_GCM &vect, unsigned long &counter) {
  unsigned long counter_high, counter_low;
  counter++;
  counter_high = counter / 65536;
  counter_low = counter % 65536;
  vect.iv[8] = highByte(counter_high);
  vect.iv[9] = lowByte(counter_high);
  vect.iv[10] = highByte(counter_low);
  vect.iv[11] = lowByte(counter_low);
}

/****** Helper functions ******/
// convert a c-string with hexbytes to real bytes
int c_string_hexbytes_2_bytes(char c_string[], byte byte_array[]) {
  byte tmp_array_size = strlen(c_string);
  byte tmp_array[tmp_array_size];
  for (byte i = 0; i < tmp_array_size; i++) {
    if ((c_string[i] >= 'A') && (c_string[i] <= 'F')) tmp_array[i] = byte(c_string[i] - 55);
    else if ((c_string[i] >= 'a') && (c_string[i] <= 'f')) tmp_array[i] = byte(c_string[i] - 87);
    else if ((c_string[i] >= '0') && (c_string[i] <= '9')) tmp_array[i] = byte(c_string[i] - 48);
    else {
      return -1;
    }
    if (i % 2 == 1) {  // i odd (every second character)
      byte_array[(i - 1) / 2] = byte((tmp_array[i - 1] * 16) + tmp_array[i]);
    }
  }
  return 0;
}
