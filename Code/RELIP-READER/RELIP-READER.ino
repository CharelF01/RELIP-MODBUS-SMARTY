/*
  Charel Feil
  RELIP Reader
  BTS-IOT 2
  29/03/2023
*/
/* needed for access point*/
#include <ESP8266WiFi.h>
#include <ESPAsyncTCP.h>
#include <ESPAsyncWebServer.h>
#include <FS.h>

#include <Crypto.h>
#include <AES.h>
#include <GCM.h>
#include <SoftwareSerial.h>
#include <SPI.h>
#include <Ethernet.h>
#include <ModbusRTU.h>
#include <ModbusEthernet.h>
#include <ModbusIP_ESP8266.h>

//define pins
#define myport_TX D1
#define myport_RX D2
#define ETHCHIP_SELECT D3
#define enable_485 D0
#define APName "Charel AP"
//initialize modbuses
ModbusEthernet mbE;
ModbusRTU mbRTU;
ModbusIP mbIP;

int rtuFlag = 0;  //0 = tcp, 1=rtu, 2=wifi

/*arrays containing allowed baudrates stop bits and parities
good for checking if the correct one has been entered and easier to parse with input from ap
*/
long mBaudrate[8]{
  1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200
};
uint8_t sBit[2] = {
  1, 2
};
String parityAr[3] = {
  "NONE", "ODD", "EVEN"
};

int apMode = 0;  //0= no ap, 1 = setting ap, 2= resetting ap
//initialize software serial
SoftwareSerial myport;

//define modbus ethernet mac and ip address
IPAddress ip(192, 168, 131, 122);
IPAddress gateway(192, 168, 168, 1);
IPAddress subnet(255, 255, 255, 0);
IPAddress dns(1, 1, 1, 1);
IPAddress wifiip;
IPAddress wifigateway;
IPAddress wifisubnet;
/**/
byte mac[] = {
  0xD2, 0xAD, 0xB3, 0xEF, 0xFE, 0x11
};

/*
* Code for WiFi Access Point still work in progress
* Commented to not interfere with rest for proof of concept
*/
AsyncWebServer server(80);
IPAddress apIP(192, 168, 168, 168);
IPAddress apGateway(192, 168, 168, 1);
IPAddress apSubnet(255, 255, 255, 0);

/*
IPAddress wifiIP(192, 168, 168, 168);
IPAddress wifiGateway(192, 168, 168, 1);
IPAddress wifiSubnet(255, 255, 255, 0);
*/
const int paramLength = 15;
//input parameters from webpage
String PARAM_INPUT[paramLength] = {
  "encryptionKey", "mBitrate", "mIPAddress", "mSlaveAddress", "mStopBit", "mParity", "tcpGateway", "tcpSubnet", "tcpDns", "wifiSsid", "wifiPass", "wifiIP", "wifiGateway", "wifiSubnet"
};

//paths to saved input files
String PATH_INPUT[paramLength] = {
  "/encryptionKey.txt", "/modbusBitrate.txt", "/ip.txt", "/modbusSlaveAddr.txt", "/stop.txt", "/parity.txt", "/tcpGateway.txt", "/tcpSubnet.txt", "/tcpDns.txt", "/WiFiSSID.txt", "/WiFiPass.txt", "/WiFiIP.txt", "/WiFiGateway.txt", "/WiFiSubnet.txt"
};

//Variables to save values from HTML form
String encryptionKey = "";
String ssid;
String pass;
//variables to set baudrate, stop bit, parity and slave id
long modbusBaud = 115200;
uint8_t stopBit = 1;
uint8_t SLAVE_ID = 1;
String parity = "NONE"; /**/
// File paths to save input values permanently

//define max plaintext and serial stream length
const unsigned int MAX_PLAINTEXT_LEN = 1200;
const unsigned int MAX_SERIAL_STREAM_LENGTH = 1800;
uint8_t allData[MAX_SERIAL_STREAM_LENGTH];

// define name key and aad key and name will be changeable when AP is implemented
const char myvname[] = "AES-128 GCM";                 // vector name
char mykey[] = "EBD3E604BA79E1D7CF9D2D1AB1033204";    // Key for SAG1030700089067 (16 byte)
char myAAD[] = "3000112233445566778899AABBCCDDEEFF";  // 17 byte (in Hex 34 character)

//vector struct for decryption
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

//lookup table struct for list of obis codes and modbus registers
struct lutStruct {
  String identifier;
  String name;
  int addr;
  int numAddr;
  int multiplier;
};

//init counter(s) and non blocking delay(s)
unsigned long counter = 0;
int prevMillis = 0;
int interval = 2000;
int prevAPMillis = 0;
int APTimeout = 1000 * 60 * 2 /**/;  //2 minutes
//init length of lookup table
const int lutLength = 30;
//init vector
Vector_GCM my_vector;
//init lookuptable with values, many commented because not needed/ not in E23
lutStruct lookupTable[lutLength] = {
  /*OBIS          Description                                          Register  numreg multiplier  */
  { "1-3:0.2.8", "Version for P1 output", 50007, 1, 1 },                          //software version of smarty needs to be read X/10
                                                                                  /*{"0-0:1.0.0",   "current date-time ",                                   50882, 2,  },  //year,month, day, hour, minute, second*/
  { "0-0:42.0.0", "Logical device name", 50042, 16, 1 },                          //characters in hex
  { "1-0:1.8.0", "Total imported energy register (P+) ", 50770, 2, 1 },           //kWh
  { "1-0:2.8.0", "Total exported energy register (P-)", 50776, 2, 1 },            //kWh
  { "1-0:3.8.0", "Total imported energy register (Q+)", 50772, 2, 1 },            //kvarh
  { "1-0:4.8.0", "Total exported energy register (Q-)", 50778, 2, 1 },            //kvarh
  { "1-0:1.7.0", "Instantaneous imported active power (P+)", 50536, 2, 100 },     //kW
  { "1-0:2.7.0", "Instantaneous exported active power (P-)", 50536, 2, 100 },     //kW
  { "1-0:3.7.0", "Instantaneous imported reactive power (Q+)", 50538, 2, 100 },   //kvarh
  { "1-0:4.7.0", "Instantaneous exported reactive power (Q-)", 50538, 2, 100 },   //kvarh
                                                                                  /*{"0-0:17.0.0",  "Active threshold (SMAX)",                              50016, 1,  },  //kVa*/
  { "1-0:9.7.0", "Instantaneous imported apparent power (S+)", 50540, 2, 100 },   //kVa
  { "1-0:10.7.0", "Instantaneous exported apparent power (S+)", 50540, 2, 100 },  //kVa
                                                                                  /*{"1-1:31.4.0",  "Threshold for maximum imported and exported current",  50019, 2,  },  //A
    {"0-0:96.3.10", "Breaker control state",                                50021, 1,  },  //bool
    {"0-1:96.3.10", "Relay 1 control state",                                50022, 1,  },  //bool
    {"0-2:96.3.10", "Relay 2 control state",                                50023, 1,  },  //bool
    {"0-0:96.7.21", "Number of power failures",                             50024, 1,  },  //int
    {"1-0:32.32.0", "Number of voltage sags L1",                            50025, 1,  },  //int
    {"1-0:52.32.0", "Number of voltage sags L2",                            50026, 1,  },  //int
    {"1-0:72.32.0", "Number of voltage sags L3",                            50027, 1,  },  //int
    {"1-0:32.36.0", "Number of voltage swells L1",                          50028, 1,  },  //int
    {"1-0:52.36.0", "Number of voltage swells L2",                          50029, 1,  },  //int
    {"1-0:72.36.0", "Number of voltage swells L3",                          50030, 1,  },  //int
    {"0-0:96.13.0", "Long message E-meter",                                 50031, 1,  },  //???
    {"0-0:96.13.2", "Long message channel 2",                               50032, 1,  },  //???
    {"0-0:96.13.3", "Long message channel 3",                               50033, 1,  },  //???
    {"0-0:96.13.4", "Long message channel 4",                               50034, 1,  },  //???
    {"0-0:96.13.5", "Long message channel 5",                               50035, 1,  },  //???*/
  { "1-0:32.7.0", "Instantaneous voltage L1", 50520, 2, 100 },                    //V
  { "1-0:52.7.0", "Instantaneous voltage L2", 50522, 2, 100 },                    //V
  { "1-0:72.7.0", "Instantaneous voltage L3", 50524, 2, 100 },                    //V
  { "1-0:31.7.0", "Instantaneous current L1", 50528, 2, 1000 },                   //A
  { "1-0:51.7.0", "Instantaneous current L2", 50530, 2, 1000 },                   //A
  { "1-0:71.7.0", "Instantaneous current L3", 50532, 2, 1000 },                   //A
  { "1-0:21.7.0", "Instantaneous active power (P+) L1", 50544, 2, 100 },          //kW
  { "1-0:22.7.0", "Instantaneous active power (P-) L1 ", 50544, 2, 100 },         //kW
  { "1-0:41.7.0", "Instantaneous active power (P+) L2", 50546, 2, 100 },          //kW
  { "1-0:42.7.0", "Instantaneous active power (P-) L2", 50546, 2, 100 },          //kW
  { "1-0:61.7.0", "Instantaneous active power (P+) L3", 50548, 2, 100 },          //kW
  { "1-0:62.7.0", "Instantaneous active power (P-) L3", 50548, 2, 100 },          //kW
  { "1-0:23.7.0", "Instantaneous reactive power (Q+) L1", 50550, 2, 100 },        //kvar
  { "1-0:24.7.0", "Instantaneous reactive power (Q-) L1", 50550, 2, 100 },        //kvar
  { "1-0:43.7.0", "Instantaneous reactive power (Q+) L2", 50552, 2, 100 },        //kvar
  { "1-0:44.7.0", "Instantaneous reactive power (Q-) L2 ", 50552, 2, 100 },       //kvar
  { "1-0:63.7.0", "Instantaneous reactive power (Q+) L3 ", 50554, 2, 100 },       //kvar
  { "1-0:64.7.0", "Instantaneous reactive power (Q-) L3 ", 50554, 2, 100 }        //kvar
};     /**/

/****** Helper functions from myself******/
void addCustomRegs() {
  //add registers for soco + number
  if (rtuFlag == 0) mbE.addHreg(50000, 0, 6);
  else if (rtuFlag == 1) mbRTU.addHreg(50000, 0, 6);
  else if (rtuFlag == 2) mbIP.addHreg(50000, 0, 6);
  //mbIP.addHreg(50000, 0, 6);
  //put soco and number in registers
  addToHreg(50000, 'S', 1);
  addToHreg(50001, 'O', 1);
  addToHreg(50002, 'C', 1);
  addToHreg(50003, 'O', 1);
  addToHreg(50005, 0X005f, 1);

  //add registers for slave id, baudrate, stop bit and parity
  if (rtuFlag == 0) mbE.addHreg(57344, 0, 4);
  else if (rtuFlag == 1) mbRTU.addHreg(57344, 0, 4);
  else if (rtuFlag == 2) mbIP.addHreg(57344, 0, 4);
  //add slave id to register
  addToHreg(57344, SLAVE_ID, 1);
  //check baudrate and set the corresponding index in register
  int baud = 0;
  while (mBaudrate[baud] != modbusBaud) {
    baud++;
  }
  addToHreg(57345, baud, 1);

  //check stop bit and set the corresponding index in register
  int stopB = 0;
  while (sBit[stopB] != stopBit) {
    stopB++;
  }
  addToHreg(57346, stopB, 1);

  //check parity and set the corresponding index in register
  int par = 0;
  while (parityAr[par] != parity) {
    par++;
  }
  addToHreg(57347, par, 1);
}
//get the data and write it to the registers
void obisToHReg(Vector_GCM &vect, lutStruct lut[]) {
  //make string with whole plaintext
  String pltxt = String((char *)vect.plaintext);
  //go through whole lookup table and search plaintext for identifiers
  for (int i = 0; i < lutLength; i++) {
    String seek = lut[i].identifier;
    int begindex = pltxt.indexOf(seek);
    //get the line beginning with the identifier
    String line = getLine(pltxt, begindex);
    Serial1.println(String(i) + ": " + line);

    //Special case for device name
    if (seek == "0-0:42.0.0") {
      //get beginning and end of String
      int subStringBegin = line.indexOf("(") + 1;
      int subStringEnd = line.indexOf(")");
      //define array size and corresponding arrays
      const int arsize = lut[i].numAddr + 1;
      byte devName[arsize];
      char tempChar[arsize * 2];
      //get the substring and convert it to a char array
      line.substring(subStringBegin, subStringEnd).toCharArray(tempChar, arsize * 2);
      //convert the hex char array to regular characters and save them in a byte array
      c_string_hexbytes_2_bytes(tempChar, devName);
      Serial1.println("\n\r Dev Name");
      //go through byte array and write it to the Registers
      for (int x = 0; x < arsize - 1; x++) {
        Serial1.write(devName[x]);
        if (rtuFlag == 0) {
          Serial1.println("TCP setting " + String(devName[x]) + "to register " + String(lut[i].addr + x));
          mbE.Hreg(lut[i].addr + x, devName[x]);
        } else if (rtuFlag == 1) {
          Serial1.println("RTU setting " + String(devName[x]) + "to register " + String(lut[i].addr + x));
          mbRTU.Hreg(lut[i].addr + x, devName[x]);
        } else if (rtuFlag == 2) {
          Serial1.println("WiFi setting " + String(devName[x]) + "to register " + String(lut[i].addr + x));
          mbIP.Hreg(lut[i].addr + x, devName[x]);
        }

        //mbIP.Hreg(lut[i].addr + x, devName[x]);
      }
    }
    //special cases for combined values
    else if (lut[i].addr == lut[i + 1].addr) {
      //get second line with values
      i++;
      String seek2 = lut[i].identifier;
      int begindex2 = pltxt.indexOf(seek2);
      String line2 = getLine(pltxt, begindex2);
      Serial1.println(String(i) + ": " + line2);
      //extract both numbers
      float num1 = (numberFromString(line, "(", ")") * lut[i].multiplier);
      float num2 = (numberFromString(line2, "(", ")") * lut[i].multiplier);
      uint32_t numToReg;
      //combine them accordingly
      if (seek == "1-0:9.7.0") numToReg = (uint32_t)(num1 + num2);
      else numToReg = (uint32_t)(num1 - num2);
      //Serial1.println(seek + " : " + String(lut[i].addr) + " : " + String(numToReg));
      //add them to the register
      addToHreg(lut[i].addr, numToReg, lut[i].numAddr);
    }
    //special case for double value, 1 line
    /*else if (seek=="1-1:31.4.0") {
        uint16_t ar[2];
        multipleNumbersFromString(line, "(", ")", "(", ")",ar);
        mbE.Hreg(lut[i].addr, ar[0]);
        mbRTU.Hreg(lut[i].addr, ar[0]);
        mbE.Hreg(lut[i].addr+1, ar[1]);
        mbRTU.Hreg(lut[i].addr+1, ar[1]);
    }*/
    //the rest
    else {
      uint32_t numToReg = (uint32_t)(numberFromString(line, "(", ")") * lut[i].multiplier);
      //Serial1.println(seek + ": " + String(numToReg));
      addToHreg(lut[i].addr, numToReg, lut[i].numAddr);
    }
  }
} /**/

//function that returns one line from begin index until next \n
String getLine(String sData, int begindex) {
  String line = "";
  int j = begindex;
  char c = sData.charAt(j);
  while (c != 10) {
    line += c;
    j++;
    c = sData.charAt(j);
    yield();
  }
  return line;
}

//adds to both ethernet and rtu registers
void addToHreg(int beginAddress, uint32_t number, int numRegisters) {
  //check if 2 registers are needed and mask the data accordingly
  //0xFFFF0000 to keep the first 16bit for first register
  //0x0000FFFF to keep the last 16bit for second register
  if (numRegisters == 2) {
    if (rtuFlag == 0) {
      Serial1.println("TCP setting " + String(number) + "to register " + String(beginAddress));
      mbE.Hreg(beginAddress + 1, number & 0x0000FFFF);
      mbE.Hreg(beginAddress, number & 0xFFFF0000);

    } else if (rtuFlag == 1) {
      Serial1.println("RTU setting " + String(number) + "to register " + String(beginAddress));
      mbRTU.Hreg(beginAddress, number & 0xFFFF0000);
      mbRTU.Hreg(beginAddress + 1, number & 0x0000FFFF);
    } else if (rtuFlag == 2) {
      Serial1.println("RTU setting " + String(number) + "to register " + String(beginAddress));
      mbIP.Hreg(beginAddress, number & 0xFFFF0000);
      mbIP.Hreg(beginAddress + 1, number & 0x0000FFFF);
    }
    //mbIP.Hreg(beginAddress + 1, number & 0x0000FFFF);
    //mbIP.Hreg(beginAddress, number & 0xFFFF0000);
  } else {
    if (rtuFlag == 0) {
      Serial1.println("TCP setting " + String(number) + "to register " + String(beginAddress));
      mbE.Hreg(beginAddress, number);
    } else if (rtuFlag == 1) {
      Serial1.println("RTU setting " + String(number) + "to register " + String(beginAddress));
      mbRTU.Hreg(beginAddress, number);
    } else if (rtuFlag == 2) {
      Serial1.println("RTU setting " + String(number) + "to register " + String(beginAddress));
      mbIP.Hreg(beginAddress, number);
    }
  }
}

//probably no longer needed, still kept it to not lose it just in case
/*void doSplit(Vector_GCM &vect) {
  String pltxt = "";
  for (int x = 0; x < vect.datasize; x++) {
    pltxt += (char)vect.plaintext[x];
  }
  int i = 0;
  int j = 0;
  String tempData = "";
  while (j < vect.datasize) {
    if (pltxt.charAt(j) == 10 ||pltxt.charAt(j) == 13) {
      splitData[i] = tempData;
      if (i > 1) {
        Serial1.print(i);
        Serial1.print(" register: ");
        if (i != 16) {
          float numToReg=numberFromString(tempData, "(", ")");
          Serial1.println(numToReg);
          mbE.Hreg(i, numToReg);
        } else {
          float numToReg=multipleNumbersFromString(tempData, "(", ")", "(", ")");
          Serial1.println(multipleNumbersFromString(tempData, "(", ")", "(", ")"));
          mbE.Hreg(i, numToReg);
        }
      }
      tempData = "";
      i++;
    } else {
      tempData += pltxt.charAt(j);
    }
    j++;
  }
}*/

//returns float number from a given string in between 2 delimiters (mostly "(" and ")") filtering out any unwanted characters
float numberFromString(String sData, const char *begin, const char *end) {
  /*find indexes of delimiters*/
  int subStringBegin = sData.indexOf(begin) + 1;
  int subStringEnd = sData.indexOf(end);
  /*create substring between delimiters*/
  String sub = sData.substring(subStringBegin, subStringEnd);
  String conversion = "";
  for (int x = 0; x < sub.length(); x++) {
    char selectChar = sub.charAt(x);
    if (selectChar == 45 || selectChar == 46 || selectChar > 47 && selectChar < 58) {
      conversion += selectChar;
    }
  }

  return atof(conversion.c_str());  //some are bigger than uint16_t so output=wrong in modbus
}
//same as above, only with 2 numbers from 1 string which are beign put into a given array, was needed for 1-1:31.4.0, but no longer in use
void multipleNumbersFromString(String sData, const char *begin1, const char *end1, const char *begin2, const char *end2, uint16_t ar[]) {
  /*get indexes from the set delimiters*/
  int firstSubStringBegin = sData.indexOf(begin1);
  int firstSubStringEnd = sData.indexOf(end1);
  int lastSubStringBegin = sData.lastIndexOf(begin2);
  int lastSubStringEnd = sData.lastIndexOf(end2);

  /*create the substrings and conversion string*/
  String firstSub = sData.substring(firstSubStringBegin, firstSubStringEnd);
  String lastSub = sData.substring(lastSubStringBegin, lastSubStringEnd);
  String conversion = "";

  /*go through first substring and put together the conversion string with the number*/
  for (int x = 0; x < firstSub.length(); x++) {
    char firstChar = firstSub.charAt(x);
    if (firstChar == 46 || firstChar > 47 && firstChar < 58) {
      conversion += firstChar;
    }
  }
  /*output the conversion string and input the number into the given array*/
  Serial1.println("multipleNumbersFromString returned" + conversion);
  ar[0] = atof(conversion.c_str());
  /*reset conversion string*/
  conversion = "";
  /*do the same thing with the next string*/
  for (int x = 0; x < lastSub.length(); x++) {
    char lastChar = lastSub.charAt(x);
    if (lastChar == 45 || /**/ lastChar == 46 || lastChar > 47 && lastChar < 58) {
      conversion += lastChar;
    }
  }
  Serial1.println("multipleNumbersFromString returned" + conversion);
  ar[1] = atof(conversion.c_str());
}

//function to receive data
void receiveData() {
  unsigned int serial_count = 0;
  //if serial is available, wait a bit to receive all the data, then handle it
  if (Serial.available() > 0) delay(250);
  while ((Serial.available() > 0) && (serial_count < MAX_SERIAL_STREAM_LENGTH)) {
    allData[serial_count] = Serial.read();
    //check if beginning of data is valid
    if (allData[0] != 0xDB) {
      //erase buffer and break out of loop
      while (Serial.available() > 0) {
        Serial.read();
      }
      break;
    }
    serial_count++;
  }
}

//function to get minimum register index
uint16_t getMin(lutStruct lut[]) {
  uint16_t result = lut[0].addr;
  for (int i = 1; i < lutLength; i++) {
    uint16_t temp = lut[i].addr;
    if (temp < result) result = temp;
  }
  return result;
}
//function to get maximum register index
uint16_t getMax(lutStruct lut[]) {
  uint16_t result = lut[0].addr;
  for (int i = 1; i < lutLength; i++) {
    uint16_t temp = lut[i].addr;
    if (temp > result) result = temp;
  }
  return result;
}
/****** Helper functions from Mr. Weiler and edited to fit my needs******/
// convert a c-string with hexbytes to real bytes
int c_string_hexbytes_2_bytes(char c_string[], byte byte_array[]) {
  byte tmp_array_size = strlen(c_string);
  byte tmp_array[tmp_array_size];
  for (byte i = 0; i < tmp_array_size; i++) {
    if ((c_string[i] >= 'A') && (c_string[i] <= 'F')) tmp_array[i] = byte(c_string[i] - 55);
    else if ((c_string[i] >= 'a') && (c_string[i] <= 'f')) tmp_array[i] = byte(c_string[i] - 87);
    else if ((c_string[i] >= '0') && (c_string[i] <= '9')) tmp_array[i] = byte(c_string[i] - 48);
    else {
      //Serial.println("error: no Hex bytes in string");
      return -1;
    }
    if (i % 2 == 1) {  // i odd (every second character)
      byte_array[(i - 1) / 2] = byte((tmp_array[i - 1] * 16) + tmp_array[i]);
    }
  }
  return 0;
}
// initialize the vector_structure from c-strings
int init_vector_GCM_decryption(Vector_GCM &vect, const char *vect_name, char *key, char *aad) {

  vect.name = vect_name;  // init vector name
  if (strlen(key) != (vect.keysize * 2)) {
    digitalWrite(enable_485, HIGH);
    Serial.println("Key must have " + String(vect.keysize) + " bytes");
    digitalWrite(enable_485, LOW);
    return -1;
  }
  if (strlen(aad) != (vect.authsize * 2)) {
    digitalWrite(enable_485, HIGH);
    Serial1.println("AAD must have " + String(vect.authsize) + " bytes");
    digitalWrite(enable_485, LOW);
    return -1;
  }

  uint16_t totlen = uint16_t(allData[11]) * 256 + uint16_t(allData[12]) - 17;  // get length of data

  if (totlen > MAX_SERIAL_STREAM_LENGTH) {
    digitalWrite(enable_485, HIGH);
    Serial1.println("total Length too long");
    digitalWrite(enable_485, LOW);
  }

  for (int i = 0; i < totlen; i++) {
    vect.ciphertext[i] = allData[i + 18];
  }
  for (int i = 0; i < 8; i++) {
    vect.iv[i] = allData[2 + i];
  }
  for (int i = 8; i < 12; i++) {
    vect.iv[i] = allData[6 + i];
  }

  for (int i = 0; i < 12; i++) {
    vect.tag[i] = allData[totlen + 18 + i];
  }
  vect.datasize = totlen;




  return 0;
}
void print_vector(Vector_GCM &vect) {
  digitalWrite(enable_485, HIGH);
  const byte MAX_SCREEN_LINE_LENGTH = 25;
  Serial1.print("-----------------------------------\nPrint Vector: ");
  Serial1.print("\n\rVector_Name: " + String(vect.name));
  Serial1.print("\n\rKey Size: " + String(vect.keysize));
  Serial1.print("\n\rData Size: " + String(vect.datasize));
  Serial1.print("\n\rAuth_Data Size: " + String(vect.authsize));
  Serial1.print("\n\rInit_Vect Size: " + String(vect.ivsize));
  Serial1.print("\n\rAuth_Tag Size: " + String(vect.tagsize));
  Serial1.print("\n\rKey: ");
  for (byte i = 0; i < vect.keysize; i++) {
    Serial1.print(String(vect.key[i], HEX) + ' ');
  }
  Serial1.print("\nPlaintext: ");
  byte more_lines = (vect.datasize / MAX_SCREEN_LINE_LENGTH);
  if (more_lines) {
    for (byte i = 0; i < more_lines; i++) {
      for (byte j = 0; j < MAX_SCREEN_LINE_LENGTH; j++) {
        Serial1.print(String(vect.plaintext[i * MAX_SCREEN_LINE_LENGTH + j], HEX) + ' ');
        yield();
      }
      Serial1.println();
    }
  }
  for (byte j = 0; j < (vect.datasize % MAX_SCREEN_LINE_LENGTH); j++) {
    Serial1.print(String(vect.plaintext[more_lines * MAX_SCREEN_LINE_LENGTH + j], HEX) + ' ');
    yield();
  }
  Serial1.print("\nCyphertext: ");
  if (more_lines) {
    for (byte i = 0; i < more_lines; i++) {
      for (byte j = 0; j < MAX_SCREEN_LINE_LENGTH; j++) {
        Serial1.print(String(vect.ciphertext[i * MAX_SCREEN_LINE_LENGTH + j], HEX) + ' ');
        yield();
      }
      Serial1.println();
    }
  }
  for (byte j = 0; j < (vect.datasize % MAX_SCREEN_LINE_LENGTH); j++) {
    Serial1.print(String(vect.ciphertext[more_lines * MAX_SCREEN_LINE_LENGTH + j], HEX) + ' ');
    yield();
  }
  Serial1.print("\n\rAuth_Data: ");
  for (byte i = 0; i < vect.authsize; i++) {
    Serial1.print(String(vect.authdata[i], HEX) + ' ');
  }
  Serial1.print("\n\rInit_Vect: ");
  for (byte i = 0; i < vect.ivsize; i++) {
    Serial1.print(String(vect.iv[i], HEX) + ' ');
  }
  Serial1.print("\n\rAuth_Tag: ");
  for (byte i = 0; i < vect.tagsize; i++) {
    Serial1.print(String(vect.tag[i], HEX) + ' ');
  }
  Serial1.println("\n\r-----------------------------------");
  digitalWrite(enable_485, LOW);
}
void decrypt_text(Vector_GCM &vect) {
  GCM<AES128> *gcmaes128 = 0;
  gcmaes128 = new GCM<AES128>();
  gcmaes128->setKey(vect.key, gcmaes128->keySize());
  gcmaes128->setIV(vect.iv, vect.ivsize);
  gcmaes128->decrypt(vect.plaintext, vect.ciphertext, vect.datasize);
  delete gcmaes128;
}

/****** Spiffs Functions from examples needed later for AP******/
/**/
void initSPIFFS() {
  if (!SPIFFS.begin()) {
    Serial1.println("An error has occurred while mounting SPIFFS");
  }
  Serial1.println("SPIFFS mounted successfully");
}
void setHTMLVariables() {
  if (SPIFFS.exists(PATH_INPUT[0])) {
    encryptionKey = SPIFFS.open(PATH_INPUT[0], "r").readString();
    Serial1.println("mykey= " + String(mykey));
    Serial1.println("encryption key=" + encryptionKey);
    encryptionKey.toUpperCase();
    encryptionKey.toCharArray(mykey, 33);
    Serial1.println("mykey= " + String(mykey));
  }
  if (SPIFFS.exists(PATH_INPUT[1])) {
    modbusBaud = atol(SPIFFS.open(PATH_INPUT[1], "r").readString().c_str());
    Serial1.println(modbusBaud);
  }
  if (SPIFFS.exists(PATH_INPUT[2])) {
    ip.fromString(SPIFFS.open(PATH_INPUT[2], "r").readString());
    Serial1.println(ip);
  }
  if (SPIFFS.exists(PATH_INPUT[3])) {
    SLAVE_ID = atoi(SPIFFS.open(PATH_INPUT[3], "r").readString().c_str());
    Serial1.println(SLAVE_ID);
  }
  if (SPIFFS.exists(PATH_INPUT[4])) {
    stopBit = atoi(SPIFFS.open(PATH_INPUT[4], "r").readString().c_str());
    Serial1.println(stopBit);
  }
  if (SPIFFS.exists(PATH_INPUT[5])) {
    parity = SPIFFS.open(PATH_INPUT[5], "r").readString();
    Serial1.println(parity);
  }
  if (SPIFFS.exists(PATH_INPUT[6])) {
    gateway.fromString(SPIFFS.open(PATH_INPUT[6], "r").readString());
    Serial1.println(gateway);
  }
  if (SPIFFS.exists(PATH_INPUT[7])) {
    subnet.fromString(SPIFFS.open(PATH_INPUT[7], "r").readString());
    Serial1.println(subnet);
  }
  if (SPIFFS.exists(PATH_INPUT[8])) {
    dns.fromString(SPIFFS.open(PATH_INPUT[8], "r").readString());
    Serial1.println(dns);
  }
  if (SPIFFS.exists(PATH_INPUT[9])) {
    ssid = SPIFFS.open(PATH_INPUT[9], "r").readString();
    Serial1.println(ssid);
  }
  if (SPIFFS.exists(PATH_INPUT[10])) {
    pass = SPIFFS.open(PATH_INPUT[10], "r").readString();
    Serial1.println(pass);
  }
  if (SPIFFS.exists(PATH_INPUT[11])) {
    wifiip.fromString(SPIFFS.open(PATH_INPUT[11], "r").readString());
    Serial1.println(ip);
  }
  if (SPIFFS.exists(PATH_INPUT[12])) {
    wifigateway.fromString(SPIFFS.open(PATH_INPUT[12], "r").readString());
    Serial1.println(gateway);
  }
  if (SPIFFS.exists(PATH_INPUT[13])) {
    wifisubnet.fromString(SPIFFS.open(PATH_INPUT[13], "r").readString());
    Serial1.println(subnet);
  }
}
void startSWSerial() {
  Serial1.println("RTU setting softwareserial to" + String(stopBit) + parity);
  if (stopBit == 1) {

    if (parity == "NONE") myport.begin(modbusBaud, SWSERIAL_8N1, myport_RX, myport_TX, false);
    else if (parity == "ODD") myport.begin(modbusBaud, SWSERIAL_8O1, myport_RX, myport_TX, false);
    else if (parity == "EVEN") myport.begin(modbusBaud, SWSERIAL_8E1, myport_RX, myport_TX, false);
  } else if (stopBit == 2) {
    if (parity == "NONE") myport.begin(modbusBaud, SWSERIAL_8N2, myport_RX, myport_TX, false);
    else if (parity == "ODD") myport.begin(modbusBaud, SWSERIAL_8O2, myport_RX, myport_TX, false);
    else if (parity == "EVEN") myport.begin(modbusBaud, SWSERIAL_8E2, myport_RX, myport_TX, false);
  }
}
void setup() {

  //begin all serials
  Serial.begin(115200, SERIAL_8N1, SERIAL_FULL, TX, true);  //must be true
  Serial1.begin(115200, SERIAL_8N1, SERIAL_TX_ONLY, D4, false);
  initSPIFFS();
  Dir dir = SPIFFS.openDir("/");
  while (dir.next()) {
    Serial1.println(dir.fileName());
    if (dir.fileName() == PATH_INPUT[1]) rtuFlag = 1;
    else if (dir.fileName() == PATH_INPUT[2]) rtuFlag = 0;
    else if (dir.fileName() == PATH_INPUT[9]) rtuFlag = 2;
    //SPIFFS.remove(dir.fileName());
  }
  Serial1.println(rtuFlag);
  setHTMLVariables();
  if (rtuFlag == 1) {
    Serial1.println("starting softwareSerial and rtu");
    startSWSerial();
    //begin modbus rtu, set baudrate and slave id
    mbRTU.begin(&myport, enable_485);
    mbRTU.setBaudrate(modbusBaud);
    mbRTU.slave(SLAVE_ID);
    // set pinmode(s)
    pinMode(enable_485, OUTPUT);
  } else if (rtuFlag == 0) {
    Serial1.println("starting ethernet and tcp");
    Ethernet.init(ETHCHIP_SELECT);
    Ethernet.begin(mac, ip, dns, gateway, subnet);
  } else if (rtuFlag == 2) {
    Serial1.println("starting Wifi and tcp");
    WiFi.mode(WIFI_AP_STA);
    WiFi.config(wifiip, dns, wifigateway, wifisubnet);
    WiFi.begin(ssid, pass);
    while (WiFi.status() != WL_CONNECTED) {
      delay(500);
      Serial1.print(".");
    }
    Serial1.println(WiFi.localIP());
  }
  //set serial buffer size so that no data in transfer is lost
  Serial.setRxBufferSize(2048);
  delay(2500);

  /* needed for AP, work in progress
  */

  //WiFi.onEvent(WiFiEvent);



  if (encryptionKey == "") {
    apMode = 1;
    Serial1.println("AP should start");
    Serial1.println(apMode);
    WiFi.softAPConfig(apIP, apGateway, apSubnet);
    WiFi.softAP(APName, NULL);
    server.on("/", HTTP_GET, [](AsyncWebServerRequest *request) {
      //File file =SPIFFS.open("/index.html", "r");
      request->send(SPIFFS, "/index.html", "text/html");
    });
    server.on("/style.css", HTTP_GET, [](AsyncWebServerRequest *request) {
      //File file =SPIFFS.open("/index.html", "r");
      request->send(SPIFFS, "/style.css", "text/css");
      //file.close();
    });
    server.on("/get", HTTP_GET, [](AsyncWebServerRequest *request) {
      int params = request->params();
      for (int i = 0; i < params; i++) {
        AsyncWebParameter *p = request->getParam(i);
        for (int j = 0; j < paramLength; j++) {
          if (p->name() == PARAM_INPUT[j].c_str()) {
            String pval = String(p->value().c_str());
            Serial1.print(String(PARAM_INPUT[j].c_str()) + " set to: " + String(p->value().c_str()) + "\n");
            File file = SPIFFS.open(PATH_INPUT[j].c_str(), "w");
            file.print(pval);
            file.close();
          }
        }
        if (i == params - 1) ESP.reset();
        // HTTP POST ssid value
      }
    });
    server.begin();
  } else {
    apMode = 2;
    Serial1.println(apMode);
    prevAPMillis = millis();
    Serial1.println("AP2 should start");
    WiFi.softAPConfig(apIP, apGateway, apSubnet);
    WiFi.softAP(APName, NULL);
    server.on("/", HTTP_GET, [](AsyncWebServerRequest *request) {
      //File file =SPIFFS.open("/index.html", "r");
      request->send(SPIFFS, "/index2.html", "text/html");
    });
    server.on("/style.css", HTTP_GET, [](AsyncWebServerRequest *request) {
      //File file =SPIFFS.open("/index.html", "r");
      request->send(SPIFFS, "/style.css", "text/css");
      //file.close();
    });
    server.on("/reset", HTTP_GET, [](AsyncWebServerRequest *request) {
      Dir dir = SPIFFS.openDir("/");
      while (dir.next()) {
        String fileName = dir.fileName();
        Serial1.println(dir.fileName());

        if (fileName != "/index.html" && fileName != "/index2.html" && fileName != "/style.css")
          SPIFFS.remove(dir.fileName());
      }
      ESP.reset();
      // HTTP POST ssid value
    });
    server.begin();
  }
  //get range to set the modbus addresses
  uint16_t minAddress = getMin(lookupTable);
  uint16_t maxAddress = getMax(lookupTable);
  uint16_t range = maxAddress - minAddress;
  //for debugging
  Serial1.println("Min Address:" + String(minAddress));
  Serial1.println("Max Address:" + String(maxAddress));
  Serial1.println("range:" + String(range));
  //add the registers
  if (rtuFlag == 1) {
    mbRTU.addHreg(minAddress, 0, range);
    Serial1.println("Setting rtu addresses");
  } else if (rtuFlag == 0) {
    mbE.addHreg(minAddress, 0, range);
    Serial1.println("Setting tcp addresses");
  } else if (rtuFlag == 2) {
    mbIP.addHreg(minAddress, 0, range);
    Serial1.println("Setting ip addresses");
  }
  //mbIP.addHreg(minAddress, 0, range);
  //function for custom registers like the "SOCO", baudrate etc
  addCustomRegs();
  //make cstring from key and aad to hex byte array inside vector
  c_string_hexbytes_2_bytes(mykey, my_vector.key);       // array passed by ref
  c_string_hexbytes_2_bytes(myAAD, my_vector.authdata);  // array passed by ref
  //start modbus ethernet server
  if (rtuFlag == 0) mbE.server();
  else if (rtuFlag == 2) mbIP.server();
  delay(2500);
}

void loop() {

  if ((millis() - prevAPMillis >= APTimeout) && apMode == 2) {
    WiFi.softAPdisconnect(true);
    Serial1.println("AP2 closed");
    Serial1.println(apMode);
    apMode = 0;
    Serial1.println(apMode);
    /*if(ssid!=""&&pass!=""){
      Serial1.println("here");
      Serial1.println(WiFi.config(wifiIP, wifiGateway, wifiSubnet)? "Ready":"Failed");
      Serial1.println(WiFi.begin(ssid,pass)? "Ready":"Failed");
      while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
      }
    }*/
  } else if (apMode == 0) {

    //Serial1.println(apMode);
    //call receive data function
    receiveData();
    //check if data is valid
    if ((allData[0] == 0xDB) && (allData[1] != 0) && (allData[2] != 0)) {
      //check if vector initialisation has failed
      if (init_vector_GCM_decryption(my_vector, "my_vector", mykey, myAAD) != 0) {
        Serial1.println("ERROR");
        delay(100);
        return;
      }
      //decrypt the received text
      decrypt_text(my_vector);
      //non blocking delay to print out vector for debugging and write new values to registers
      if (millis() - prevMillis >= interval) {
        prevMillis = millis();
        print_vector(my_vector);
        obisToHReg(my_vector, lookupTable);
      }
    }
    //modbus ethernet and rtu tasks

    if (rtuFlag == 1) {
      mbRTU.task();
      Serial1.println("RTU Task");
    } else if (rtuFlag == 0) {
      mbE.task();
      Serial1.println("TCP task running");
    } else if (rtuFlag == 2) {
      if (WiFi.status() == WL_CONNECTED) {
        mbIP.task();
        Serial1.println("WiFI task running");
      }
      else{
        
        while (WiFi.status() != WL_CONNECTED) {
          
          delay(500);
          Serial1.print(".");
        }
      }
    }
  }
  //yield to be safe if nothing happens for some time
  yield();
}
