/* Demonstrator of ECDH-communication objects
 *  In a practical situation, ecdh1 would be an object on device1 and ecdh2 would be an object on device2.
 *  The writeData and readData functions should be replaced by functionality that actually sends data between these two devices.  The Radiohead-library could be used for serial and
 *  wireless communication.
 *  
 *  The purpose of the EcdhComm-class is for two devices, each having a public/private keypair to set up a shared secret over an insecure channel.  This shared secret could be used
 *  later on for authentication (with Kryptoknight) or for symmetric encryption.
 *  
 *  Secure pairing happens based on ECDH (Elliptic Curve Diffie Hellman) key agreement.  The protocol is resistant to eavesdroppers, but not to man-in-the-middle attacks as it doesn't
 *  provide authentication.  So only use this on a physical channel where man-in-the-middle attacks are very unlikely: direct cable link, NFC or other very short range RFID, IrDA, ...
 */
#include "ecdhcomm.h"

static int RNG(uint8_t *dest, unsigned size);
void print(const byte* array, byte length);

const byte IDLENGTH=10;
byte id1[IDLENGTH]={0,1,2,3,4,5,6,7,8,9};
byte id2[IDLENGTH]={9,8,7,6,5,4,3,2,1,0};
EcdhComm ecdh1= EcdhComm(&RNG, writeData1, readData1);
EcdhComm ecdh2= EcdhComm(&RNG, writeData2, readData2);

void setup() {
    // put your setup code here, to run once:
    Serial.begin(9600);
    while(!Serial);
    Serial.println("start");
    if(!ecdh1.init(id1, IDLENGTH))
    {
      Serial.println("Can't initialize ecdh1");
    }
    if(!ecdh2.init(id2, IDLENGTH))
    {
      Serial.println("Can't initialize ecdh2");
    }
    Serial.println("Initiator starts secure pairing");
    if(!ecdh1.startPairing())
    {
	Serial.println("Sending message failed.");
	return;
    }
}

void loop() {
    if(ecdh1.loop()==EcdhComm::AUTHENTICATION_OK)
    {
        Serial.println("ECDH1: Message received by peer and acknowledged");
    }
    if(ecdh2.loop()==EcdhComm::AUTHENTICATION_OK)
    {
        Serial.println("ECDH2: Message received by peer and acknowledged");
    }
}

//TODO: replace by safe external RNG
static int RNG(uint8_t *dest, unsigned size) {
    // Use the least-significant bits from the ADC for an unconnected pin (or connected to a source of
    // random noise). This can take a long time to generate random data if the result of analogRead(0)
    // doesn't change very frequently.
    while (size) {
	uint8_t val = 0;
	for (unsigned i = 0; i < 8; ++i) {
	    int init = analogRead(0);
	    int count = 0;
	    while (analogRead(0) == init) {
		++count;
	    }

	    if (count == 0) {
		val = (val << 1) | (init & 0x01);
	    } else {
		val = (val << 1) | (count & 0x01);
	    }
	}
	*dest = val;
	++dest;
	--size;
    }
    // NOTE: it would be a good idea to hash the resulting random data using SHA-256 or similar.
    return 1;
}

void print(const byte* array, byte length)
{
  Serial.print("Length = ");Serial.println(length,DEC);
    for (byte i = 0; i < length; i++)
    {
	Serial.print(array[i], HEX);
	Serial.print(" ");
	if ((i + 1) % 16 == 0)
	{
	    Serial.println();
	}
    }
    Serial.println();
}

//Dummy send and receive functions.
//Should be replaced by Serial write and read functions in real application
static byte rxtxData[100];
static byte rxtxLength;
static bool dataReady=false;
static byte rxtxData2[100];
static byte rxtxLength2;
static bool dataReady2=false;


//Dummy function to write data from device 2 to device 1
bool writeData2(byte* data, byte length)
{
    memcpy(rxtxData,data, length);
    rxtxLength=length;
    dataReady=true;
    Serial.print("Data written by device 2 to device 1: ");print(data, length);
    return true;
}

//Dummy function to read incoming data on device 1
bool readData1(byte** data, byte& length)
{
    if(!dataReady)
    {
    return false;
    }
    dataReady=false;
    *data=rxtxData;
    length=rxtxLength;
    Serial.print("Data read by device 1: ");print(*data, length);
    return true;
}


//Dummy function to write data from device 1 to device 2
bool writeData1(byte* data, byte length)
{
    memcpy(rxtxData2,data, length);
    rxtxLength2=length;
    dataReady2=true;
    Serial.print("Data written by device 1 to device 2: ");print(data, length);
    return true;
}

//Dummy function to read incoming data on device 2
bool readData2(byte** data, byte& length)
{
    if(!dataReady2)
    {
    return false;
    }
    dataReady2=false;
    *data=rxtxData2;
    length=rxtxLength2;
    Serial.print("Data read by device 2: ");print(*data, length);
    return true;
}
