#include <crypto.h>
#include <cmac.h>
#include <TI_aes_128.h>
#include <uECC.h>
#include <types.h>
#include <uECC_vli.h>

NfcSec01 unitA(true);
NfcSec01 unitB(false);
bool testMasterKeySse();

void setup() {
  // put your setup code here, to run once:
  Serial.begin(115200);
  if(testMasterKeySse()){
    Serial.println("Pairing successful");
  }
}

void loop() {
  // put your main code here, to run repeatedly:

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
  // NOTE: it would be a good idea to hash the resulting random data using SHA-B56 or similar.
  return 1;
}


bool testMasterKeySse() {
  byte publicA[unitA.getPublicKeySize()];
  byte nonceA[unitA.getNonceSize()];
  byte NFCID3_A[NfcSec01::NFCID_SIZE];
  byte MKsseA[unitA.getMasterKeySize()];
  byte macTagA[unitA.getMacTagSize()];

  byte publicB[unitB.getPublicKeySize()];
  byte nonceB[unitB.getNonceSize()];
  byte NFCID3_B[NfcSec01::NFCID_SIZE];
  byte MKsseB[unitB.getMasterKeySize()];
  byte macTagB[unitB.getMacTagSize()];


  Serial.println();
  //Initialize unit A
  Serial.println("Data of unit A:");
  //Key
  unitA.generateAsymmetricKey(&RNG);
  unitA.getPublicKey(publicA);
  printBuffer("PublicA", publicA, unitA.getPublicKeySize());
  //Nonce
  unitA.generateRandomNonce(&RNG);
  unitA.getLocalNonce(nonceA);
  printBuffer("NonceA", nonceA, unitA.getNonceSize());
  //NFCID3
  RNG(NFCID3_A, NfcSec01::NFCID_SIZE); //Should be read from the NFC-tag
  unitA.setNFCIDi(NFCID3_A, NfcSec01::NFCID_SIZE);
  printBuffer("NFCID3_A", NFCID3_A, NfcSec01::NFCID_SIZE);

  //Initialize unit B
  Serial.println("Data of unit B:");
  //Key
  unitB.generateAsymmetricKey(&RNG);
  unitB.getPublicKey(publicB);
  printBuffer("PublicB", publicB, unitA.getPublicKeySize());
  //Nonce
  unitB.generateRandomNonce(&RNG);
  unitB.getLocalNonce(nonceB);
  printBuffer("NonceB", nonceB, unitB.getNonceSize());
  //NFCID3
  RNG(NFCID3_B, NfcSec01::NFCID_SIZE);
  unitB.setNFCIDi(NFCID3_B, NfcSec01::NFCID_SIZE);
  printBuffer("NFCID3_B", NFCID3_B, NfcSec01::NFCID_SIZE);

  //Generate master key on unit A:
  unitA.setRemotePublicKey(publicB);
  if (!unitA.calcMasterKeySSE(nonceB, NFCID3_B, NfcSec01::NFCID_SIZE)) {
    Serial.println("Can't calculate master keyA");
    return false;
  }
  unitA.getMasterKey(MKsseA);
  printBuffer("MKsseA", MKsseA, unitA.getMasterKeySize());

  //Generate master key on unit B:
  unitB.setRemotePublicKey(publicA);
  if (!unitB.calcMasterKeySSE(nonceA, NFCID3_A, NfcSec01::NFCID_SIZE)) {
    Serial.println("Can't calculate master keyB");
    return false;
  }
  unitB.getMasterKey(MKsseB);
  printBuffer("MKsseB", MKsseB, unitB.getMasterKeySize());

  if(memcmp(MKsseA,MKsseB,unitA.getMasterKeySize())!=0){
    Serial.println("Master keys are not equal");
    return false;
  }

  //Generate key confirmation tag on unit A = MacTagA
  unitA.generateKeyConfirmationTag(macTagA);
  printBuffer("macTagA", macTagA, unitA.getMacTagSize());

  //Unit B checks MacTagA
  if (!unitB.checkKeyConfirmation(macTagA)) {
    Serial.println("Key confirmation fails");
    return false;
  }

  //Generate key confirmation tag on unit B = MacTagB
  unitB.generateKeyConfirmationTag(macTagB);
  printBuffer("macTagB", macTagB, unitB.getMacTagSize());

  //Unit A checks MacTagB
  if (!unitA.checkKeyConfirmation(macTagB)) {
    Serial.println("Key confirmation fails");
    return false;
  }
  Serial.println("Key confirmation successful");
  return true;
}

void printBuffer(const char* name, const byte* buf, byte len) {
  Serial.print(name);
  Serial.print(": ");
  for (int i = 0; i < len; i++) {
    Serial.print(buf[i], HEX);
    Serial.print(" ");
  }
  Serial.println();
}

