#include <crypto.h>
#include <cmac.h>
#include <TI_aes_128.h>
#include <uECC.h>
#include <types.h>
#include <uECC_vli.h>

NfcSec01 unit1;
NfcSec01 unit2;

void setup() {
  // put your setup code here, to run once:
  Serial.begin(9600);
  testMasterKeySse();
}

void loop() {
  // put your main code here, to run repeatedly:

}

extern "C" {

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

}  // extern "C"

bool testMasterKeySse() {
  const byte uECC_BYTES = 24;
  const struct uECC_Curve_t * curve = uECC_secp192r1();
  byte private1[uECC_BYTES];
  byte public1[uECC_BYTES * 2];
  byte nonce1[BLOCK_SIZE / 2];
  byte NFCID3_1[NfcSec01::NFCID_SIZE];
  byte MKsse1[BLOCK_SIZE];
  byte macTag1[BLOCK_SIZE];

  byte private2[uECC_BYTES];
  byte public2[uECC_BYTES * 2];
  byte nonce2[BLOCK_SIZE / 2];
  byte NFCID3_2[NfcSec01::NFCID_SIZE];
  byte MKsse2[BLOCK_SIZE];
  byte macTag2[BLOCK_SIZE];

  uECC_set_rng(&RNG);

  Serial.println();
  //Initialize unit 1
  Serial.println("Data of unit 1:");
  uECC_make_key(public1, private1, curve);
  RNG(nonce1, 8);
  RNG(NFCID3_1, NfcSec01::NFCID_SIZE);//Should be read from the NFC-tag
  printBuffer("Public1", public1, 2 * uECC_BYTES);
  printBuffer("Private1", private1, uECC_BYTES);
  printBuffer("nonce1", nonce1, 8);
  printBuffer("NFCID3_1", NFCID3_1, NfcSec01::NFCID_SIZE);
  unit1.setLocalKey(private1, public1);
  unit1.setLocalNonce(nonce1);
  unit1.setNFCIDi(NFCID3_1,NfcSec01::NFCID_SIZE);

  //Initialize unit 2
  uECC_make_key(public2, private2, curve);
  RNG(nonce2, 8);
  RNG(NFCID3_2, NfcSec01::NFCID_SIZE);
  Serial.println("Data of unit 2:");
  printBuffer("Public2", public2, 2 * uECC_BYTES);
  printBuffer("Private2", private2, uECC_BYTES);
  printBuffer("nonce2", nonce2, 8);
  printBuffer("NFCID3_2", NFCID3_2, NfcSec01::NFCID_SIZE);
  unit2.setLocalKey(private2, public2);
  unit2.setLocalNonce(nonce2);
  unit2.setNFCIDi(NFCID3_2,NfcSec01::NFCID_SIZE);

  //Generate master key on unit 1:
  if (!unit1.calcMasterKeySSE(public2, nonce2, NFCID3_2, true)) {
    Serial.println("Can't calculate master key1");
    return false;
  }
  unit1.getMasterKey(MKsse1);
  printBuffer("MKsse1", MKsse1, BLOCK_SIZE);

  //Generate master key on unit 2:
  if (!unit2.calcMasterKeySSE(public1, nonce1, NFCID3_1, false)) {
    Serial.println("Can't calculate master key2");
    return false;
  }
  unit2.getMasterKey(MKsse2);
  printBuffer("MKsse2", MKsse2, BLOCK_SIZE);

  //Check if master keys are equal
  if (memcmp(MKsse1, MKsse2, BLOCK_SIZE)) {
    Serial.println("Master keys are not equal");
    return false;
  }
  Serial.println("Master keys are equal: OK");

  //Key confirmation 1
  unit1.generateKeyConfirmationTag(public2, NFCID3_2, macTag1, true);
  printBuffer("macTag1", macTag1, 12);

  //Key confirmation 2
  unit2.generateKeyConfirmationTag(public1, NFCID3_1, macTag2, false);
  printBuffer("macTag2", macTag2, 12);
  //Check if key confirmation succeeds
  if (!unit1.checkKeyConfirmation(macTag2, macTag1)) {
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

