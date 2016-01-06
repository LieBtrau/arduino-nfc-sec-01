#ifndef CRYPTO_H
#define CRYPTO_H
#include "Arduino.h"
#include <uECC.h>
#include "cmac.h"

class NfcSec01
{
public:
    NfcSec01(bool bIsInitiator);
    static byte getPublicKeySize();
    static byte getPrivateKeySize();
    static byte getNonceSize();
    static byte getMacTagSize();
    static byte getMasterKeySize();
    bool generateAsymmetricKey(uECC_RNG_Function rng_function);
    void generateRandomNonce(uECC_RNG_Function rng_function);
    void generateKeyConfirmationTag(byte* KeyConfirmationTag);
    void getLocalNonce(byte* nonce);
    void setLocalNonce(const byte* localNonce);
    void getPublicKey(byte* key);
    bool setLocalKey(const byte* pLocalPrivateKey, const byte* pLocalPublicKey);
    void getMasterKey(byte *key);
    void setNFCIDi(const byte* nfcid3i, byte length);
    bool calcMasterKeySSE(const byte* pRemotePublicKey, const byte* pRemoteNonce, const byte* pRemoteNFCID3, byte nfcid3Length);
    bool checkKeyConfirmation(const byte* pRemoteMacTag);
    void testEcc();
    bool testMasterKeySse();
    void testCmac();
    static const byte NFCID_SIZE=10;
    static const byte _96BIT_ = 12;
    static const byte _128BIT_ = 16;
    static const byte _192BIT_ = 24;
    typedef enum
    {
        QA_AND_NA,
        QB_AND_NB,
        MAC_TAG_A,
        MAC_TAG_B
    }MSG_ID;
private:
    void generateKeyConfirmationTag(byte* KeyConfirmationTag, bool bIsLocal);
    byte _localPrivateKey[_192BIT_];
    byte _localPublicKey[2*_192BIT_];
    byte _remotePublicKey[2*_192BIT_];
    byte _remoteNFCID3[NFCID_SIZE];
    byte _localNonce[_96BIT_];
    byte _localNFCID3[NFCID_SIZE];
    byte _MKsse[_128BIT_];
    byte _KeyConfirmationTag[_96BIT_];
    bool _bIsInitiator;
};

#endif // CRYPTO_H
