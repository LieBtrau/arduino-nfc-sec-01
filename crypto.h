#ifndef CRYPTO_H
#define CRYPTO_H
#include "Arduino.h"
#include <uECC.h>
#include "cmac.h"

class NfcSec01
{
public:
    NfcSec01(bool bIsInitiator);
    void generateKeyConfirmationTag(const byte* pRemotePublicKey, const byte* pRemoteNFCID3, byte* KeyConfirmationTag);
    byte* getLocalNonce(bool bGenerateNew);
    void getMasterKey(byte *key);
    void setLocalNonce(const byte* localNonce);
    void setNFCIDi(const byte* nfcid3i, byte length);
    bool setLocalKey(const byte* pLocalPrivateKey, const byte* pLocalPublicKey);
    bool calcMasterKeySSE(const byte* pRemotePublicKey, const byte* pRemoteNonce, const byte* pRemoteNFCID3);
    bool checkKeyConfirmation(const byte* pRemoteMacTag);
    void testEcc();
    bool testMasterKeySse();
    void testCmac();
    static const byte NFCID_SIZE=10;
    static const byte _96BIT_ = 12;
    static const byte _128BIT_ = 16;
    static const byte _192BIT_ = 24;
private:
    void printBuffer(const char *name, const byte* buf, byte len);
    byte _localPrivateKey[_192BIT_];
    byte _localPublicKey[2*_192BIT_];
    byte _localNonce[_96BIT_];
    byte _localNFCID3[NFCID_SIZE];
    byte _MKsse[_128BIT_];
    byte _KeyConfirmationTag[_96BIT_];
    bool _bIsInitiator;
};

#endif // CRYPTO_H
