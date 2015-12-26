#ifndef CRYPTO_H
#define CRYPTO_H
#include "Arduino.h"
#include <uECC.h>
#include "cmac.h"

class NfcSec01
{
public:
    NfcSec01();
    void generateKeyConfirmationTag(const byte* pRemotePublicKey, const byte* pRemoteNFCID3, byte* KeyConfirmationTag, bool bIsInitiator);
    byte* getLocalNonce(bool bGenerateNew);
    void getMasterKey(byte *key);
    void setLocalNonce(const byte* localNonce);
    void setNFCIDi(const byte* nfcid3i, byte length);
    bool setLocalKey(const byte* pLocalPrivateKey, const byte* pLocalPublicKey);
    bool calcMasterKeySSE(const byte* pRemotePublicKey, const byte* pRemoteNonce, const byte* pRemoteNFCID3, bool bIsInitiator);
    bool checkKeyConfirmation(const byte* pRemoteMacTag, const byte* pLocalMacTag);
    void testEcc();
    bool testMasterKeySse();
    void testCmac();
    static const byte NFCID_SIZE=10;
    static const byte uECC_BYTES=24;
private:
    static const byte _96BIT_ = 12;
    static const byte _192BIT_ = 24;
    void printBuffer(const char *name, const byte* buf, byte len);
    byte _localPrivateKey[uECC_BYTES+1];
    byte _localPublicKey[uECC_BYTES*2+1];
    byte _localNonce[uECC_BYTES];
    byte _localNFCID3[NFCID_SIZE];
    byte _MKsse[BLOCK_SIZE];
};

#endif // CRYPTO_H
