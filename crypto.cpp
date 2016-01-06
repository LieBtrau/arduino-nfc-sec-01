#include "crypto.h"


NfcSec01::NfcSec01(bool bIsInitiator):_bIsInitiator(bIsInitiator){}

bool NfcSec01::generateAsymmetricKey(uECC_RNG_Function rng_function)
{
    uECC_set_rng(rng_function);
    const struct uECC_Curve_t * curve = uECC_secp192r1();
    return uECC_make_key(_localPublicKey, _localPrivateKey, curve)!=0;
}

void NfcSec01::generateRandomNonce(uECC_RNG_Function rng_function)
{
    rng_function(_localNonce, _96BIT_);
}

byte NfcSec01::getPublicKeySize()
{
    return _192BIT_*2;
}

byte NfcSec01::getPrivateKeySize()
{
    return _192BIT_;
}

byte NfcSec01::getNonceSize()
{
    return _96BIT_;
}

byte NfcSec01::getMacTagSize()
{
    return _96BIT_;
}

byte NfcSec01::getMasterKeySize()
{
    return _128BIT_;
}

bool NfcSec01::setLocalKey(const byte *pLocalPrivateKey, const byte *pLocalPublicKey)
{
    memcpy(_localPrivateKey, pLocalPrivateKey, _192BIT_);
    memcpy(_localPublicKey, pLocalPublicKey, 2*_192BIT_);
    return true;
}

void NfcSec01::setLocalNonce(const byte* localNonce)
{
    memcpy(_localNonce, localNonce, _96BIT_);
}

void NfcSec01::setNFCIDi(const byte* nfcid3i, byte length)
{
    memset(_localNFCID3,0,NFCID_SIZE);
    memcpy(_localNFCID3,nfcid3i,min(NFCID_SIZE,length));
}

void NfcSec01::getLocalNonce(byte* nonce)
{
   memcpy(nonce, _localNonce, _96BIT_);
}

void NfcSec01::getPublicKey(byte* key)
{
    memcpy(key, _localPublicKey, _192BIT_*2);
}

void NfcSec01::getMasterKey(byte* key)
{
    memcpy(key, _MKsse, _128BIT_);
}

void NfcSec01::generateKeyConfirmationTag(byte* KeyConfirmationTag)
{
    generateKeyConfirmationTag(KeyConfirmationTag, true);
}

void NfcSec01::generateKeyConfirmationTag(byte* KeyConfirmationTag, bool bIsLocal)
    {
    byte msg[1+NFCID_SIZE*2+_192BIT_*4];
    byte cmac[_128BIT_];

    msg[0]=(_bIsInitiator ^ (!bIsLocal) ? 3 : 2);
    memcpy(msg + 1, bIsLocal ? _localNFCID3 : _remoteNFCID3, NFCID_SIZE);
    memcpy(msg + 1 + NFCID_SIZE, bIsLocal ? _remoteNFCID3 : _localNFCID3, NFCID_SIZE);
    memcpy(msg + 1 + 2 * NFCID_SIZE, bIsLocal ? _localPublicKey : _remotePublicKey,2 * _192BIT_);
    memcpy(msg + 1 + 2 * NFCID_SIZE + 2 * _192BIT_, bIsLocal ? _remotePublicKey : _localPublicKey, _192BIT_*2);
    //MacTagA = AES-XCBC-MAC-96_K( (03), IDA, IDB, QA, QB’ )
    //MacTagB = AES-XCBC-MAC-96_K( (02), IDB, IDA, QB, QA’ )
    AES_CMAC(_MKsse, msg, sizeof(msg), cmac);
    memcpy(_KeyConfirmationTag, cmac, _96BIT_);
    memcpy(KeyConfirmationTag, cmac, _96BIT_);
}

bool NfcSec01::checkKeyConfirmation(const byte* pRemoteMacTag)
{
    byte calcRemoteTag[_96BIT_];
    generateKeyConfirmationTag(calcRemoteTag,false);
    return(memcmp(pRemoteMacTag, calcRemoteTag, _96BIT_)==0);
}

//NFC-SEC-1: ECMA-386: Key Agreement + Key Derivation
// A -> B : QA || NA    (QA=public key of A, NA nonce generated by A)
// B <- A : QB || NB    (QA=public key of B, NA nonce generated by B)
bool NfcSec01::calcMasterKeySSE(const byte* pRemotePublicKey, const byte* pRemoteNonce, const byte* pRemoteNFCID3, byte nfcid3Length)
{
    const struct uECC_Curve_t * curve = uECC_secp192r1();
    byte SharedSecret[_192BIT_];
    byte S[_128BIT_+2*NFCID_SIZE+1];
    byte SKEYSEED[_128BIT_];

    //Key Agreement
    //  SharedSecret = ECDH(dA,QB);                                                     //shared secret = 192bit
    if(!uECC_shared_secret(pRemotePublicKey, _localPrivateKey, SharedSecret, curve))
    {
        return false;
    }
    //Save the remote data in member variables
    memcpy(_remotePublicKey, pRemotePublicKey, 2*_192BIT_);
    memcpy(_remoteNFCID3, pRemoteNFCID3, nfcid3Length);
    //Key Derivation
    //  S = ( NA || NB );                                                               //nonces = (64bit)
    memcpy(S+(_bIsInitiator?0:_128BIT_/2),_localNonce,_128BIT_/2);
    memcpy(S+(_bIsInitiator?_128BIT_/2:0), pRemoteNonce, _128BIT_/2);
    //  SKEYSEED = KDF (S, SharedSecret)                                                //SKEYSEED = 128bit
    AES_CMAC(S, SharedSecret, _128BIT_, SKEYSEED);
    //  MKsse = KDF (SKEYSEED, S || ID S || ID R || (0x01))                             //MKsse = 128bit
    memcpy(S+_128BIT_+(_bIsInitiator?0:NFCID_SIZE),_localNFCID3,NFCID_SIZE);
    memcpy(S+_128BIT_+(_bIsInitiator?NFCID_SIZE:0),pRemoteNFCID3,NFCID_SIZE);
    S[_128BIT_+2*NFCID_SIZE]=0X01;
    AES_CMAC(SKEYSEED, S, sizeof(S), _MKsse);
    return true;
}
