#include "ecdhcomm.h"
#define DEBUG

EcdhComm::EcdhComm(RNG_Function rng_function, TX_Function tx_func, RX_Function rx_func):
    _rng_function(rng_function),
    _txfunc(tx_func),
    _rxfunc(rx_func),
    _commTimeOut(0),
    _nfcsec(),
    _messageBuffer(0){}

EcdhComm::~EcdhComm()
{
    if(_messageBuffer)
    {
        free(_messageBuffer);
    }
}

bool EcdhComm::init(const byte* localId, byte idLength)
{
    _messageBuffer=(byte*)malloc(255);
    if(!_messageBuffer)
    {
#ifdef DEBUG
        Serial.println("Can't init.");
        return false;
#endif
    }
    setLocalId(localId, idLength);
    if(!_nfcsec.generateAsymmetricKey(_rng_function))
    {
#ifdef DEBUG
        Serial.println("Can't generate key.");
        return false;
#endif
    }
    _state=WAITING_FOR_NONCE_A;
    return true;
}

EcdhComm::AUTHENTICATION_RESULT EcdhComm::loop()
{
    byte messageLength;

    if(millis()>_commTimeOut+10000)
    {
#ifdef DEBUG
        Serial.println("Timeout");
#endif
        _state=WAITING_FOR_NONCE_A;
        _nfcsec.setInitiator(false);
        _commTimeOut=millis();
    }
    messageLength=255;
    if(!_rxfunc(&_messageBuffer, messageLength) || !messageLength)
    {
#ifdef DEBUG
        // Serial.println("No message ready.");
#endif
        if(!messageLength)
        {
#ifdef DEBUG
            Serial.println("Empty message.");
#endif
        }
        return _state==WAITING_FOR_NONCE_A ? NO_AUTHENTICATION: AUTHENTICATION_BUSY;
    }
#ifdef DEBUG
    Serial.println("Received something!");
#endif
    switch(_state)
    {
    case WAITING_FOR_NONCE_A:
        if((!parseNonce(false)) || (!sendNonce(false)))
        {
            return NO_AUTHENTICATION;
        }
        _state=WAITING_FOR_MACTAG_A;
        _commTimeOut=millis();
        return AUTHENTICATION_BUSY;
    case WAITING_FOR_NONCE_B:
        if((!parseNonce(true)) || (!sendMacTag(true)))
        {
            return NO_AUTHENTICATION;
        }
        _state=WAITING_FOR_MACTAG_B;
        return AUTHENTICATION_BUSY;
    case WAITING_FOR_MACTAG_A:
        _state=WAITING_FOR_NONCE_A;
        return (parseMacTag(false) && sendMacTag(false)) ? AUTHENTICATION_OK : NO_AUTHENTICATION;
    case WAITING_FOR_MACTAG_B:
        _state=WAITING_FOR_NONCE_A;
        return parseMacTag(true) ? AUTHENTICATION_OK : NO_AUTHENTICATION;
    }
}

bool EcdhComm::startPairing()
{
    if(!sendNonce(true))
    {
        return false;
    }
    _state=WAITING_FOR_NONCE_B;
    return true;
}

void EcdhComm::setLocalId(const byte* localId, byte idLength)
{
    _nfcsec.setNFCIDi(localId, idLength);
}

bool EcdhComm::parseMacTag(bool isInitiator)
{
    if(*_messageBuffer!=(isInitiator ? MACTAG_B : MACTAG_A))
    {
#ifdef DEBUG
        Serial.println("Message is not MACTAG_x.");
#endif
        return false;
    }
    bool bResult =  _nfcsec.checkKeyConfirmation(_messageBuffer+1);
    if(!bResult)
    {
#ifdef DEBUG
        Serial.println("Key confirmation check failed");
#endif
    }
    return bResult;
}

// TAG | MACTAG
bool EcdhComm::sendMacTag(bool isInitiator)
{
    *_messageBuffer= isInitiator ? MACTAG_A : MACTAG_B;
    _nfcsec.generateKeyConfirmationTag(_messageBuffer+1);
    if(!_txfunc(_messageBuffer,1+_nfcsec.getMacTagSize()))
    {
#ifdef DEBUG
        Serial.println("Can't send mactag message.");
#endif
        return false;
    }
    return true;
}


// TAG | ID | PUBKEY | NONCE
bool EcdhComm::sendNonce(bool isInitiator)
{
    _nfcsec.setInitiator(isInitiator);
    *_messageBuffer= isInitiator ? NONCE_A : NONCE_B;
    byte* ptr=_messageBuffer+1;
    _nfcsec.getNFCIDi(ptr);
    ptr+=_nfcsec.getNfcidSize();
    _nfcsec.getPublicKey(ptr);
    ptr+=_nfcsec.getPublicKeySize();
    if(isInitiator)
    {
        _nfcsec.generateRandomNonce(_rng_function);
    }
    _nfcsec.getLocalNonce(ptr);
    ptr+=_nfcsec.getNonceSize();

    if(!_txfunc(_messageBuffer,ptr-_messageBuffer))
    {
#ifdef DEBUG
        Serial.println("Can't send initiator message.");
#endif
        return false;
    }
    _commTimeOut=millis();
    return true;
}

bool EcdhComm::parseNonce(bool isInitiator)
{
    if(*_messageBuffer!=(isInitiator ? NONCE_B : NONCE_A))
    {
#ifdef DEBUG
        Serial.println("Message is not NONCE_x.");
#endif
        return false;
    }
    _nfcsec.setRemotePublicKey(_messageBuffer+1+_nfcsec.getNfcidSize());
    if(!isInitiator)
    {
        _nfcsec.generateRandomNonce(_rng_function);
    }
    bool bResult= _nfcsec.calcMasterKeySSE(_messageBuffer+1+_nfcsec.getNfcidSize()+_nfcsec.getPublicKeySize(), _messageBuffer+1);
    if(!bResult)
    {
#ifdef DEBUG
        Serial.println("calcMasterKeySSE failed");
#endif
    }
    return bResult;
}
