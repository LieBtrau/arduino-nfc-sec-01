#ifndef ECDHCOMM_H
#define ECDHCOMM_H

#include "crypto.h"

class EcdhComm
{
public:
    typedef int (*RNG_Function)(uint8_t *dest, unsigned size);
    typedef bool(*TX_Function)(byte* data, byte length);
    typedef bool(*RX_Function)(byte** data, byte& length);
    typedef void(*EventHandler)(byte* data, byte length);

    typedef enum
    {
        NO_AUTHENTICATION,
        AUTHENTICATION_OK,
        AUTHENTICATION_BUSY,
    }AUTHENTICATION_RESULT;
    EcdhComm(RNG_Function rng_function, TX_Function tx_func, RX_Function rx_func);
    ~EcdhComm();
    bool init(const byte* localId, byte idLength);
    AUTHENTICATION_RESULT loop();
    bool startPairing();
    byte* getMasterKey();
    byte* getRemoteId();
private:
    typedef enum
    {
        PUBKEY_A,
        PUBKEY_B,
        NONCE_A,
        NONCE_B,
        MACTAG_A,
        MACTAG_B
    }MSG_ID;
    typedef enum
    {
        NOT_STARTED,
        WAITING_FOR_PUBKEY_A,
        WAITING_FOR_PUBKEY_B,
        WAITING_FOR_NONCE_A,
        WAITING_FOR_NONCE_B,
        WAITING_FOR_MACTAG_A,
        WAITING_FOR_MACTAG_B
    }AUTHENTICATION_STATE;
    bool sendPubKey(bool isInitiator);
    bool parsePubKey(bool isInitiator);
    bool sendNonce(bool isInitiator);
    bool parseNonce(bool isInitiator);
    bool sendMacTag(bool isInitiator);
    bool parseMacTag(bool isInitiator);
    void setLocalId(const byte* localId, byte idLength);
    static const byte NONCE_LENGTH=8;
    static const byte MAX_MESSAGE_LEN=60; //maximum length for RH_SERIAL
    RNG_Function _rng_function;
    TX_Function _txfunc;
    RX_Function _rxfunc;
    AUTHENTICATION_STATE _state;
    unsigned long _commTimeOut;
    byte* _messageBuffer;
    NfcSec01 _nfcsec;
};

#endif // ECDHCOMM_H
