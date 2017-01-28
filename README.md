# arduino-nfc-sec-01
Arduino library that implements the NFC-SEC Cryptography Standard using ECDH and AES (more or less)

This library allows to securely set up a shared secret key over an insecure channel between two parties that have never met before.  
This key agreement protocol is secure against eavesdroppers.  It's however vulnerable to man-in-the-middle attacks because it lacks authentication.  The physical channel must be chosen well.  NFC, IrDA are good options because they practically exclude man-in-the-middle attacks.
