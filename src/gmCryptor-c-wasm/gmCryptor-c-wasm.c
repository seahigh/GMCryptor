#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h> 
#include <emscripten.h>
#include "../gmCryptor-c-base/gmCryptor-clib.h"
 
EMSCRIPTEN_KEEPALIVE
char *_sm3Hash(const unsigned char *message)
{ 
  return sm3Hash(message);
}

EMSCRIPTEN_KEEPALIVE
char *_sm4EcbEncrypt(const unsigned char *plain_text, const unsigned char *key_hex)
{ 
  return sm4EcbEncrypt(plain_text, key_hex);
}
 
EMSCRIPTEN_KEEPALIVE
char *_sm4EcbDecrypt(const unsigned char *cipher_hex, const unsigned char *key_hex){ 
  return sm4EcbDecrypt(cipher_hex, key_hex);
}

EMSCRIPTEN_KEEPALIVE
char *_sm4CbcEncrypt(const unsigned char *plain_text, const unsigned char *key_hex, const unsigned char *iv_hex){ 
  return sm4CbcEncrypt(plain_text, key_hex,iv_hex);
}

EMSCRIPTEN_KEEPALIVE
char *_sm4CbcDecrypt(const unsigned char *cipher_hex, const unsigned char *key_hex, const unsigned char *iv_hex){ 
  return sm4CbcDecrypt(cipher_hex, key_hex,iv_hex);
}

EMSCRIPTEN_KEEPALIVE
char *_sm2Encrypt(const unsigned char *plain_text, const unsigned char *pub_hex, const int mode){ 
  return sm2Encrypt(plain_text, pub_hex,mode);
}

EMSCRIPTEN_KEEPALIVE
char *_sm2Decrypt(const unsigned char *cipher_hex, const unsigned char *pri_hex, const int mode){ 
  return sm2Decrypt(cipher_hex,pri_hex,mode);
}

EMSCRIPTEN_KEEPALIVE
char *_sm2EncryptAsn1(const unsigned char *plain_text, const unsigned char *pub_hex){ 
  return sm2EncryptAsn1(plain_text, pub_hex);
}

EMSCRIPTEN_KEEPALIVE
char *_sm2DecryptAsn1(const unsigned char *cipher_hex, const unsigned char *pri_hex){ 
  return sm2DecryptAsn1(cipher_hex, pri_hex);
}

EMSCRIPTEN_KEEPALIVE
char *_sm2Signature(const unsigned char *message, const unsigned char *pri_hex){ 
  return sm2Signature(message, pri_hex);
}

EMSCRIPTEN_KEEPALIVE
bool _sm2VerifySign(const unsigned char *message, const unsigned char *sign_hex, const unsigned char *pub_hex){ 
  return sm2VerifySign(message, sign_hex, pub_hex);
}