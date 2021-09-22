
#include <stdio.h>
#include <openssl/md5.h>
#include <string.h>
#include <stdlib.h>
#include <crypto/sm3.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <crypto/bn.h>
#include <openssl/modes.h>
#include <emscripten.h>

#define CERTVRIFY_SM2_ID "1234567812345678"
#define CERTVRIFY_SM2_ID_LEN sizeof(CERTVRIFY_SM2_ID) - 1
#define SM2_ENCRYPT_C1C2C3 1
#define SM2_ENCRYPT_C1C3C2 0

static char *to_hex(const void *_s, size_t l)
{
  uint8_t *s = (uint8_t *)_s;
  size_t i, j;
  const char *hex = "0123456789abcdef";
  char *r = (char *)malloc((l * 2) + 1);
  for (i = j = 0; i < l; i++)
  {
    r[j++] = hex[(s[i] >> 4) & 0xf];
    r[j++] = hex[s[i] & 0xf];
  }
  r[j] = '\0';
  return r;
}

int main()
{
}

EMSCRIPTEN_KEEPALIVE
char *sm3Hash(char *message)
{
  int SM3_BYTES = 32;
  unsigned char sm3sum[SM3_BYTES];
  SM3_CTX ctx;
  sm3_init(&ctx);
  sm3_update(&ctx, message, strlen(message));
  sm3_final(sm3sum, &ctx);
  char *result = (char *)to_hex(sm3sum, SM3_BYTES);
  free(message);
  free(result);
  return result;
}

EMSCRIPTEN_KEEPALIVE
char *sm4EcbEncrypt(char *plain_text, char *key_hex)
{
  long key_len;
  unsigned char *key = OPENSSL_hexstr2buf(key_hex, &key_len);

  unsigned char *cipher_text = NULL;
  int cipher_len = strlen(plain_text) + 32;

  cipher_text = (unsigned char *)malloc(cipher_len);

  int final_len = 0;
  EVP_CIPHER_CTX *ctx;
  ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx, EVP_sm4_ecb(), NULL, key, NULL);
  EVP_EncryptUpdate(ctx, cipher_text, &cipher_len, (unsigned char *)plain_text, strlen(plain_text));
  EVP_EncryptFinal_ex(ctx, cipher_text + cipher_len, &final_len);

  char *result = (char *)to_hex(cipher_text, cipher_len + final_len);

  EVP_CIPHER_CTX_free(ctx);
  free(key);
  free(result);
  free(cipher_text);
  free(plain_text);
  free(key_hex);
  return result;
}

EMSCRIPTEN_KEEPALIVE
char *sm4CbcEncrypt(char *plain_text, char *key_hex, char *iv_hex)
{
  long key_len;
  unsigned char *key = OPENSSL_hexstr2buf(key_hex, &key_len);

  long iv_len;
  unsigned char *iv = OPENSSL_hexstr2buf(iv_hex, &iv_len);

  int cipher_len = strlen(plain_text) + 32;
  int final_len = 0;

  unsigned char *cipher_text = NULL;

  cipher_text = (unsigned char *)malloc(cipher_len);

  EVP_CIPHER_CTX *ctx;
  ctx = EVP_CIPHER_CTX_new();

  EVP_EncryptInit_ex(ctx, EVP_sm4_cbc(), NULL, key, iv);
  EVP_EncryptUpdate(ctx, cipher_text, &cipher_len, (unsigned char *)plain_text, strlen(plain_text));
  EVP_EncryptFinal_ex(ctx, cipher_text + cipher_len, &final_len);

  char *result = (char *)to_hex(cipher_text, cipher_len + final_len);

  EVP_CIPHER_CTX_free(ctx);
  free(iv);
  free(result);
  free(key);
  free(cipher_text);
  free(plain_text);
  free(key_hex);
  free(iv_hex);
  return result;
}

EMSCRIPTEN_KEEPALIVE
char *sm4EcbDecrypt(char *cipher_hex, char *key_hex)
{
  long cipher_len;
  unsigned char *cipher_text = OPENSSL_hexstr2buf(cipher_hex, &cipher_len);

  long key_len;
  unsigned char *key = OPENSSL_hexstr2buf(key_hex, &key_len);

  int plain_len = cipher_len + 32;

  unsigned char *plain_text = (unsigned char *)malloc(plain_len);

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

  int final_len = 0;

  EVP_DecryptInit_ex(ctx, EVP_sm4_ecb(), NULL, key, NULL);
  EVP_DecryptUpdate(ctx, plain_text, &plain_len, cipher_text, cipher_len);
  EVP_DecryptFinal_ex(ctx, plain_text + plain_len, &final_len);
  EVP_CIPHER_CTX_free(ctx);
  char *result = (char *)malloc(plain_len + final_len + 1);
  memcpy(result, plain_text, plain_len + final_len);
  free(key);
  free(result);
  free(cipher_text);
  free(plain_text);
  free(cipher_hex);
  free(key_hex);
  return result;
}

EMSCRIPTEN_KEEPALIVE
char *sm4CbcDecrypt(char *cipher_hex, char *key_hex, char *iv_hex)
{
  long cipher_len;
  unsigned char *cipher_text = OPENSSL_hexstr2buf(cipher_hex, &cipher_len);

  long key_len;
  unsigned char *key = OPENSSL_hexstr2buf(key_hex, &key_len);

  long iv_len;
  unsigned char *iv = OPENSSL_hexstr2buf(iv_hex, &iv_len);

  unsigned char *plain_text = NULL;
  int plain_len = cipher_len + 32;

  plain_text = (unsigned char *)malloc(plain_len);

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

  int final_len = 0;

  EVP_DecryptInit_ex(ctx, EVP_sm4_cbc(), NULL, key, iv);
  EVP_DecryptUpdate(ctx, plain_text, &plain_len, cipher_text, cipher_len);
  EVP_DecryptFinal_ex(ctx, plain_text + plain_len, &final_len);
  EVP_CIPHER_CTX_free(ctx);

  char *result = (char *)malloc(plain_len + final_len + 1);
  memcpy(result, plain_text, plain_len + final_len);

  free(cipher_text);
  free(result);
  free(iv);
  free(key);
  free(plain_text);
  free(key_hex);
  free(cipher_hex);
  free(iv_hex);
  return result;
}

EMSCRIPTEN_KEEPALIVE
char *sm2Signature(char *message, char *pri_hex)
{
  return NULL;
}