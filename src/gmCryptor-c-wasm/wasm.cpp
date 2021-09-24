
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <botan/hex.h>
#include <botan/botan.h>
#include <openssl/evp.h>
#include <emscripten.h>
#include <botan/sm2.h>
#include <iostream>

#include <botan/auto_rng.h>
#include <botan/pubkey.h>

#define CERTVRIFY_SM2_ID "1234567812345678"
#define CERTVRIFY_SM2_ID_LEN sizeof(CERTVRIFY_SM2_ID) - 1
#define SM2_ENCRYPT_C1C2C3 1
#define SM2_ENCRYPT_C1C3C2 0

using namespace std;
using namespace Botan;

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
  // std::string sig_text("{name: \"Seahigh DX\", nick: \"Seahigh DX\"}");
  // std::vector<uint8_t> data(text.data(),text.data()+text.length());
  // Botan::EC_Group ecgrp("sm2p256v1");

  // std::string pubkey_s = "04B01614EBC1F3660B4E23BFDD959080974D26EBF6A9240FBAD160B2430BBCA0C137597155455F39A78570A39E967A879909150D09DDE44D4326FBA850512D3031";
  // std::string signature_s = "1C8B7F50C5B0BA81A9BD105315B876E10EE32FA9AF8429FD8E7F9496325ED9C0841A4F76D88D464D22F74C5512932840329CEA566CCE899DA7E9414B626E5E5D";

  // Botan::PointGFp pub_p = ecgrp.OS2ECP(Botan::hex_decode(pubkey_s));

  // Botan::SM2_PublicKey pub_k(ecgrp,pub_p);

  // Botan::PK_Verifier pkVerifier(pub_k,"EMSA1(SM3)");
  // pkVerifier.update(data);

  // int re = pkVerifier.check_signature(Botan::hex_decode(signature_s));
  // std::cout << "is " << (re? "valid\n" : "invalid\n") << std::endl;

  // printf("%d\n", re);

  //   Botan::AutoSeeded_RNG rng;
  //   // Generate ECDSA keypair
  //   //Botan::ECDSA_PrivateKey key(rng, Botan::EC_Group("sm2p256v1"));
  //   Botan::SM2_PrivateKey key(rng,Botan::EC_Group("sm2p256v1"));

  //   std::cout <<  "sm2 sign: " << sig_text << std::endl;
  //   std::string text = sig_text;
  //   std::vector<uint8_t> data(text.data(),text.data()+text.length());

  //   std::cout << "pubkey:" << std::endl << Botan::hex_encode(key.public_key_bits()) << std::endl;
  //   std::cout << "prikey:" << std::endl << Botan::hex_encode(key.private_key_bits()) << std::endl;

  //   // sign data
  //   Botan::PK_Signer signer(key, rng, "userid,SM3");
  //   signer.update(data);

  //   std::vector<uint8_t> signature = signer.signature(rng);
  //   std::cout << "Signature:" << std::endl << Botan::hex_encode(signature);

  //   // verify signature

  //   Botan::PK_Verifier verifier(key, "userid,SM3");
  //   verifier.update(data);
  //   std::cout << std::endl << "verify sig is " << (verifier.check_signature(signature)? "valid" : "invalid");

  //  string plaintext = "{name: \"Seahigh DX\", nick: \"Seahigh DX\"}";

  //  Botan::InitializationVector IV("504f1a1f80d40c760c74bd5257124dc9");
  //  Botan::SymmetricKey key("996ce17f6abc9fe126b57aa5f1d8c92c");
  //  Botan::Pipe pipe(Botan::get_cipher("SM4/CBC", key, IV, Botan::ENCRYPTION), new Botan::Hex_Encoder);
  //  pipe.process_msg(plaintext);
  //  std::string str = pipe.read_all_as_string(0);
  //  std::cout << "SM4 CBC: " << str << std::endl;
  std::string plaintext("Your great-grandfather gave this watch to your granddad for good luck. Unfortunately, Dane's luck wasn't as good as his old man's.");
  // std::vector<uint8_t> pt(plaintext.data(), plaintext.data() + plaintext.length());
  // std::unique_ptr<Botan::RandomNumberGenerator> rng(new Botan::AutoSeeded_RNG);

  return 0;
}

extern "C"
{
#include <crypto/sm3.h>

  // EMSCRIPTEN_KEEPALIVE
  // char *sm3Hash(char *message)
  // {
  //   Botan::SecureVector<unsigned char> sm3Out;
  //   const auto hash = Botan::HashFunction::create("SM3");
  //   sm3Out = hash->process((unsigned char *)message, strlen(message));

  //   char *result = (char *)(Botan::hex_encode(sm3Out).c_str());
  //   free(result);
  //   return result;
  // }

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
    free(key);
    free(cipher_text);
    free(plain_text);
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
}
