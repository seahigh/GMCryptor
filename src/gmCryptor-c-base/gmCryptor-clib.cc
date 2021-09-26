#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/modes.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define CERTVRIFY_SM2_ID "1234567812345678"
#define CERTVRIFY_SM2_ID_LEN sizeof(CERTVRIFY_SM2_ID) - 1
#define SM2_ENCRYPT_C1C2C3 1
#define SM2_ENCRYPT_C1C3C2 0

extern "C"
{

#include <crypto/sm3.h>

  unsigned char *sm3Hash(const unsigned char *message, size_t *out_len);
  unsigned char *sm4EcbEncrypt(const unsigned char *plain_text, const unsigned char *key_hex, size_t *out_len);
  unsigned char *sm4EcbDecrypt(const unsigned char *cipher_hex, const unsigned char *key_hex, size_t *out_len);
  unsigned char *sm4CbcEncrypt(const unsigned char *plain_text, const unsigned char *key_hex, const unsigned char *iv_hex, size_t *out_len);
  unsigned char *sm4CbcDecrypt(const unsigned char *cipher_hex, const unsigned char *key_hex, const unsigned char *iv_hex, size_t *out_len);
  unsigned char *sm2Encrypt(const unsigned char *plain_text, const unsigned char *pub_hex, const int mode, size_t *out_len);
  unsigned char *sm2Decrypt(const unsigned char *cipher_hex, const unsigned char *pri_hex, const int mode, size_t *out_len);
  unsigned char *sm2EncryptAsn1(const unsigned char *plain_text, const unsigned char *pub_hex, size_t *out_len);
  unsigned char *sm2DecryptAsn1(const unsigned char *cipher_hex, const unsigned char *pri_hex, size_t *out_len);
  unsigned char *sm2Signature(const unsigned char *message, const unsigned char *pri_hex, size_t *out_len);
  bool sm2VerifySign(const unsigned char *message, const unsigned char *sign_hex, const unsigned char *pub_hex);
}

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

int sm2_encrypt_data(const unsigned char *plain_text, const int plain_len, const unsigned char *pub_key, unsigned char *cipher_text, const int type)
{
  unsigned char c1[65], c3[32];
  unsigned char *c2 = NULL;
  int error_code;
  unsigned char k[32] = {0x59, 0x27, 0x6e, 0x27, 0xd5, 0x06, 0x86, 0x1a,
                         0x16, 0x68, 0x0f, 0x3a, 0xd9, 0xc0, 0x2d, 0xcc,
                         0xef, 0x3c, 0xc1, 0xfa, 0x3c, 0xdb, 0xe4, 0xce,
                         0x6d, 0x54, 0xb8, 0x0d, 0xea, 0xc1, 0xbc, 0x21};
  unsigned char pub_key_x[32], pub_key_y[32], c1_x[32], c1_y[32], x2[32], y2[32];
  unsigned char c1_point[65], x2_y2[64];
  unsigned char *t = NULL;
  BN_CTX *ctx = NULL;
  BIGNUM *bn_k = NULL, *bn_c1_x = NULL, *bn_c1_y = NULL;
  BIGNUM *bn_pub_key_x = NULL, *bn_pub_key_y = NULL;
  BIGNUM *bn_x2 = NULL, *bn_y2 = NULL;
  const BIGNUM *bn_order, *bn_cofactor;
  EC_GROUP *group = NULL;
  const EC_POINT *generator;
  EC_POINT *pub_key_pt = NULL, *c1_pt = NULL, *s_pt = NULL, *ec_pt = NULL;
  const EVP_MD *md;
  EVP_MD_CTX *md_ctx = NULL;
  int i, flag;

  memcpy(pub_key_x, (pub_key + 1), sizeof(pub_key_x));
  memcpy(pub_key_y, (pub_key + 1 + sizeof(pub_key_x)), sizeof(pub_key_y));

  error_code = 0x1004; // ALLOCATION_MEMORY_FAIL;

  if (!(t = (unsigned char *)malloc(plain_len)))
  {
    goto clean_up;
  }

  if (!(c2 = (unsigned char *)malloc(plain_len)))
  {
    goto clean_up;
  }

  if (!(ctx = BN_CTX_new()))
  {
    goto clean_up;
  }
  BN_CTX_start(ctx);
  bn_k = BN_CTX_get(ctx);
  bn_c1_x = BN_CTX_get(ctx);
  bn_c1_y = BN_CTX_get(ctx);
  bn_pub_key_x = BN_CTX_get(ctx);
  bn_pub_key_y = BN_CTX_get(ctx);
  bn_x2 = BN_CTX_get(ctx);
  bn_y2 = BN_CTX_get(ctx);
  if (!(bn_y2))
  {
    goto clean_up;
  }
  if (!(group = EC_GROUP_new_by_curve_name(NID_sm2)))
  {
    goto clean_up;
  }

  if (!(pub_key_pt = EC_POINT_new(group)))
  {
    goto clean_up;
  }
  if (!(c1_pt = EC_POINT_new(group)))
  {
    goto clean_up;
  }
  if (!(s_pt = EC_POINT_new(group)))
  {
    goto clean_up;
  }
  if (!(ec_pt = EC_POINT_new(group)))
  {
    goto clean_up;
  }

  if (!(md_ctx = EVP_MD_CTX_new()))
  {
    goto clean_up;
  }

  error_code = 0x1009; //COMPUTE_SM2_CIPHERTEXT_FAIL;

  if (!(BN_bin2bn(pub_key_x, sizeof(pub_key_x), bn_pub_key_x)))
  {
    goto clean_up;
  }
  if (!(BN_bin2bn(pub_key_y, sizeof(pub_key_y), bn_pub_key_y)))
  {
    goto clean_up;
  }

  if (!(bn_order = EC_GROUP_get0_order(group)))
  {
    goto clean_up;
  }
  if (!(bn_cofactor = EC_GROUP_get0_cofactor(group)))
  {
    goto clean_up;
  }
  if (!(generator = EC_GROUP_get0_generator(group)))
  {
    goto clean_up;
  }
  if (!(EC_POINT_set_affine_coordinates_GFp(group, pub_key_pt, bn_pub_key_x, bn_pub_key_y, ctx)))
  {
    goto clean_up;
  }
  /* Compute EC point s = [h]Pubkey, h is the cofactor.
	   If s is at infinity, the function returns and reports an error. */
  if (!(EC_POINT_mul(group, s_pt, NULL, pub_key_pt, bn_cofactor, ctx)))
  {
    goto clean_up;
  }
  if (EC_POINT_is_at_infinity(group, s_pt))
  {
    error_code = 0x1008; //EC_POINT_IS_AT_INFINITY
    goto clean_up;
  }
  md = EVP_sm3();
  do
  {
    if (!(BN_bin2bn(k, sizeof(k), bn_k)))
    {
      goto clean_up;
    }
    if (BN_is_zero(bn_k))
    {
      continue;
    }
    if (!(EC_POINT_mul(group, c1_pt, bn_k, NULL, NULL, ctx)))
    {
      goto clean_up;
    }
    if (!(EC_POINT_mul(group, ec_pt, NULL, pub_key_pt, bn_k, ctx)))
    {
      goto clean_up;
    }
    if (!(EC_POINT_get_affine_coordinates_GFp(group, ec_pt, bn_x2, bn_y2, ctx)))
    {
      goto clean_up;
    }
    if (BN_bn2binpad(bn_x2, x2, sizeof(x2)) != sizeof(x2))
    {
      goto clean_up;
    }
    if (BN_bn2binpad(bn_y2, y2, sizeof(y2)) != sizeof(y2))
    {
      goto clean_up;
    }
    memcpy(x2_y2, x2, sizeof(x2));
    memcpy((x2_y2 + sizeof(x2)), y2, sizeof(y2));

    if (!(ECDH_KDF_X9_62(t, plain_len, x2_y2, sizeof(x2_y2), NULL, 0, md)))
    {
      error_code = 0x100a; //COMPUTE_SM2_KDF_FAIL;
      goto clean_up;
    }

    /* If each component of t is zero, the random number k 
		   should be re-generated. 
		   A fixed random number k is used in this test function,
		   so this case will not happen.*/
    flag = 1;
    for (i = 0; i < plain_len; i++)
    {
      if (t[i] != 0)
      {
        flag = 0;
        break;
      }
    }
  } while (flag);

  if (!(EC_POINT_get_affine_coordinates_GFp(group, c1_pt, bn_c1_x, bn_c1_y, ctx)))
  {
    goto clean_up;
  }
  if (BN_bn2binpad(bn_c1_x, c1_x, sizeof(c1_x)) != sizeof(c1_x))
  {
    goto clean_up;
  }
  if (BN_bn2binpad(bn_c1_y, c1_y, sizeof(c1_y)) != sizeof(c1_y))
  {
    goto clean_up;
  }
  c1_point[0] = 0x4;
  memcpy((c1_point + 1), c1_x, sizeof(c1_x));
  memcpy((c1_point + 1 + sizeof(c1_x)), c1_y, sizeof(c1_y));
  memcpy(c1, c1_point, sizeof(c1_point));

  EVP_DigestInit_ex(md_ctx, md, NULL);
  EVP_DigestUpdate(md_ctx, x2, sizeof(x2));
  EVP_DigestUpdate(md_ctx, plain_text, plain_len);
  EVP_DigestUpdate(md_ctx, y2, sizeof(y2));
  EVP_DigestFinal_ex(md_ctx, c3, NULL);
  for (i = 0; i < plain_len; i++)
  {
    c2[i] = plain_text[i] ^ t[i];
  }
  if (type == SM2_ENCRYPT_C1C2C3)
  {
    memcpy(cipher_text, c1, 65);
    memcpy(cipher_text + 65, c2, plain_len);
    memcpy(cipher_text + 65 + plain_len, c3, 32);
  }
  else
  {
    memcpy(cipher_text, c1, 65);
    memcpy(cipher_text + 65, c3, 32);
    memcpy(cipher_text + 65 + 32, c2, plain_len);
  }
  error_code = 0;

clean_up:
  if (t)
  {
    free(t);
  }
  if (c2)
  {
    free(c2);
  }
  if (ctx)
  {
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
  }
  if (group)
  {
    EC_GROUP_free(group);
  }
  if (pub_key_pt)
  {
    EC_POINT_free(pub_key_pt);
  }
  if (c1_pt)
  {
    EC_POINT_free(c1_pt);
  }
  if (s_pt)
  {
    EC_POINT_free(s_pt);
  }
  if (ec_pt)
  {
    EC_POINT_free(ec_pt);
  }
  if (md_ctx)
  {
    EVP_MD_CTX_free(md_ctx);
  }
  return error_code;
}

int sm2_decrypt_data(unsigned char *cipher_text, unsigned long cipher_len, const unsigned char *pri_key, unsigned char *plain_text, const int type)
{
  const int c2_len = cipher_len - (65 + 32);
  unsigned char c1[65];
  unsigned char c2[c2_len];
  unsigned char c3[32];

  if (type == SM2_ENCRYPT_C1C2C3)
  {
    memcpy(c1, cipher_text, 65);
    memcpy(c2, cipher_text + 65, c2_len);
    memcpy(c3, cipher_text + 65 + c2_len, 32);
  }
  else
  {
    memcpy(c1, cipher_text, 65);
    memcpy(c3, cipher_text + 65, 32);
    memcpy(c2, cipher_text + 65 + 32, c2_len);
  }

  int error_code;
  unsigned char c1_x[32], c1_y[32], x2[32], y2[32];
  unsigned char x2_y2[64], digest[32];
  unsigned char *t = NULL, *M = NULL;
  BN_CTX *ctx = NULL;
  BIGNUM *bn_d = NULL, *bn_c1_x = NULL, *bn_c1_y = NULL;
  BIGNUM *bn_x2 = NULL, *bn_y2 = NULL;
  const BIGNUM *bn_cofactor;
  EC_GROUP *group = NULL;
  EC_POINT *c1_pt = NULL, *s_pt = NULL, *ec_pt = NULL;
  const EVP_MD *md;
  EVP_MD_CTX *md_ctx = NULL;
  int plain_len, i, flag;

  plain_len = c2_len;
  memcpy(c1_x, (c1 + 1), sizeof(c1_x));
  memcpy(c1_y, (c1 + 1 + sizeof(c1_x)), sizeof(c1_y));

  error_code = 0x1004; // ALLOCATION_MEMORY_FAIL;
  if (!(ctx = BN_CTX_new()))
  {
    goto clean_up;
  }
  BN_CTX_start(ctx);
  bn_d = BN_CTX_get(ctx);
  bn_c1_x = BN_CTX_get(ctx);
  bn_c1_y = BN_CTX_get(ctx);
  bn_x2 = BN_CTX_get(ctx);
  bn_y2 = BN_CTX_get(ctx);
  if (!(bn_y2))
  {
    goto clean_up;
  }
  if (!(group = EC_GROUP_new_by_curve_name(NID_sm2)))
  {
    goto clean_up;
  }

  if (!(c1_pt = EC_POINT_new(group)))
  {
    goto clean_up;
  }
  if (!(s_pt = EC_POINT_new(group)))
  {
    goto clean_up;
  }
  if (!(ec_pt = EC_POINT_new(group)))
  {
    goto clean_up;
  }

  if (!(md_ctx = EVP_MD_CTX_new()))
  {
    goto clean_up;
  }

  error_code = 0x100c; //SM2_DECRYPT_FAIL;
  if (!(BN_bin2bn(pri_key, 32, bn_d)))
  {
    goto clean_up;
  }
  if (!(BN_bin2bn(c1_x, sizeof(c1_x), bn_c1_x)))
  {
    goto clean_up;
  }
  if (!(BN_bin2bn(c1_y, sizeof(c1_y), bn_c1_y)))
  {
    goto clean_up;
  }

  if (!(EC_POINT_set_affine_coordinates_GFp(group, c1_pt, bn_c1_x, bn_c1_y, ctx)))
  {
    goto clean_up;
  }
  if (EC_POINT_is_on_curve(group, c1_pt, ctx) != 1)
  {
    error_code = 0x100b; //INVALID_SM2_CIPHERTEXT;
    goto clean_up;
  }

  if (!(bn_cofactor = EC_GROUP_get0_cofactor(group)))
  {
    goto clean_up;
  }
  if (!(EC_POINT_mul(group, s_pt, NULL, c1_pt, bn_cofactor, ctx)))
  {
    goto clean_up;
  }
  if (EC_POINT_is_at_infinity(group, s_pt))
  {
    error_code = 0x100b; //INVALID_SM2_CIPHERTEXT;
    goto clean_up;
  }

  if (!(EC_POINT_mul(group, ec_pt, NULL, c1_pt, bn_d, ctx)))
  {
    goto clean_up;
  }
  if (!(EC_POINT_get_affine_coordinates_GFp(group, ec_pt, bn_x2, bn_y2, ctx)))
  {
    goto clean_up;
  }
  if (BN_bn2binpad(bn_x2, x2, sizeof(x2)) != sizeof(x2))
  {
    goto clean_up;
  }
  if (BN_bn2binpad(bn_y2, y2, sizeof(x2)) != sizeof(y2))
  {
    goto clean_up;
  }
  memcpy(x2_y2, x2, sizeof(x2));
  memcpy((x2_y2 + sizeof(x2)), y2, sizeof(y2));
  md = EVP_sm3();

  if (!(t = (unsigned char *)malloc(plain_len)))
  {
    goto clean_up;
  }
  if (!(ECDH_KDF_X9_62(t, plain_len, x2_y2, sizeof(x2_y2), NULL, 0, md)))
  {
    error_code = 0x100a; //COMPUTE_SM2_KDF_FAIL;
    goto clean_up;
  }

  /* If each component of t is zero, the function 
	   returns and reports an error. */
  flag = 1;
  for (i = 0; i < plain_len; i++)
  {
    if (t[i] != 0)
    {
      flag = 0;
      break;
    }
  }
  if (flag)
  {
    error_code = 0x100b; //INVALID_SM2_CIPHERTEXT;
    goto clean_up;
  }

  if (!(M = (unsigned char *)malloc(plain_len)))
  {
    goto clean_up;
  }
  for (i = 0; i < plain_len; i++)
  {
    M[i] = c2[i] ^ t[i];
  }

  EVP_DigestInit_ex(md_ctx, md, NULL);
  EVP_DigestUpdate(md_ctx, x2, sizeof(x2));
  EVP_DigestUpdate(md_ctx, M, plain_len);
  EVP_DigestUpdate(md_ctx, y2, sizeof(y2));
  EVP_DigestFinal_ex(md_ctx, digest, NULL);

  if (memcmp(digest, c3, sizeof(digest)))
  {
    error_code = 0x100b; //INVALID_SM2_CIPHERTEXT;
    goto clean_up;
  }
  memcpy(plain_text, M, plain_len);

  error_code = 0;

clean_up:
  if (ctx)
  {
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
  }
  if (group)
  {
    EC_GROUP_free(group);
  }

  if (c1_pt)
  {
    EC_POINT_free(c1_pt);
  }
  if (s_pt)
  {
    EC_POINT_free(s_pt);
  }
  if (ec_pt)
  {
    EC_POINT_free(ec_pt);
  }

  if (md_ctx)
  {
    EVP_MD_CTX_free(md_ctx);
  }
  if (t)
  {
    free(t);
  }
  if (M)
  {
    free(M);
  }
  return error_code;
}

unsigned char *sm3Hash(const unsigned char *msg, size_t *out_len)
{
  SM3_CTX sm3_ctx;
  int SM3_BYTES = 32;
  unsigned char sm3sum[SM3_BYTES];

  char *message = (char *)msg;

  sm3_init(&sm3_ctx);
  sm3_update(&sm3_ctx, message, strlen(message));
  sm3_final(sm3sum, &sm3_ctx);

  unsigned char *result = (unsigned char *)to_hex(sm3sum, SM3_BYTES);
  *out_len = 2 * (SM3_BYTES);
  return result;
}

unsigned char *sm4EcbEncrypt(const unsigned char *ptext, const unsigned char *khex, size_t *out_len)
{

  char *plain_text = (char *)ptext;
  char *key_hex = (char *)khex;
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

  unsigned char *result = (unsigned char *)to_hex(cipher_text, cipher_len + final_len);
  *out_len = 2 * (cipher_len + final_len);
  EVP_CIPHER_CTX_free(ctx);

  free(key);
  free(cipher_text);
  return result;
}

unsigned char *sm4CbcEncrypt(const unsigned char *ptext, const unsigned char *khex, const unsigned char *ihex, size_t *out_len)
{

  char *plain_text = (char *)ptext;
  char *key_hex = (char *)khex;
  char *iv_hex = (char *)ihex;
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

  unsigned char *result = (unsigned char *)to_hex(cipher_text, cipher_len + final_len);
  *out_len = 2 * (cipher_len + final_len);
  EVP_CIPHER_CTX_free(ctx);

  free(key);
  free(iv);
  free(cipher_text);

  return result;
}

unsigned char *sm2Encrypt(const unsigned char *ptext, const unsigned char *phex, const int mode, size_t *out_len)
{
  char *plain_text = (char *)ptext;
  char *pub_hex = (char *)phex;

  unsigned char *cipher_text = (unsigned char *)malloc(strlen(plain_text) + 97 + 1);

  long key_len;
  unsigned char *pub_key = OPENSSL_hexstr2buf(pub_hex, &key_len);
  unsigned char *result = NULL;
  if (key_len == 0)
  {
    result = NULL;
    *out_len = 0;
    goto toEnd;
  }
  if (sm2_encrypt_data((const unsigned char *)plain_text, strlen(plain_text), pub_key, cipher_text, mode) != 0)
  {
    result = NULL;
    *out_len = 0;
    goto toEnd;
  }
  result = (unsigned char *)to_hex(cipher_text, strlen(plain_text) + 97);
  *out_len = 2 * (strlen(plain_text) + 97);
  goto toEnd;

toEnd:
  free(cipher_text);
  free(pub_key);

  return result;
}

unsigned char *sm2Decrypt(const unsigned char *chex, const unsigned char *phex, const int mode, size_t *out_len)
{
  char *cipher_hex = (char *)chex;
  char *pri_hex = (char *)phex;

  unsigned char *result = NULL;

  long cipher_len;
  unsigned char *cipher_text = OPENSSL_hexstr2buf(cipher_hex, &cipher_len);

  long key_len;
  unsigned char *pri_key = OPENSSL_hexstr2buf(pri_hex, &key_len);

  if (key_len == 0)
  {
    result = NULL;
    *out_len = 0;
    goto toEnd;
  }
  if (cipher_len == 0)
  {
    result = NULL;
    *out_len = 0;
    goto toEnd;
  }
  result = (unsigned char *)malloc(cipher_len - (65 + 32));
  if (sm2_decrypt_data(cipher_text, cipher_len, pri_key, result, mode) != 0)
  {
    result = NULL;
    *out_len = 0;
    goto toEnd;
  }
  *out_len = cipher_len - (65 + 32);
  goto toEnd;

toEnd:
  free(cipher_text);
  free(pri_key);
  return result;
}

unsigned char *sm4CbcDecrypt(const unsigned char *chex, const unsigned char *khex, const unsigned char *ihex, size_t *out_len)
{
  char *cipher_hex = (char *)chex;
  char *key_hex = (char *)khex;
  char *iv_hex = (char *)ihex;

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

  *out_len = plain_len + final_len;

  free(key);
  free(iv);
  free(cipher_text);
  return plain_text;
}

unsigned char *sm4EcbDecrypt(const unsigned char *chex, const unsigned char *khex, size_t *out_len)
{
  char *cipher_hex = (char *)chex;
  char *key_hex = (char *)khex;

  long cipher_len;
  unsigned char *cipher_text = OPENSSL_hexstr2buf(cipher_hex, &cipher_len);

  long key_len;
  unsigned char *key = OPENSSL_hexstr2buf(key_hex, &key_len);

  unsigned char *plain_text = NULL;
  int plain_len = cipher_len + 32;

  plain_text = (unsigned char *)malloc(plain_len);

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

  int final_len = 0;

  EVP_DecryptInit_ex(ctx, EVP_sm4_ecb(), NULL, key, NULL);
  EVP_DecryptUpdate(ctx, plain_text, &plain_len, cipher_text, cipher_len);
  EVP_DecryptFinal_ex(ctx, plain_text + plain_len, &final_len);
  EVP_CIPHER_CTX_free(ctx);

  *out_len = plain_len + final_len;

  free(key);
  free(cipher_text);

  return plain_text;
}

unsigned char *sm2EncryptAsn1(const unsigned char *ptext, const unsigned char *phex, size_t *out_len)
{
  char *plain_text = (char *)ptext;
  char *pub_hex = (char *)phex;

  size_t cipher_len = 0;
  unsigned char *cipher_text = NULL;

  EVP_MD_CTX *evpMdCtx = EVP_MD_CTX_new();
  EVP_PKEY *evp_key = EVP_PKEY_new();
  EC_KEY *ec_key = EC_KEY_new();
  EVP_PKEY_CTX *ectx = NULL;

  EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_sm2);
  EC_KEY_set_group(ec_key, group);

  EC_POINT *pub_key = EC_POINT_hex2point(group, (const char *)pub_hex, NULL, NULL);

  if (EC_KEY_set_public_key(ec_key, pub_key) != 1)
  {
    goto toEnd;
  }
  if (EVP_PKEY_set1_EC_KEY(evp_key, ec_key) != 1)
  {
    goto toEnd;
  }

  EVP_PKEY_set_alias_type(evp_key, EVP_PKEY_SM2);
  ectx = EVP_PKEY_CTX_new(evp_key, NULL);

  EVP_PKEY_encrypt_init(ectx);
  EVP_PKEY_encrypt(ectx, NULL, &cipher_len, (const unsigned char *)plain_text, strlen(plain_text));

  cipher_text = (unsigned char *)malloc(cipher_len);
  EVP_PKEY_encrypt(ectx, cipher_text, &cipher_len, (const unsigned char *)plain_text, strlen(plain_text));
  goto toEnd;

toEnd:
  if (ec_key)
    EC_KEY_free(ec_key);
  if (group)
    EC_GROUP_free(group);
  if (pub_key)
    EC_POINT_free(pub_key);
  if (ectx)
    EVP_PKEY_CTX_free(ectx);
  if (evp_key)
    EVP_PKEY_free(evp_key);
  if (evpMdCtx)
    EVP_MD_CTX_free(evpMdCtx);
  unsigned char *result = (unsigned char *)to_hex((unsigned char *)cipher_text, cipher_len);
  *out_len = 2 * cipher_len;

  free(cipher_text);

  return result;
}

unsigned char *sm2DecryptAsn1(const unsigned char *chex, const unsigned char *phex, size_t *out_len)
{
  char *cipher_hex = (char *)chex;
  char *pri_hex = (char *)phex;

  long cipher_len;
  unsigned char *cipher_text = OPENSSL_hexstr2buf(cipher_hex, &cipher_len);

  size_t plain_len = 0;
  unsigned char *plain_text = NULL;

  EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_sm2);
  BIGNUM *prk = BN_new();
  EVP_MD_CTX *evpMdCtx = EVP_MD_CTX_new();
  EVP_PKEY_CTX *ectx = NULL;

  EVP_PKEY *evp_key = EVP_PKEY_new();

  if (BN_hex2bn(&prk, pri_hex) == 0)
  {
    goto toEnd;
  }
  if (EC_KEY_set_private_key(ec_key, prk) != 1)
  {
    goto toEnd;
  }
  if (EVP_PKEY_set1_EC_KEY(evp_key, ec_key) != 1)
  {
    goto toEnd;
  }
  EVP_PKEY_set_alias_type(evp_key, EVP_PKEY_SM2);
  ectx = EVP_PKEY_CTX_new(evp_key, NULL);
  EVP_PKEY_decrypt_init(ectx);
  EVP_PKEY_decrypt(ectx, NULL, &plain_len, cipher_text, cipher_len);

  plain_text = (unsigned char *)malloc(plain_len);
  EVP_PKEY_decrypt(ectx, plain_text, &plain_len, cipher_text, cipher_len);
  goto toEnd;

toEnd:
  if (ec_key)
    EC_KEY_free(ec_key);
  if (evp_key)
    EVP_PKEY_free(evp_key);
  if (evpMdCtx)
    EVP_MD_CTX_free(evpMdCtx);
  if (ectx)
    EVP_PKEY_CTX_free(ectx);
  if (prk)
    BN_free(prk);

  *out_len = plain_len;
  free(cipher_text);
  free(plain_text);
  return plain_text;
}

unsigned char *sm2Signature(const unsigned char *msg, const unsigned char *phex, size_t *out_len)
{
  char *message = (char *)msg;
  char *pri_hex = (char *)phex;

  uint8_t sign[512];
  size_t sign_len = sizeof(sign);

  EC_KEY *ec_key = EC_KEY_new();
  BIGNUM *pri_key = BN_new();
  EVP_MD_CTX *evpMdCtx = EVP_MD_CTX_new();
  EVP_PKEY_CTX *sctx = NULL;
  BN_CTX *ctx = BN_CTX_new();
  EVP_PKEY *evp_key = EVP_PKEY_new();

  EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_sm2);
  EC_KEY_set_group(ec_key, group);

  EC_POINT *r = EC_POINT_new(group);

  if (BN_hex2bn(&pri_key, pri_hex) == 0)
  {
    sign_len = 0;
    goto toEnd;
  }
  if (EC_KEY_set_private_key(ec_key, pri_key) != 1)
  {
    sign_len = 0;
    goto toEnd;
  }

  EC_POINT_mul(group, r, pri_key, NULL, NULL, ctx);
  EC_KEY_set_public_key(ec_key, r);

  if (EVP_PKEY_set1_EC_KEY(evp_key, ec_key) != 1)
  {
    sign_len = 0;
    goto toEnd;
  }
  EVP_PKEY_set_alias_type(evp_key, EVP_PKEY_SM2);

  sctx = EVP_PKEY_CTX_new(evp_key, NULL);

  EVP_PKEY_CTX_set1_id(sctx, CERTVRIFY_SM2_ID, CERTVRIFY_SM2_ID_LEN);

  EVP_MD_CTX_set_pkey_ctx(evpMdCtx, sctx);

  EVP_DigestSignInit(evpMdCtx, NULL, EVP_sm3(), NULL, evp_key);

  EVP_DigestSign(evpMdCtx, sign, &sign_len, (unsigned char *)message, strlen(message));
  goto toEnd;

toEnd:
  unsigned char *result = (unsigned char *)to_hex((unsigned char *)sign, sign_len);

  if (ec_key)
    EC_KEY_free(ec_key);
  if (group)
    EC_GROUP_free(group);
  if (r)
    EC_POINT_free(r);
  if (sctx)
    EVP_PKEY_CTX_free(sctx);
  if (evpMdCtx)
    EVP_MD_CTX_free(evpMdCtx);
  if (evp_key)
    EVP_PKEY_free(evp_key);
  if (pri_key)
    BN_free(pri_key);
  if (ctx)
    BN_CTX_free(ctx);
  *out_len = 2 * sign_len;

  return result;
}

bool sm2VerifySign(const unsigned char *msg, const unsigned char *shex, const unsigned char *phex)
{
  char *message = (char *)msg;
  char *pub_hex = (char *)phex;
  char *sign_hex = (char *)shex;

  bool verify_result = false;

  long sign_len;
  unsigned char *sign = OPENSSL_hexstr2buf(sign_hex, &sign_len);
  EVP_MD_CTX *evpMdCtx = EVP_MD_CTX_new();
  EVP_PKEY *evp_key = EVP_PKEY_new();
  EC_KEY *ec_key = EC_KEY_new();
  EVP_PKEY_CTX *sctx = NULL;

  EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_sm2);
  EC_KEY_set_group(ec_key, group);

  EC_POINT *pub_key = EC_POINT_hex2point(group, (const char *)pub_hex, NULL, NULL);

  if (EC_KEY_set_public_key(ec_key, pub_key) != 1)
  {
    goto toEnd;
  }
  if (EVP_PKEY_set1_EC_KEY(evp_key, ec_key) != 1)
  {
    goto toEnd;
  }
  if (!sign)
  {
    goto toEnd;
  }
  EVP_PKEY_set_alias_type(evp_key, EVP_PKEY_SM2);
  sctx = EVP_PKEY_CTX_new(evp_key, NULL);
  EVP_PKEY_CTX_set1_id(sctx, CERTVRIFY_SM2_ID, CERTVRIFY_SM2_ID_LEN);
  EVP_MD_CTX_set_pkey_ctx(evpMdCtx, sctx);
  if (EVP_DigestVerifyInit(evpMdCtx, NULL, EVP_sm3(), NULL, evp_key) != 1)
  {
    goto toEnd;
  }
  if (EVP_DigestVerify(evpMdCtx, sign, sign_len, (const unsigned char *)message, strlen(message)) != 1)
  {
    verify_result = false;
  }
  else
  {
    verify_result = true;
  }
  goto toEnd;

toEnd:
  if (sign)
    free(sign);
  if (ec_key)
    EC_KEY_free(ec_key);
  if (group)
    EC_GROUP_free(group);
  if (pub_key)
    EC_POINT_free(pub_key);
  if (sctx)
    EVP_PKEY_CTX_free(sctx);
  if (evp_key)
    EVP_PKEY_free(evp_key);
  if (evpMdCtx)
    EVP_MD_CTX_free(evpMdCtx);

  return verify_result;
}
