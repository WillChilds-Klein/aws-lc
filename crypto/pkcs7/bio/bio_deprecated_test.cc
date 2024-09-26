// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#include <gtest/gtest.h>

<<<<<<< HEAD
#include <openssl/bio.h>
#include <openssl/bytestring.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include "../../test/test_util.h"
#include "../internal.h"

struct MessageDigestParams {
  const char name[40];
  const EVP_MD *(*md)(void);
};

static const struct MessageDigestParams MessageDigests[] = {
    {"MD5", EVP_md5},
    {"SHA1", EVP_sha1},
    {"SHA224", EVP_sha224},
    {"SHA256", EVP_sha256},
    {"SHA284", EVP_sha384},
    {"SHA512", EVP_sha512},
    {"SHA512_224", EVP_sha512_224},
    {"SHA512_256", EVP_sha512_256},
    {"SHA3_224", EVP_sha3_224},
    {"SHA3_256", EVP_sha3_256},
    {"SHA3_384", EVP_sha3_384},
    {"SHA3_512", EVP_sha3_512},
};

class BIODeprecatedTest : public testing::TestWithParam<MessageDigestParams> {};

INSTANTIATE_TEST_SUITE_P(
    PKCS7Test, BIODeprecatedTest, testing::ValuesIn(MessageDigests),
    [](const testing::TestParamInfo<MessageDigestParams> &params)
        -> std::string { return params.param.name; });

TEST_P(BIODeprecatedTest, MessageDigestBasic) {
  uint8_t message[1024 * 8];
  uint8_t buf[16 * 1024];
  std::vector<uint8_t> message_vec;
  std::vector<uint8_t> buf_vec;
  bssl::UniquePtr<BIO> bio;
  bssl::UniquePtr<BIO> bio_md;
  bssl::UniquePtr<BIO> bio_mem;
  bssl::UniquePtr<EVP_MD_CTX> ctx;

  OPENSSL_memset(message, 'A', sizeof(message));
  OPENSSL_memset(buf, '\0', sizeof(buf));

  const EVP_MD *md = GetParam().md();
  ASSERT_TRUE(md);

  // Simple initialization and error cases
  bio_md.reset(BIO_new(BIO_f_md()));
  ASSERT_TRUE(bio_md);
  EXPECT_FALSE(BIO_reset(bio_md.get()));
  EXPECT_TRUE(BIO_set_md(bio_md.get(), (EVP_MD *)md));
  EVP_MD_CTX *ctx_tmp;  // |bio_md| owns the context, we just take a ref here
  EXPECT_TRUE(BIO_get_md_ctx(bio_md.get(), &ctx_tmp));
  EXPECT_EQ(EVP_MD_type(md), EVP_MD_CTX_type(ctx_tmp));
  EXPECT_EQ(md, EVP_MD_CTX_md(ctx_tmp));  // for static *EVP_MD_CTX, ptrs equal
  EXPECT_FALSE(BIO_ctrl(bio_md.get(), BIO_C_GET_MD, 0, nullptr));
  EXPECT_FALSE(BIO_ctrl(bio_md.get(), BIO_C_SET_MD_CTX, 0, nullptr));
  EXPECT_FALSE(BIO_ctrl(bio_md.get(), BIO_C_DO_STATE_MACHINE, 0, nullptr));
  EXPECT_FALSE(BIO_ctrl(bio_md.get(), BIO_CTRL_DUP, 0, nullptr));
  EXPECT_FALSE(BIO_ctrl(bio_md.get(), BIO_CTRL_GET_CALLBACK, 0, nullptr));
  EXPECT_FALSE(BIO_ctrl(bio_md.get(), BIO_CTRL_SET_CALLBACK, 0, nullptr));
  EXPECT_FALSE(BIO_read(bio_md.get(), buf, 0));
  EXPECT_FALSE(BIO_write(bio_md.get(), buf, 0));
  EXPECT_EQ(0UL, BIO_number_read(bio_md.get()));
  EXPECT_EQ(0UL, BIO_number_written(bio_md.get()));
  EXPECT_FALSE(BIO_gets(bio_md.get(), (char *)buf, EVP_MD_size(md) - 1));

  // Write-through digest BIO
  bio_md.reset(BIO_new(BIO_f_md()));
  ASSERT_TRUE(bio_md);
  EXPECT_TRUE(BIO_set_md(bio_md.get(), (void *)md));
  bio_mem.reset(BIO_new(BIO_s_mem()));
  ASSERT_TRUE(bio_mem);
  bio.reset(BIO_push(bio_md.get(), bio_mem.get()));
  ASSERT_TRUE(bio);
  EXPECT_TRUE(BIO_write(bio.get(), message, sizeof(message)));
  unsigned digest_len = BIO_gets(bio_md.get(), (char *)buf, sizeof(buf));
  buf_vec.clear();
  buf_vec.insert(buf_vec.begin(), buf, buf + digest_len);
  OPENSSL_memset(buf, '\0', sizeof(buf));
  message_vec.clear();
  int rsize;
  while ((rsize = BIO_read(bio_mem.get(), buf, sizeof(buf))) > 0) {
    message_vec.insert(message_vec.end(), buf, buf + rsize);
  }
  ctx.reset(EVP_MD_CTX_new());
  ASSERT_TRUE(EVP_DigestInit_ex(ctx.get(), md, NULL));
  ASSERT_TRUE(
      EVP_DigestUpdate(ctx.get(), message_vec.data(), message_vec.size()));
  ASSERT_TRUE(EVP_DigestFinal_ex(ctx.get(), buf, &digest_len));
  EXPECT_EQ(Bytes(buf_vec.data(), buf_vec.size()), Bytes(buf, digest_len));
  bio_md.release();   // |bio| took ownership
  bio_mem.release();  // |bio| took ownership

  // Read-through digest BIO
  bio_md.reset(BIO_new(BIO_f_md()));
  ASSERT_TRUE(bio_md);
  EXPECT_TRUE(BIO_set_md(bio_md.get(), (void *)md));
  bio_mem.reset(BIO_new_mem_buf(message, sizeof(message)));
  ASSERT_TRUE(bio_mem);
  bio.reset(BIO_push(bio_md.get(), bio_mem.get()));
  ASSERT_TRUE(bio);
  message_vec.clear();
  OPENSSL_memset(buf, '\0', sizeof(buf));
  while ((rsize = BIO_read(bio.get(), buf, sizeof(buf))) > 0) {
    message_vec.insert(message_vec.begin(), buf, buf + rsize);
  }
  EXPECT_EQ(Bytes(message_vec.data(), message_vec.size()),
            Bytes(message, sizeof(message)));
  digest_len = BIO_gets(bio_md.get(), (char *)buf, sizeof(buf));
  buf_vec.clear();
  buf_vec.insert(buf_vec.begin(), buf, buf + digest_len);
  ctx.reset(EVP_MD_CTX_new());
  ASSERT_TRUE(EVP_DigestInit_ex(ctx.get(), md, NULL));
  ASSERT_TRUE(
      EVP_DigestUpdate(ctx.get(), message_vec.data(), message_vec.size()));
  ASSERT_TRUE(EVP_DigestFinal_ex(ctx.get(), buf, &digest_len));
  EXPECT_EQ(Bytes(buf, digest_len), Bytes(buf_vec.data(), buf_vec.size()));
  EXPECT_EQ(Bytes(buf_vec.data(), buf_vec.size()), Bytes(buf, digest_len));
  // Resetting |bio_md| should reset digest state, elicit different digest
  // output
  EXPECT_TRUE(BIO_reset(bio.get()));
  digest_len = BIO_gets(bio_md.get(), (char *)buf, sizeof(buf));
  EXPECT_NE(Bytes(buf_vec.data(), buf_vec.size()), Bytes(buf, digest_len));
  bio_md.release();   // |bio| took ownership
  bio_mem.release();  // |bio| took ownership
}

TEST_P(BIODeprecatedTest, MessageDigestRandomized) {
  uint8_t message_buf[8 * 1024];
  uint8_t digest_buf[EVP_MAX_MD_SIZE];
  std::vector<uint8_t> message;
  std::vector<uint8_t> expected_digest;
  bssl::UniquePtr<BIO> bio;
  bssl::UniquePtr<BIO> bio_md;
  bssl::UniquePtr<BIO> bio_mem;
  bssl::UniquePtr<EVP_MD_CTX> ctx;

  const EVP_MD *md = GetParam().md();
  ASSERT_TRUE(md);

  const size_t block_size = EVP_MD_block_size(md);
  std::vector<std::vector<size_t>> io_patterns = {
      {},
      {0},
      {1},
      {8, 8, 8, 8},
      {block_size - 1, 1, block_size + 1, block_size, block_size - 1},
      {4, 1, 5, 3, 2, 0, 1, sizeof(message_buf), 133, 4555, 22, 4, 7964, 1234},
  };

  for (auto io_pattern : io_patterns) {
    message.clear();
    expected_digest.clear();
    ctx.reset(EVP_MD_CTX_new());
    EVP_DigestInit_ex(ctx.get(), md, NULL);
    // Construct overall message and its expected expected_digest
    for (auto io_size : io_pattern) {
      ASSERT_LE(io_size, sizeof(message_buf));
      RAND_bytes(message_buf, io_size);
      message.insert(message.end(), &message_buf[0], &message_buf[io_size]);
    }
    EVP_DigestUpdate(ctx.get(), message.data(), message.size());
    unsigned digest_size;
    EVP_DigestFinal_ex(ctx.get(), digest_buf, &digest_size);
    ASSERT_EQ(EVP_MD_CTX_size(ctx.get()), digest_size);
    expected_digest.insert(expected_digest.begin(), &digest_buf[0],
                           &digest_buf[digest_size]);
    OPENSSL_cleanse(digest_buf, sizeof(digest_buf));

    // Write-through digest BIO, check against expectation
    bio_md.reset(BIO_new(BIO_f_md()));
    ASSERT_TRUE(bio_md);
    EXPECT_TRUE(BIO_set_md(bio_md.get(), (void *)md));
    bio_mem.reset(BIO_new(BIO_s_mem()));
    ASSERT_TRUE(bio_mem);
    bio.reset(BIO_push(bio_md.get(), bio_mem.get()));
    ASSERT_TRUE(bio);
    int pos = 0;
    for (auto io_size : io_pattern) {
      int wsize = BIO_write(bio.get(), (char *)(message.data() + pos), io_size);
      EXPECT_EQ((int)io_size, wsize);
      pos += io_size;
    }
    digest_size =
        BIO_gets(bio_md.get(), (char *)digest_buf, sizeof(digest_buf));
    ASSERT_EQ(EVP_MD_CTX_size(ctx.get()), digest_size);
    EXPECT_EQ(Bytes(expected_digest.data(), expected_digest.size()),
              Bytes(digest_buf, digest_size));
    OPENSSL_cleanse(digest_buf, sizeof(digest_buf));
    bio_md.release();   // |bio| took ownership
    bio_mem.release();  // |bio| took ownership

    // Read-through digest BIO, check against expectation
    bio_md.reset(BIO_new(BIO_f_md()));
    ASSERT_TRUE(bio_md);
    EXPECT_TRUE(BIO_set_md(bio_md.get(), (void *)md));
    bio_mem.reset(BIO_new_mem_buf(message.data(), message.size()));
    ASSERT_TRUE(bio_mem);
    bio.reset(BIO_push(bio_md.get(), bio_mem.get()));
    ASSERT_TRUE(bio);
    for (auto io_size : io_pattern) {
      int rsize = BIO_read(bio.get(), message_buf, io_size);
      EXPECT_EQ((int)io_size, rsize);
    }
    EXPECT_TRUE(BIO_eof(bio.get()));
    digest_size =
        BIO_gets(bio_md.get(), (char *)digest_buf, sizeof(digest_buf));
    ASSERT_EQ(EVP_MD_CTX_size(ctx.get()), digest_size);
    EXPECT_EQ(Bytes(expected_digest.data(), expected_digest.size()),
              Bytes(digest_buf, digest_size));
    OPENSSL_cleanse(digest_buf, sizeof(digest_buf));
    bio_md.release();   // |bio| took ownership
    bio_mem.release();  // |bio| took ownership
=======
#include <openssl/bytestring.h>
#include <openssl/crypto.h>
#include <openssl/mem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include "../internal.h"
#include "../../test/test_util.h"

// NOTE: need to keep these in sync with cipher BIO source file
#define ENC_MIN_CHUNK_SIZE 256
#define ENC_BLOCK_SIZE 1024 * 4

#define BIO_get_cipher_status(bio) \
  BIO_ctrl(bio, BIO_C_GET_CIPHER_STATUS, 0, NULL)

struct CipherParams {
  const char name[40];
  const EVP_CIPHER *(*cipher)(void);
};

static const struct CipherParams Ciphers[] = {
    {"AES_128_CTR", EVP_aes_128_ctr},
    {"AES_128_GCM", EVP_aes_128_gcm},
    {"AES_128_OFB", EVP_aes_128_ofb},
    {"AES_256_CTR", EVP_aes_256_ctr},
    {"AES_256_GCM", EVP_aes_256_gcm},
    {"AES_256_OFB", EVP_aes_256_ofb},
    {"ChaCha20Poly1305", EVP_chacha20_poly1305},
};

class BIODeprecatedTest : public testing::TestWithParam<CipherParams> {};

INSTANTIATE_TEST_SUITE_P(PKCS7Test, BIODeprecatedTest, testing::ValuesIn(Ciphers),
                         [](const testing::TestParamInfo<CipherParams> &params)
                             -> std::string { return params.param.name; });

TEST_P(BIODeprecatedTest, Cipher) {
  uint8_t key[EVP_MAX_KEY_LENGTH];
  uint8_t iv[EVP_MAX_IV_LENGTH];
  uint8_t pt[8 * ENC_BLOCK_SIZE];
  uint8_t pt_decrypted[sizeof(pt)];
  uint8_t ct[sizeof(pt) + 2 * EVP_MAX_BLOCK_LENGTH];  // pt + pad + tag
  bssl::UniquePtr<BIO> bio_cipher;
  bssl::UniquePtr<BIO> bio_mem;
  std::vector<uint8_t> pt_vec, ct_vec, decrypted_pt_vec;
  uint8_t buff[2 * sizeof(pt)];
  OPENSSL_memset(buff, 'A', sizeof(buff));

  const EVP_CIPHER *cipher = GetParam().cipher();
  ASSERT_TRUE(cipher);

  OPENSSL_memset(pt, 'A', sizeof(pt));
  ASSERT_TRUE(RAND_bytes(key, sizeof(key)));
  ASSERT_TRUE(RAND_bytes(iv, sizeof(iv)));

  // Unsupported or unimplemented CTRL flags and cipher(s)
  bio_cipher.reset(BIO_new(BIO_f_cipher()));
  ASSERT_TRUE(bio_cipher);
  EXPECT_FALSE(BIO_ctrl(bio_cipher.get(), BIO_CTRL_DUP, 0, NULL));
  EXPECT_FALSE(BIO_ctrl(bio_cipher.get(), BIO_CTRL_GET_CALLBACK, 0, NULL));
  EXPECT_FALSE(BIO_ctrl(bio_cipher.get(), BIO_CTRL_SET_CALLBACK, 0, NULL));
  EXPECT_FALSE(BIO_ctrl(bio_cipher.get(), BIO_C_DO_STATE_MACHINE, 0, NULL));
  EXPECT_FALSE(BIO_ctrl(bio_cipher.get(), BIO_C_GET_CIPHER_CTX, 0, NULL));
  EXPECT_FALSE(BIO_ctrl(bio_cipher.get(), BIO_C_SSL_MODE, 0, NULL));
  EXPECT_FALSE(BIO_set_cipher(bio_cipher.get(), EVP_rc4(), key, iv, /*enc*/ 1));

  // Round-trip using only |BIO_read|, backing mem buffer with pt/ct. Fixed size
  // IO.
  bio_cipher.reset(BIO_new(BIO_f_cipher()));
  ASSERT_TRUE(bio_cipher);
  EXPECT_TRUE(BIO_set_cipher(bio_cipher.get(), cipher, key, iv, /*enc*/ 1));
  bio_mem.reset(BIO_new_mem_buf(pt, sizeof(pt)));
  ASSERT_TRUE(bio_mem);
  ASSERT_TRUE(BIO_push(bio_cipher.get(), bio_mem.get()));
  bio_mem.release();  // |bio_cipher| will take ownership
  // Copy |pt| contents to |ct| so we can detect that |ct| gets overwritten
  OPENSSL_memcpy(ct, pt, sizeof(pt));
  OPENSSL_cleanse(pt_decrypted, sizeof(pt_decrypted));
  EXPECT_FALSE(BIO_eof(bio_cipher.get()));
  EXPECT_LT(0UL, BIO_pending(bio_cipher.get()));
  EXPECT_TRUE(BIO_read(bio_cipher.get(), ct, sizeof(ct)));
  EXPECT_TRUE(BIO_eof(bio_cipher.get()));
  EXPECT_EQ(0UL, BIO_pending(bio_cipher.get()));
  EXPECT_TRUE(BIO_get_cipher_status(bio_cipher.get()));
  // only consider first |sizeof(pt)| bytes of |ct|, exclude pad block
  EXPECT_NE(Bytes(pt, sizeof(pt)), Bytes(ct, sizeof(pt)));
  // Reset both BIOs and decrypt
  bio_cipher.reset(BIO_new(BIO_f_cipher()));
  ASSERT_TRUE(bio_cipher);
  EXPECT_TRUE(BIO_set_cipher(bio_cipher.get(), cipher, key, iv, /*enc*/ 0));
  bio_mem.reset(BIO_new_mem_buf((const uint8_t *)ct, sizeof(ct)));
  ASSERT_TRUE(bio_mem);
  ASSERT_TRUE(BIO_push(bio_cipher.get(), bio_mem.get()));
  bio_mem.release();  // |bio_cipher| will take ownership
  EXPECT_TRUE(BIO_read(bio_cipher.get(), pt_decrypted, sizeof(pt_decrypted)));
  EXPECT_TRUE(BIO_get_cipher_status(bio_cipher.get()));
  EXPECT_EQ(Bytes(pt, sizeof(pt)), Bytes(pt_decrypted, sizeof(pt_decrypted)));

  // Round-trip using |BIO_write| for encryption with same BIOs, reset between
  // encryption/decryption using |BIO_reset|. Fixed size IO.
  bio_cipher.reset(BIO_new(BIO_f_cipher()));
  ASSERT_TRUE(bio_cipher);
  EXPECT_TRUE(BIO_set_cipher(bio_cipher.get(), cipher, key, iv, /*enc*/ 1));
  bio_mem.reset(BIO_new(BIO_s_mem()));
  ASSERT_TRUE(bio_mem);
  ASSERT_TRUE(BIO_push(bio_cipher.get(), bio_mem.get()));
  // Copy |pt| contents to |ct| so we can detect that |ct| gets overwritten
  OPENSSL_memcpy(ct, pt, sizeof(pt));
  OPENSSL_cleanse(pt_decrypted, sizeof(pt_decrypted));
  EXPECT_TRUE(BIO_eof(bio_cipher.get()));
  EXPECT_EQ(0UL, BIO_wpending(bio_cipher.get()));
  EXPECT_TRUE(BIO_write(bio_cipher.get(), pt, sizeof(pt)));
  EXPECT_FALSE(BIO_eof(bio_cipher.get()));
  EXPECT_EQ(0UL, BIO_wpending(bio_cipher.get()));
  EXPECT_TRUE(BIO_flush(bio_cipher.get()));
  EXPECT_EQ(0UL, BIO_wpending(bio_cipher.get()));
  EXPECT_TRUE(BIO_get_cipher_status(bio_cipher.get()));
  EXPECT_TRUE(BIO_read(bio_mem.get(), ct, sizeof(ct)));
  // only consider first |sizeof(pt)| bytes of |ct|, exclude pad block
  EXPECT_NE(Bytes(pt, sizeof(pt)), Bytes(ct, sizeof(pt)));
  // Reset both BIOs and decrypt
  EXPECT_TRUE(BIO_reset(bio_cipher.get()));  // also resets owned |bio_mem|
  EXPECT_TRUE(BIO_write(bio_mem.get(), ct, sizeof(ct)));
  bio_mem.release();  // |bio_cipher| took ownership
  EXPECT_TRUE(BIO_set_cipher(bio_cipher.get(), cipher, key, iv, /*enc*/ 0));
  EXPECT_TRUE(BIO_read(bio_cipher.get(), pt_decrypted, sizeof(pt_decrypted)));
  EXPECT_TRUE(BIO_get_cipher_status(bio_cipher.get()));
  EXPECT_EQ(Bytes(pt, sizeof(pt)), Bytes(pt_decrypted, sizeof(pt_decrypted)));

  // Test a number of different IO sizes around byte, word, cipher block,
  // BIO internal buffer size, and other boundaries.
  int io_sizes[] = {1,
                    3,
                    7,
                    8,
                    9,
                    64,
                    923,
                    2 * ENC_BLOCK_SIZE,
                    15,
                    16,
                    17,
                    31,
                    32,
                    33,
                    511,
                    512,
                    513,
                    1023,
                    1024,
                    1025,
                    ENC_MIN_CHUNK_SIZE - 1,
                    ENC_MIN_CHUNK_SIZE,
                    ENC_MIN_CHUNK_SIZE + 1,
                    ENC_BLOCK_SIZE - 1,
                    ENC_BLOCK_SIZE,
                    ENC_BLOCK_SIZE + 1};

  // Round-trip encryption/decryption with successive IOs of different sizes.
  bio_cipher.reset(BIO_new(BIO_f_cipher()));
  ASSERT_TRUE(bio_cipher);
  EXPECT_TRUE(BIO_set_cipher(bio_cipher.get(), cipher, key, iv, /*enc*/ 1));
  bio_mem.reset(BIO_new(BIO_s_mem()));
  ASSERT_TRUE(bio_mem);
  ASSERT_TRUE(BIO_push(bio_cipher.get(), bio_mem.get()));
  for (size_t wsize : io_sizes) {
    pt_vec.insert(pt_vec.end(), buff, buff + wsize);
    EXPECT_TRUE(BIO_write(bio_cipher.get(), buff, wsize));
  }
  EXPECT_TRUE(BIO_flush(bio_cipher.get()));
  EXPECT_TRUE(BIO_get_cipher_status(bio_cipher.get()));
  while (!BIO_eof(bio_mem.get())) {
    size_t bytes_read = BIO_read(bio_mem.get(), buff, sizeof(buff));
    ct_vec.insert(ct_vec.end(), buff, buff + bytes_read);
  }
  EXPECT_TRUE(BIO_reset(bio_cipher.get()));  // also resets owned |bio_mem|
  EXPECT_TRUE(
      BIO_write(bio_mem.get(), ct_vec.data(), ct_vec.size()));  // replace ct
  bio_mem.release();  // |bio_cipher| took ownership
  EXPECT_TRUE(BIO_set_cipher(bio_cipher.get(), cipher, key, iv, /*enc*/ 0));
  for (size_t rsize : io_sizes) {
    EXPECT_TRUE(BIO_read(bio_cipher.get(), buff, rsize));
    decrypted_pt_vec.insert(decrypted_pt_vec.end(), buff, buff + rsize);
  }
  EXPECT_TRUE(BIO_get_cipher_status(bio_cipher.get()));
  EXPECT_EQ(pt_vec.size(), decrypted_pt_vec.size());
  EXPECT_EQ(Bytes(pt_vec.data(), pt_vec.size()),
            Bytes(decrypted_pt_vec.data(), decrypted_pt_vec.size()));

  // Induce IO failures in the underlying BIO between subsequent same-size
  // operations. The flow os this test is to, for each IO size:
  //
  // 1. Write/encrypt a chunk of plaintext.
  // 2. Disable writes in the underlying BIO and try to write the same plaintext
  //    chunk again. depending on how large the write size relative to cipher
  //    BIO's internal buffer size, the write may partially or fully succeed if
  //    it can be buffered.
  // 3. Enable writes in the underlying BIO and complete 2.'s chunk by writing
  //    any remaining bytes in the chunk
  // 4. Flush the cipher BIO to complete the encryption, reset the cipher BIO in
  //    decrypt mode with the underlying BIO containing the ciphertext.
  // 5. Similar to 1., read/decrypt a chunk of ciphertext.
  // 6. Similar to 2., disable reads in the underlying BIO. As with 2., this may
  //    partially or fully succeed depending on how large the read is relative
  //    to internal buffer sizes.
  // 7. Enable reads in the underlying BIO and decrypt the rest of the
  //    ciphertext.
  // 8. Compare original and decrypted plaintexts.
  int rsize, wsize;
  uint8_t *pos;
  for (int io_size : io_sizes) {
    pt_vec.clear();
    decrypted_pt_vec.clear();
    bio_cipher.reset(BIO_new(BIO_f_cipher()));
    ASSERT_TRUE(bio_cipher);
    EXPECT_TRUE(BIO_set_cipher(bio_cipher.get(), cipher, key, iv, /*enc*/ 1));
    bio_mem.reset(BIO_new(BIO_s_mem()));
    ASSERT_TRUE(bio_mem);
    ASSERT_TRUE(BIO_push(bio_cipher.get(), bio_mem.get()));
    // Initial write should fully succeed
    pos = &pt[0];
    wsize = BIO_write(bio_cipher.get(), pos, io_size);
    if (wsize > 0) {
      pt_vec.insert(pt_vec.end(), pos, pos + wsize);
      pos += wsize;
    }
    EXPECT_EQ(io_size, wsize);
    // All data should have been flushed
    EXPECT_EQ(0UL, BIO_wpending(bio_cipher.get()));
    // Set underlying BIO to r/o to induce buffering in |bio_cipher|
    auto disable_writes = [](BIO *bio, int oper, const char *argp, size_t len,
                             int argi, long argl, int bio_ret,
                             size_t *processed) -> long {
      return (oper & BIO_CB_RETURN) || !(oper & BIO_CB_WRITE);
    };
    BIO_set_callback_ex(bio_mem.get(), disable_writes);
    BIO_set_retry_write(bio_mem.get());
    // Write to |bio_cipher| should still succeed in writing up to
    // ENC_BLOCK_SIZE bytes by buffering them
    wsize = BIO_write(bio_cipher.get(), buff, io_size);
    if (wsize > 0) {
      pt_vec.insert(pt_vec.end(), pos, pos + wsize);
      pos += wsize;
    }
    EXPECT_GT(wsize, 0);
    EXPECT_LE(wsize, ENC_BLOCK_SIZE);
    // Now that there's buffered data, |BIO_wpending| should match
    EXPECT_EQ((size_t)wsize, BIO_wpending(bio_cipher.get()));
    // Renable writes
    BIO_set_callback_ex(bio_mem.get(), nullptr);
    BIO_clear_retry_flags(bio_mem.get());
    if (wsize < io_size) {
      const int remaining = io_size - wsize;
      ASSERT_EQ(remaining,
                BIO_write(bio_cipher.get(), buff + wsize, remaining));
      pt_vec.insert(pt_vec.end(), pos, pos + remaining);
      pos += wsize;
    }
    // Flush should empty the buffered encrypted data
    EXPECT_TRUE(BIO_flush(bio_cipher.get()));
    EXPECT_EQ(0UL, BIO_wpending(bio_cipher.get()));
    EXPECT_TRUE(BIO_get_cipher_status(bio_cipher.get()));
    EXPECT_TRUE(BIO_set_cipher(bio_cipher.get(), cipher, key, iv, /*enc*/ 0));
    // Reset BIOs, hydrate ciphertext for decryption
    ct_vec.clear();
    while ((rsize = BIO_read(bio_mem.get(), buff, io_size)) > 0) {
      ct_vec.insert(ct_vec.end(), buff, buff + rsize);
    }
    EXPECT_TRUE(BIO_reset(bio_cipher.get()));  // also resets owned |bio_mem|
    ASSERT_EQ((int)ct_vec.size(), BIO_write(bio_mem.get(), ct_vec.data(),
                                            ct_vec.size()));  // replace ct
    EXPECT_LE(pt_vec.size(), BIO_pending(bio_cipher.get()));
    // First read should fully succeed
    rsize = BIO_read(bio_cipher.get(), buff, io_size);
    ASSERT_EQ(io_size, rsize);
    decrypted_pt_vec.insert(decrypted_pt_vec.end(), buff, buff + rsize);
    // Disable reads from underlying BIO
    auto disable_reads = [](BIO *bio, int oper, const char *argp, size_t len,
                            int argi, long argl, int bio_ret,
                            size_t *processed) -> long {
      return (oper & BIO_CB_RETURN) || !(oper & BIO_CB_READ);
    };
    BIO_set_callback_ex(bio_mem.get(), disable_reads);
    // Set retry flags so |cipher_bio| doesn't give up when the read fails
    BIO_set_retry_read(bio_mem.get());
    rsize = BIO_read(bio_cipher.get(), buff, io_size);
    decrypted_pt_vec.insert(decrypted_pt_vec.end(), buff, buff + rsize);
    EXPECT_EQ(0UL, BIO_pending(bio_cipher.get()));
    // Re-enable reads from underlying BIO
    BIO_set_callback_ex(bio_mem.get(), nullptr);
    BIO_clear_retry_flags(bio_mem.get());
    while ((rsize = BIO_read(bio_cipher.get(), buff, io_size)) > 0) {
      decrypted_pt_vec.insert(decrypted_pt_vec.end(), buff, buff + rsize);
    }
    EXPECT_TRUE(BIO_eof(bio_cipher.get()));
    EXPECT_EQ(0UL, BIO_pending(bio_cipher.get()));
    EXPECT_TRUE(BIO_get_cipher_status(bio_cipher.get()));
    EXPECT_EQ(pt_vec.size(), decrypted_pt_vec.size());
    EXPECT_EQ(Bytes(pt_vec.data(), pt_vec.size()),
              Bytes(decrypted_pt_vec.data(), decrypted_pt_vec.size()));
    bio_mem.release();  // |bio_cipher| took ownership
>>>>>>> 6edfd1d57 (Move cipher BIO to pkcs7 directory)
  }
}
