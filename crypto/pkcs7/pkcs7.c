/* Copyright (c) 2014, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include <openssl/pkcs7.h>

#include <openssl/bytestring.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/pool.h>
#include <openssl/stack.h>

#include "internal.h"
#include "../bytestring/internal.h"


// 1.2.840.113549.1.7.1
static const uint8_t kPKCS7Data[] = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                                     0x0d, 0x01, 0x07, 0x01};

// 1.2.840.113549.1.7.2
static const uint8_t kPKCS7SignedData[] = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                                           0x0d, 0x01, 0x07, 0x02};

// pkcs7_parse_header reads the non-certificate/non-CRL prefix of a PKCS#7
// SignedData blob from |cbs| and sets |*out| to point to the rest of the
// input. If the input is in BER format, then |*der_bytes| will be set to a
// pointer that needs to be freed by the caller once they have finished
// processing |*out| (which will be pointing into |*der_bytes|).
//
// It returns one on success or zero on error. On error, |*der_bytes| is
// NULL.
int pkcs7_parse_header(uint8_t **der_bytes, CBS *out, CBS *cbs) {
  CBS in, content_info, content_type, wrapped_signed_data, signed_data;
  uint64_t version;

  // The input may be in BER format.
  *der_bytes = NULL;
  if (!CBS_asn1_ber_to_der(cbs, &in, der_bytes) ||
      // See https://tools.ietf.org/html/rfc2315#section-7
      !CBS_get_asn1(&in, &content_info, CBS_ASN1_SEQUENCE) ||
      !CBS_get_asn1(&content_info, &content_type, CBS_ASN1_OBJECT)) {
    goto err;
  }

  if (!CBS_mem_equal(&content_type, kPKCS7SignedData,
                     sizeof(kPKCS7SignedData))) {
    OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_NOT_PKCS7_SIGNED_DATA);
    goto err;
  }

  // See https://tools.ietf.org/html/rfc2315#section-9.1
  if (!CBS_get_asn1(&content_info, &wrapped_signed_data,
                    CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0) ||
      !CBS_get_asn1(&wrapped_signed_data, &signed_data, CBS_ASN1_SEQUENCE) ||
      !CBS_get_asn1_uint64(&signed_data, &version) ||
      !CBS_get_asn1(&signed_data, NULL /* digests */, CBS_ASN1_SET) ||
      !CBS_get_asn1(&signed_data, NULL /* content */, CBS_ASN1_SEQUENCE)) {
    goto err;
  }

  if (version < 1) {
    OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_BAD_PKCS7_VERSION);
    goto err;
  }

  CBS_init(out, CBS_data(&signed_data), CBS_len(&signed_data));
  return 1;

err:
  OPENSSL_free(*der_bytes);
  *der_bytes = NULL;
  return 0;
}

int PKCS7_get_raw_certificates(STACK_OF(CRYPTO_BUFFER) *out_certs, CBS *cbs,
                               CRYPTO_BUFFER_POOL *pool) {
  CBS signed_data, certificates;
  uint8_t *der_bytes = NULL;
  int ret = 0, has_certificates;
  const size_t initial_certs_len = sk_CRYPTO_BUFFER_num(out_certs);

  // See https://tools.ietf.org/html/rfc2315#section-9.1
  if (!pkcs7_parse_header(&der_bytes, &signed_data, cbs) ||
      !CBS_get_optional_asn1(
          &signed_data, &certificates, &has_certificates,
          CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0)) {
    goto err;
  }

  if (!has_certificates) {
    CBS_init(&certificates, NULL, 0);
  }

  while (CBS_len(&certificates) > 0) {
    CBS cert;
    if (!CBS_get_asn1_element(&certificates, &cert, CBS_ASN1_SEQUENCE)) {
      goto err;
    }

    CRYPTO_BUFFER *buf = CRYPTO_BUFFER_new_from_CBS(&cert, pool);
    if (buf == NULL ||
        !sk_CRYPTO_BUFFER_push(out_certs, buf)) {
      CRYPTO_BUFFER_free(buf);
      goto err;
    }
  }

  ret = 1;

err:
  OPENSSL_free(der_bytes);

  if (!ret) {
    while (sk_CRYPTO_BUFFER_num(out_certs) != initial_certs_len) {
      CRYPTO_BUFFER *buf = sk_CRYPTO_BUFFER_pop(out_certs);
      CRYPTO_BUFFER_free(buf);
    }
  }

  return ret;
}

static int pkcs7_bundle_raw_certificates_cb(CBB *out, const void *arg) {
  const STACK_OF(CRYPTO_BUFFER) *certs = arg;
  CBB certificates;

  // See https://tools.ietf.org/html/rfc2315#section-9.1
  if (!CBB_add_asn1(out, &certificates,
                    CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0)) {
    return 0;
  }

  for (size_t i = 0; i < sk_CRYPTO_BUFFER_num(certs); i++) {
    CRYPTO_BUFFER *cert = sk_CRYPTO_BUFFER_value(certs, i);
    if (!CBB_add_bytes(&certificates, CRYPTO_BUFFER_data(cert),
                       CRYPTO_BUFFER_len(cert))) {
      return 0;
    }
  }

  // |certificates| is a implicitly-tagged SET OF.
  return CBB_flush_asn1_set_of(&certificates) && CBB_flush(out);
}

int PKCS7_bundle_raw_certificates(CBB *out,
                                  const STACK_OF(CRYPTO_BUFFER) *certs) {
  return pkcs7_add_signed_data(out, /*digest_algos_cb=*/NULL,
                               pkcs7_bundle_raw_certificates_cb,
                               /*signer_infos_cb=*/NULL, certs);
}

int pkcs7_add_signed_data(CBB *out,
                          int (*digest_algos_cb)(CBB *out, const void *arg),
                          int (*cert_crl_cb)(CBB *out, const void *arg),
                          int (*signer_infos_cb)(CBB *out, const void *arg),
                          const void *arg) {
  CBB outer_seq, oid, wrapped_seq, seq, version_bytes, digest_algos_set,
      content_info, signer_infos;

  // See https://tools.ietf.org/html/rfc2315#section-7
  if (!CBB_add_asn1(out, &outer_seq, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1(&outer_seq, &oid, CBS_ASN1_OBJECT) ||
      !CBB_add_bytes(&oid, kPKCS7SignedData, sizeof(kPKCS7SignedData)) ||
      !CBB_add_asn1(&outer_seq, &wrapped_seq,
                    CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0) ||
      // See https://tools.ietf.org/html/rfc2315#section-9.1
      !CBB_add_asn1(&wrapped_seq, &seq, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1(&seq, &version_bytes, CBS_ASN1_INTEGER) ||
      !CBB_add_u8(&version_bytes, 1) ||
      !CBB_add_asn1(&seq, &digest_algos_set, CBS_ASN1_SET) ||
      (digest_algos_cb != NULL && !digest_algos_cb(&digest_algos_set, arg)) ||
      !CBB_add_asn1(&seq, &content_info, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1(&content_info, &oid, CBS_ASN1_OBJECT) ||
      !CBB_add_bytes(&oid, kPKCS7Data, sizeof(kPKCS7Data)) ||
      (cert_crl_cb != NULL && !cert_crl_cb(&seq, arg)) ||
      !CBB_add_asn1(&seq, &signer_infos, CBS_ASN1_SET) ||
      (signer_infos_cb != NULL && !signer_infos_cb(&signer_infos, arg))) {
    return 0;
  }

  return CBB_flush(out);
}

static int pkcs7_bio_add_digest(BIO **pbio, X509_ALGOR *alg,
                                const PKCS7_CTX *ctx)
{
    BIO *btmp;
    char name[OSSL_MAX_NAME_SIZE];
    const EVP_MD *md;

    if ((btmp = BIO_new(BIO_f_md())) == NULL) {
        OPENSSL_PUT_ERROR(PKCS7, ERR_R_BIO_LIB);
        goto err;
    }

    OBJ_obj2txt(name, sizeof(name), alg->algorithm, 0);

    md = EVP_get_digestbyname(name);
    if (md == NULL) {
        OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_UNKNOWN_DIGEST_TYPE);
        goto err;
    }

    if (*pbio == NULL)
        *pbio = btmp;
    else if (!BIO_push(*pbio, btmp)) {
        OPENSSL_PUT_ERROR(PKCS7, ERR_R_BIO_LIB);
        goto err;
    }
    btmp = NULL;

    return 1;

 err:
    BIO_free(btmp);
    return 0;
}

static int pkcs7_encode_rinfo(PKCS7_RECIP_INFO *ri,
                              unsigned char *key, int keylen)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    unsigned char *ek = NULL;
    int ret = 0;
    size_t eklen;
    const PKCS7_CTX *ctx = ri->ctx;

    pkey = X509_get0_pubkey(ri->cert);
    if (pkey == NULL)
        return 0;

    pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (pctx == NULL)
        return 0;

    if (EVP_PKEY_encrypt_init(pctx) <= 0)
        goto err;

    if (EVP_PKEY_encrypt(pctx, NULL, &eklen, key, keylen) <= 0)
        goto err;

    ek = OPENSSL_malloc(eklen);
    if (ek == NULL)
        goto err;

    if (EVP_PKEY_encrypt(pctx, ek, &eklen, key, keylen) <= 0)
        goto err;

    ASN1_STRING_set0(ri->enc_key, ek, eklen);
    ek = NULL;

    ret = 1;

 err:
    EVP_PKEY_CTX_free(pctx);
    OPENSSL_free(ek);
    return ret;

}

BIO *PKCS7_dataInit(PKCS7 *p7, BIO *bio)
{
    int i;
    BIO *out = NULL, *btmp = NULL;
    X509_ALGOR *xa = NULL;
    const EVP_CIPHER *evp_cipher = NULL;
    STACK_OF(X509_ALGOR) *md_sk = NULL;
    STACK_OF(PKCS7_RECIP_INFO) *rsk = NULL;
    X509_ALGOR *xalg = NULL;
    PKCS7_RECIP_INFO *ri = NULL;
    ASN1_OCTET_STRING *os = NULL;

    if (p7 == NULL) {
        OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_INVALID_NULL_POINTER);
        return NULL;
    }

    /*
     * The content field in the PKCS7 ContentInfo is optional, but that really
     * only applies to inner content (precisely, detached signatures).
     *
     * When reading content, missing outer content is therefore treated as an
     * error.
     *
     * When creating content, PKCS7_content_new() must be called before
     * calling this method, so a NULL p7->d is always an error.
     */
    if (p7->d.ptr == NULL) {
        OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_NO_CONTENT);
        return NULL;
    }

    i = OBJ_obj2nid(p7->type);

    switch (i) {
    case NID_pkcs7_signed:
        md_sk = p7->d.sign->md_algs;
        os = PKCS7_get_octet_string(p7->d.sign->contents);
        break;
    case NID_pkcs7_signedAndEnveloped:
        rsk = p7->d.signed_and_enveloped->recipientinfo;
        md_sk = p7->d.signed_and_enveloped->md_algs;
        xalg = p7->d.signed_and_enveloped->enc_data->algorithm;
        evp_cipher = p7->d.signed_and_enveloped->enc_data->cipher;
        if (evp_cipher == NULL) {
            OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_CIPHER_NOT_INITIALIZED);
            goto err;
        }
        break;
    case NID_pkcs7_enveloped:
        rsk = p7->d.enveloped->recipientinfo;
        xalg = p7->d.enveloped->enc_data->algorithm;
        evp_cipher = p7->d.enveloped->enc_data->cipher;
        if (evp_cipher == NULL) {
            OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_CIPHER_NOT_INITIALIZED);
            goto err;
        }
        break;
    case NID_pkcs7_digest:
        xa = p7->d.digest->md;
        os = PKCS7_get_octet_string(p7->d.digest->contents);
        break;
    case NID_pkcs7_data:
        break;
    default:
        OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_UNSUPPORTED_CONTENT_TYPE);
        goto err;
    }

    if (evp_cipher != NULL) {
        unsigned char key[EVP_MAX_KEY_LENGTH];
        unsigned char iv[EVP_MAX_IV_LENGTH];
        int keylen, ivlen;
        EVP_CIPHER_CTX *ctx;

        // TODO [childw] what to do about BIO_f_cipher() ? not currently supported...
        /*if ((btmp = BIO_new(BIO_f_cipher())) == NULL) {*/
        if ((btmp = NULL) == NULL) {
            OPENSSL_PUT_ERROR(PKCS7, ERR_R_BIO_LIB);
            goto err;
        }
        BIO_get_cipher_ctx(btmp, &ctx);
        keylen = EVP_CIPHER_key_length(evp_cipher);
        ivlen = EVP_CIPHER_iv_length(evp_cipher);
        xalg->algorithm = OBJ_nid2obj(EVP_CIPHER_nid(evp_cipher));
        if (ivlen > 0)
            RAND_bytes(iv, ivlen);
        if (keylen > 0)
            RAND_bytes(key, keylen);

        if (EVP_CipherInit_ex(ctx, evp_cipher, NULL, key, iv, 1) <= 0)
            goto err;

        /* Lets do the pub key stuff :-) */
        for (i = 0; i < sk_PKCS7_RECIP_INFO_num(rsk); i++) {
            ri = sk_PKCS7_RECIP_INFO_value(rsk, i);
            if (pkcs7_encode_rinfo(ri, key, keylen) <= 0)
                goto err;
        }
        OPENSSL_cleanse(key, keylen);

        if (out == NULL)
            out = btmp;
        else
            BIO_push(out, btmp);
        btmp = NULL;
    }

    if (bio == NULL) {
        if (PKCS7_is_detached(p7)) {
            // TODO [childw] need to care about BIO_s_null() ?
            /*bio = BIO_new(BIO_s_null());*/
            bio = NULL;
        } else if (os && os->length > 0) {
            bio = BIO_new_mem_buf(os->data, os->length);
        } else {
            bio = BIO_new(BIO_s_mem());
            if (bio == NULL)
                goto err;
            BIO_set_mem_eof_return(bio, 0);
        }
        if (bio == NULL)
            goto err;
    }
    if (out)
        BIO_push(out, bio);
    else
        out = bio;
    return out;

 err:
    BIO_free_all(out);
    BIO_free_all(btmp);
    return NULL;
}

int PKCS7_dataFinal(PKCS7 *p7, BIO *bio)
{
    int ret = 0;
    int i, j;
    BIO *btmp;
    PKCS7_SIGNER_INFO *si;
    EVP_MD_CTX *mdc, *ctx_tmp;
    STACK_OF(X509_ATTRIBUTE) *sk;
    STACK_OF(PKCS7_SIGNER_INFO) *si_sk = NULL;
    ASN1_OCTET_STRING *os = NULL;
    const PKCS7_CTX *p7_ctx;

    if (p7 == NULL) {
        OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_INVALID_NULL_POINTER);
        return 0;
    }

    p7_ctx = ossl_pkcs7_get0_ctx(p7);

    if (p7->d.ptr == NULL) {
        OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_NO_CONTENT);
        return 0;
    }

    ctx_tmp = EVP_MD_CTX_new();
    if (ctx_tmp == NULL) {
        OPENSSL_PUT_ERROR(PKCS7, ERR_R_EVP_LIB);
        return 0;
    }

    i = OBJ_obj2nid(p7->type);

    switch (i) {
    case NID_pkcs7_data:
        os = p7->d.data;
        break;
    case NID_pkcs7_signedAndEnveloped:
        /* XXXXXXXXXXXXXXXX */
        si_sk = p7->d.signed_and_enveloped->signer_info;
        os = p7->d.signed_and_enveloped->enc_data->enc_data;
        if (os == NULL) {
            os = ASN1_OCTET_STRING_new();
            if (os == NULL) {
                OPENSSL_PUT_ERROR(PKCS7, ERR_R_ASN1_LIB);
                goto err;
            }
            p7->d.signed_and_enveloped->enc_data->enc_data = os;
        }
        break;
    case NID_pkcs7_enveloped:
        /* XXXXXXXXXXXXXXXX */
        os = p7->d.enveloped->enc_data->enc_data;
        if (os == NULL) {
            os = ASN1_OCTET_STRING_new();
            if (os == NULL) {
                OPENSSL_PUT_ERROR(PKCS7, ERR_R_ASN1_LIB);
                goto err;
            }
            p7->d.enveloped->enc_data->enc_data = os;
        }
        break;
    case NID_pkcs7_signed:
        si_sk = p7->d.sign->signer_info;
        os = PKCS7_get_octet_string(p7->d.sign->contents);
        /* If detached data then the content is excluded */
        if (PKCS7_type_is_data(p7->d.sign->contents) && p7->detached) {
            ASN1_OCTET_STRING_free(os);
            os = NULL;
            p7->d.sign->contents->d.data = NULL;
        }
        break;

    case NID_pkcs7_digest:
        os = PKCS7_get_octet_string(p7->d.digest->contents);
        /* If detached data then the content is excluded */
        if (PKCS7_type_is_data(p7->d.digest->contents) && p7->detached) {
            ASN1_OCTET_STRING_free(os);
            os = NULL;
            p7->d.digest->contents->d.data = NULL;
        }
        break;

    default:
        OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_UNSUPPORTED_CONTENT_TYPE);
        goto err;
    }

    if (si_sk != NULL) {
        for (i = 0; i < sk_PKCS7_SIGNER_INFO_num(si_sk); i++) {
            si = sk_PKCS7_SIGNER_INFO_value(si_sk, i);
            if (si->pkey == NULL)
                continue;

            j = OBJ_obj2nid(si->digest_alg->algorithm);

            btmp = bio;

            btmp = PKCS7_find_digest(&mdc, btmp, j);

            if (btmp == NULL)
                goto err;

            /*
             * We now have the EVP_MD_CTX, lets do the signing.
             */
            if (!EVP_MD_CTX_copy_ex(ctx_tmp, mdc))
                goto err;

            sk = si->auth_attr;

            /*
             * If there are attributes, we add the digest attribute and only
             * sign the attributes
             */
            if (sk_X509_ATTRIBUTE_num(sk) > 0) {
                if (!do_pkcs7_signed_attrib(si, ctx_tmp))
                    goto err;
            } else {
                unsigned char *abuf = NULL;
                unsigned int abuflen = EVP_PKEY_get_size(si->pkey);

                if (abuflen == 0 || (abuf = OPENSSL_malloc(abuflen)) == NULL)
                    goto err;

                if (!EVP_SignFinal_ex(ctx_tmp, abuf, &abuflen, si->pkey,
                                      ossl_pkcs7_ctx_get0_libctx(p7_ctx),
                                      ossl_pkcs7_ctx_get0_propq(p7_ctx))) {
                    OPENSSL_free(abuf);
                    OPENSSL_PUT_ERROR(PKCS7, ERR_R_EVP_LIB);
                    goto err;
                }
                ASN1_STRING_set0(si->enc_digest, abuf, abuflen);
            }
        }
    } else if (i == NID_pkcs7_digest) {
        unsigned char md_data[EVP_MAX_MD_SIZE];
        unsigned int md_len;
        if (!PKCS7_find_digest(&mdc, bio,
                               OBJ_obj2nid(p7->d.digest->md->algorithm)))
            goto err;
        if (!EVP_DigestFinal_ex(mdc, md_data, &md_len))
            goto err;
        if (!ASN1_OCTET_STRING_set(p7->d.digest->digest, md_data, md_len))
            goto err;
    }

    if (!PKCS7_is_detached(p7)) {
        /*
         * NOTE(emilia): I think we only reach os == NULL here because detached
         * digested data support is broken.
         */
        if (os == NULL)
            goto err;
        if (!(os->flags & ASN1_STRING_FLAG_NDEF)) {
            char *cont;
            long contlen;
            btmp = BIO_find_type(bio, BIO_TYPE_MEM);
            if (btmp == NULL) {
                OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_UNABLE_TO_FIND_MEM_BIO);
                goto err;
            }
            contlen = BIO_get_mem_data(btmp, &cont);
            /*
             * Mark the BIO read only then we can use its copy of the data
             * instead of making an extra copy.
             */
            BIO_set_flags(btmp, BIO_FLAGS_MEM_RDONLY);
            BIO_set_mem_eof_return(btmp, 0);
            ASN1_STRING_set0(os, (unsigned char *)cont, contlen);
        }
    }
    ret = 1;
 err:
    EVP_MD_CTX_free(ctx_tmp);
    return ret;
}

/* This strongly overlaps with CMS_verify(), partly with PKCS7_dataVerify() */
int PKCS7_verify(PKCS7 *p7, STACK_OF(X509) *certs, X509_STORE *store,
                 BIO *indata, BIO *out, int flags)
{
    STACK_OF(X509) *signers;
    STACK_OF(X509) *included_certs;
    STACK_OF(X509) *untrusted = NULL;
    X509 *signer;
    STACK_OF(PKCS7_SIGNER_INFO) *sinfos;
    PKCS7_SIGNER_INFO *si;
    X509_STORE_CTX *cert_ctx = NULL;
    char *buf = NULL;
    int i, j = 0, k, ret = 0;
    BIO *p7bio = NULL;
    BIO *tmpout = NULL;
    const PKCS7_CTX *p7_ctx;

    if (p7 == NULL) {
        OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_INVALID_NULL_POINTER);
        return 0;
    }

    if (!PKCS7_type_is_signed(p7)) {
        OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_WRONG_CONTENT_TYPE);
        return 0;
    }

    /* Check for no data and no content: no data to verify signature */
    if (PKCS7_get_detached(p7) && indata == NULL) {
        OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_NO_CONTENT);
        return 0;
    }

    if (flags & PKCS7_NO_DUAL_CONTENT) {
        /*
         * This was originally "#if 0" because we thought that only old broken
         * Netscape did this.  It turns out that Authenticode uses this kind
         * of "extended" PKCS7 format, and things like UEFI secure boot and
         * tools like osslsigncode need it.  In Authenticode the verification
         * process is different, but the existing PKCs7 verification works.
         */
        if (!PKCS7_get_detached(p7) && indata != NULL) {
            OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_CONTENT_AND_DATA_PRESENT);
            return 0;
        }
    }

    sinfos = PKCS7_get_signer_info(p7);

    if (!sinfos || !sk_PKCS7_SIGNER_INFO_num(sinfos)) {
        OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_NO_SIGNATURES_ON_DATA);
        return 0;
    }

    signers = PKCS7_get0_signers(p7, certs, flags);
    if (signers == NULL)
        return 0;

    /* Now verify the certificates */
    p7_ctx = ossl_pkcs7_get0_ctx(p7);
    cert_ctx = X509_STORE_CTX_new_ex(ossl_pkcs7_ctx_get0_libctx(p7_ctx),
                                     ossl_pkcs7_ctx_get0_propq(p7_ctx));
    if (cert_ctx == NULL)
        goto err;
    if ((flags & PKCS7_NOVERIFY) == 0) {
        if (!ossl_x509_add_certs_new(&untrusted, certs, X509_ADD_FLAG_NO_DUP))
            goto err;
        included_certs = pkcs7_get0_certificates(p7);
        if ((flags & PKCS7_NOCHAIN) == 0
            && !ossl_x509_add_certs_new(&untrusted, included_certs,
                                        X509_ADD_FLAG_NO_DUP))
            goto err;

        for (k = 0; k < sk_X509_num(signers); k++) {
            signer = sk_X509_value(signers, k);
            if (!X509_STORE_CTX_init(cert_ctx, store, signer, untrusted)) {
                OPENSSL_PUT_ERROR(PKCS7, ERR_R_X509_LIB);
                goto err;
            }
            if ((flags & PKCS7_NOCHAIN) == 0
                    && !X509_STORE_CTX_set_default(cert_ctx, "smime_sign"))
                goto err;
            if (!(flags & PKCS7_NOCRL))
                X509_STORE_CTX_set0_crls(cert_ctx, p7->d.sign->crl);
            i = X509_verify_cert(cert_ctx);
            if (i <= 0) {
                j = X509_STORE_CTX_get_error(cert_ctx);
                ERR_raise_data(ERR_LIB_PKCS7, PKCS7_R_CERTIFICATE_VERIFY_ERROR,
                               "Verify error: %s",
                               X509_verify_cert_error_string(j));
                goto err;
            }
            /* Check for revocation status here */
        }
    }

    if ((p7bio = PKCS7_dataInit(p7, indata)) == NULL)
        goto err;

    if (flags & PKCS7_TEXT) {
        if ((tmpout = BIO_new(BIO_s_mem())) == NULL) {
            OPENSSL_PUT_ERROR(PKCS7, ERR_R_BIO_LIB);
            goto err;
        }
        BIO_set_mem_eof_return(tmpout, 0);
    } else
        tmpout = out;

    /* We now have to 'read' from p7bio to calculate digests etc. */
    if ((buf = OPENSSL_malloc(BUFFERSIZE)) == NULL)
        goto err;
    for (;;) {
        i = BIO_read(p7bio, buf, BUFFERSIZE);
        if (i <= 0)
            break;
        if (tmpout)
            BIO_write(tmpout, buf, i);
    }

    if (flags & PKCS7_TEXT) {
        if (!SMIME_text(tmpout, out)) {
            OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_SMIME_TEXT_ERROR);
            BIO_free(tmpout);
            goto err;
        }
        BIO_free(tmpout);
    }

    /* Now Verify All Signatures */
    if (!(flags & PKCS7_NOSIGS))
        for (i = 0; i < sk_PKCS7_SIGNER_INFO_num(sinfos); i++) {
            si = sk_PKCS7_SIGNER_INFO_value(sinfos, i);
            signer = sk_X509_value(signers, i);
            j = PKCS7_signatureVerify(p7bio, p7, si, signer);
            if (j <= 0) {
                OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_SIGNATURE_FAILURE);
                goto err;
            }
        }

    ret = 1;

 err:
    X509_STORE_CTX_free(cert_ctx);
    OPENSSL_free(buf);
    if (indata != NULL)
        BIO_pop(p7bio);
    BIO_free_all(p7bio);
    sk_X509_free(signers);
    sk_X509_free(untrusted);
    return ret;
}

STACK_OF(X509) *PKCS7_get0_signers(PKCS7 *p7, STACK_OF(X509) *certs,
                                   int flags)
{
    STACK_OF(X509) *signers, *included_certs;
    STACK_OF(PKCS7_SIGNER_INFO) *sinfos;
    PKCS7_SIGNER_INFO *si;
    PKCS7_ISSUER_AND_SERIAL *ias;
    X509 *signer;
    int i;

    if (p7 == NULL) {
        OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_INVALID_NULL_POINTER);
        return NULL;
    }

    if (!PKCS7_type_is_signed(p7)) {
        OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_WRONG_CONTENT_TYPE);
        return NULL;
    }
    included_certs = pkcs7_get0_certificates(p7);

    /* Collect all the signers together */

    sinfos = PKCS7_get_signer_info(p7);

    if (sk_PKCS7_SIGNER_INFO_num(sinfos) <= 0) {
        OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_NO_SIGNERS);
        return 0;
    }

    if ((signers = sk_X509_new_null()) == NULL) {
        OPENSSL_PUT_ERROR(PKCS7, ERR_R_CRYPTO_LIB);
        return NULL;
    }

    for (i = 0; i < sk_PKCS7_SIGNER_INFO_num(sinfos); i++) {
        si = sk_PKCS7_SIGNER_INFO_value(sinfos, i);
        ias = si->issuer_and_serial;
        signer = NULL;
        /* If any certificates passed they take priority */
        signer = X509_find_by_issuer_and_serial(certs,
                                                ias->issuer, ias->serial);
        if (signer == NULL && (flags & PKCS7_NOINTERN) == 0)
            signer = X509_find_by_issuer_and_serial(included_certs,
                                                    ias->issuer, ias->serial);
        if (signer == NULL) {
            OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_SIGNER_CERTIFICATE_NOT_FOUND);
            sk_X509_free(signers);
            return 0;
        }

        if (!sk_X509_push(signers, signer)) {
            sk_X509_free(signers);
            return NULL;
        }
    }
    return signers;
}

/* Build a complete PKCS#7 enveloped data */
PKCS7 *PKCS7_encrypt(STACK_OF(X509) *certs, BIO *in, const EVP_CIPHER *cipher,
                     int flags)
{
    PKCS7 *p7;
    BIO *p7bio = NULL;
    int i;
    X509 *x509;

    if ((p7 = PKCS7_new()) == NULL) {
        OPENSSL_PUT_ERROR(PKCS7, ERR_R_PKCS7_LIB);
        return NULL;
    }

    if (!PKCS7_set_type(p7, NID_pkcs7_enveloped))
        goto err;
    if (!PKCS7_set_cipher(p7, cipher)) {
        OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_ERROR_SETTING_CIPHER);
        goto err;
    }

    for (i = 0; i < sk_X509_num(certs); i++) {
        x509 = sk_X509_value(certs, i);
        if (!PKCS7_add_recipient(p7, x509)) {
            OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_ERROR_ADDING_RECIPIENT);
            goto err;
        }
    }

    if (flags & PKCS7_STREAM)
        return p7;

    if (PKCS7_final(p7, in, flags))
        return p7;

 err:

    BIO_free_all(p7bio);
    PKCS7_free(p7);
    return NULL;

}

int PKCS7_decrypt(PKCS7 *p7, EVP_PKEY *pkey, X509 *cert, BIO *data, int flags)
{
    BIO *tmpmem;
    int ret = 0, i;
    char *buf = NULL;

    if (p7 == NULL) {
        OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_INVALID_NULL_POINTER);
        return 0;
    }

    if (!PKCS7_type_is_enveloped(p7)
        && !PKCS7_type_is_signedAndEnveloped(p7)) {
        OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_WRONG_CONTENT_TYPE);
        return 0;
    }

    if (cert && !X509_check_private_key(cert, pkey)) {
        OPENSSL_PUT_ERROR(PKCS7,
                  PKCS7_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE);
        return 0;
    }

    if ((tmpmem = PKCS7_dataDecode(p7, pkey, NULL, cert)) == NULL) {
        OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_DECRYPT_ERROR);
        return 0;
    }

    if (flags & PKCS7_TEXT) {
        BIO *tmpbuf, *bread;
        /* Encrypt BIOs can't do BIO_gets() so add a buffer BIO */
        if ((tmpbuf = BIO_new(BIO_f_buffer())) == NULL) {
            OPENSSL_PUT_ERROR(PKCS7, ERR_R_BIO_LIB);
            BIO_free_all(tmpmem);
            return 0;
        }
        if ((bread = BIO_push(tmpbuf, tmpmem)) == NULL) {
            OPENSSL_PUT_ERROR(PKCS7, ERR_R_BIO_LIB);
            BIO_free_all(tmpbuf);
            BIO_free_all(tmpmem);
            return 0;
        }
        ret = SMIME_text(bread, data);
        if (ret > 0 && BIO_method_type(tmpmem) == BIO_TYPE_CIPHER) {
            if (BIO_get_cipher_status(tmpmem) <= 0)
                ret = 0;
        }
        BIO_free_all(bread);
        return ret;
    }
    if ((buf = OPENSSL_malloc(BUFFERSIZE)) == NULL)
        goto err;
    for (;;) {
        i = BIO_read(tmpmem, buf, BUFFERSIZE);
        if (i <= 0) {
            ret = 1;
            if (BIO_method_type(tmpmem) == BIO_TYPE_CIPHER) {
                if (BIO_get_cipher_status(tmpmem) <= 0)
                    ret = 0;
            }

            break;
        }
        if (BIO_write(data, buf, i) != i) {
            break;
        }
    }
err:
    OPENSSL_free(buf);
    BIO_free_all(tmpmem);
    return ret;
}

int PKCS7_is_detached(PKCS7 *p7) {
    if (PKCS7_type_is_signed(p7)) {
        return (p7->d.sign == NULL || p7->d.sign->contents->d.ptr == NULL);
    }
    return 0;
}

ASN1_OCTET_STRING *PKCS7_get_octet_string(PKCS7 *p7)
{
    if (PKCS7_type_is_data(p7))
        return p7->d.data;
    if (PKCS7_type_is_other(p7) && p7->d.other
        && (p7->d.other->type == V_ASN1_OCTET_STRING))
        return p7->d.other->value.octet_string;
    return NULL;
}

int PKCS7_type_is_other(const PKCS7 *p7) {
    GUARD_PTR(p7);
    switch(OBJ_obj2nid(p7->type)) {
    case NID_pkcs7_data:
    case NID_pkcs7_signed:
    case NID_pkcs7_enveloped:
    case NID_pkcs7_signedAndEnveloped:
    case NID_pkcs7_digest:
    case NID_pkcs7_encrypted:
        return 0;
    default:
        return 1;
    }
}
