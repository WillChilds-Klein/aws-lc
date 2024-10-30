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
#include <openssl/obj.h>
#include <openssl/pem.h>
#include <openssl/pool.h>
#include <openssl/rand.h>
#include <openssl/stack.h>
#include <openssl/x509.h>

#include "../bytestring/internal.h"
#include "../internal.h"
#include "internal.h"

OPENSSL_BEGIN_ALLOW_DEPRECATED

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
    if (buf == NULL || !sk_CRYPTO_BUFFER_push(out_certs, buf)) {
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

int PKCS7_set_type(PKCS7 *p7, int type) {
  if (p7 == NULL) {
    OPENSSL_PUT_ERROR(PKCS7, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }
  ASN1_OBJECT *obj = OBJ_nid2obj(type);
  if (obj == NULL) {
    OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_UNSUPPORTED_CONTENT_TYPE);
    return 0;
  }

  switch (type) {
    case NID_pkcs7_signed:
      p7->type = obj;
      PKCS7_SIGNED_free(p7->d.sign);
      p7->d.sign = PKCS7_SIGNED_new();
      if (p7->d.sign == NULL) {
        return 0;
      }
      if (!ASN1_INTEGER_set(p7->d.sign->version, 1)) {
        PKCS7_SIGNED_free(p7->d.sign);
        p7->d.sign = NULL;
        return 0;
      }
      break;
    case NID_pkcs7_digest:
      p7->type = obj;
      PKCS7_DIGEST_free(p7->d.digest);
      p7->d.digest = PKCS7_DIGEST_new();
      if (p7->d.digest == NULL) {
        return 0;
      }
      if (!ASN1_INTEGER_set(p7->d.digest->version, 0)) {
        PKCS7_DIGEST_free(p7->d.digest);
        p7->d.digest = NULL;
        return 0;
      }
      break;
    case NID_pkcs7_data:
      p7->type = obj;
      ASN1_OCTET_STRING_free(p7->d.data);
      p7->d.data = ASN1_OCTET_STRING_new();
      if (p7->d.data == NULL) {
        return 0;
      }
      break;
    case NID_pkcs7_signedAndEnveloped:
      p7->type = obj;
      PKCS7_SIGN_ENVELOPE_free(p7->d.signed_and_enveloped);
      p7->d.signed_and_enveloped = PKCS7_SIGN_ENVELOPE_new();
      if (p7->d.signed_and_enveloped == NULL) {
        return 0;
      }
      if (!ASN1_INTEGER_set(p7->d.signed_and_enveloped->version, 1)) {
        PKCS7_SIGN_ENVELOPE_free(p7->d.signed_and_enveloped);
        p7->d.signed_and_enveloped = NULL;
        return 0;
      }
      p7->d.signed_and_enveloped->enc_data->content_type =
          OBJ_nid2obj(NID_pkcs7_data);
      break;
    case NID_pkcs7_enveloped:
      p7->type = obj;
      PKCS7_ENVELOPE_free(p7->d.enveloped);
      p7->d.enveloped = PKCS7_ENVELOPE_new();
      if (p7->d.enveloped == NULL) {
        return 0;
      }
      if (!ASN1_INTEGER_set(p7->d.enveloped->version, 0)) {
        PKCS7_ENVELOPE_free(p7->d.enveloped);
        p7->d.enveloped = NULL;
        return 0;
      }
      p7->d.enveloped->enc_data->content_type = OBJ_nid2obj(NID_pkcs7_data);
      break;
    case NID_pkcs7_encrypted:
      p7->type = obj;
      PKCS7_ENCRYPT_free(p7->d.encrypted);
      p7->d.encrypted = PKCS7_ENCRYPT_new();
      if (p7->d.encrypted == NULL) {
        return 0;
      }
      if (!ASN1_INTEGER_set(p7->d.encrypted->version, 0)) {
        PKCS7_ENCRYPT_free(p7->d.encrypted);
        p7->d.encrypted = NULL;
        return 0;
      }
      p7->d.encrypted->enc_data->content_type = OBJ_nid2obj(NID_pkcs7_data);
      break;
    default:
      OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_UNSUPPORTED_CONTENT_TYPE);
      return 0;
  }
  return 1;
}

int PKCS7_set_cipher(PKCS7 *p7, const EVP_CIPHER *cipher) {
  if (p7 == NULL || cipher == NULL) {
    OPENSSL_PUT_ERROR(PKCS7, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }
  if (EVP_get_cipherbynid(EVP_CIPHER_nid(cipher)) == NULL) {
    OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER);
    return 0;
  }

  PKCS7_ENC_CONTENT *ec;
  switch (OBJ_obj2nid(p7->type)) {
    case NID_pkcs7_signedAndEnveloped:
      ec = p7->d.signed_and_enveloped->enc_data;
      break;
    case NID_pkcs7_enveloped:
      ec = p7->d.enveloped->enc_data;
      break;
    default:
      OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_WRONG_CONTENT_TYPE);
      return 0;
  }

  ec->cipher = cipher;
  return 1;
}

int PKCS7_set_content(PKCS7 *p7, PKCS7 *p7_data) {
  if (p7 == NULL) {
    OPENSSL_PUT_ERROR(PKCS7, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }

  switch (OBJ_obj2nid(p7->type)) {
    case NID_pkcs7_signed:
      PKCS7_free(p7->d.sign->contents);
      p7->d.sign->contents = p7_data;
      break;
    case NID_pkcs7_digest:
      PKCS7_free(p7->d.digest->contents);
      p7->d.digest->contents = p7_data;
      break;
    default:
      OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_UNSUPPORTED_CONTENT_TYPE);
      return 0;
  }
  return 1;
}

int PKCS7_content_new(PKCS7 *p7, int type) {
  PKCS7 *ret = PKCS7_new();
  if (ret == NULL) {
    goto err;
  }
  if (!PKCS7_set_type(ret, type)) {
    goto err;
  }
  if (!PKCS7_set_content(p7, ret)) {
    goto err;
  }
  return 1;
err:
  PKCS7_free(ret);
  return 0;
}

int PKCS7_add_recipient_info(PKCS7 *p7, PKCS7_RECIP_INFO *ri) {
  STACK_OF(PKCS7_RECIP_INFO) *sk;

  if (p7 == NULL || ri == NULL) {
    OPENSSL_PUT_ERROR(PKCS7, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }

  switch (OBJ_obj2nid(p7->type)) {
    case NID_pkcs7_signedAndEnveloped:
      sk = p7->d.signed_and_enveloped->recipientinfo;
      break;
    case NID_pkcs7_enveloped:
      sk = p7->d.enveloped->recipientinfo;
      break;
    default:
      OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_WRONG_CONTENT_TYPE);
      return 0;
  }

  if (!sk_PKCS7_RECIP_INFO_push(sk, ri)) {
    return 0;
  }
  return 1;
}

int PKCS7_add_signer(PKCS7 *p7, PKCS7_SIGNER_INFO *p7i) {
  ASN1_OBJECT *obj;
  X509_ALGOR *alg;
  STACK_OF(PKCS7_SIGNER_INFO) *signer_sk;
  STACK_OF(X509_ALGOR) *md_sk;

  if (p7 == NULL || p7i == NULL) {
    OPENSSL_PUT_ERROR(PKCS7, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }

  switch (OBJ_obj2nid(p7->type)) {
    case NID_pkcs7_signed:
      signer_sk = p7->d.sign->signer_info;
      md_sk = p7->d.sign->md_algs;
      break;
    case NID_pkcs7_signedAndEnveloped:
      signer_sk = p7->d.signed_and_enveloped->signer_info;
      md_sk = p7->d.signed_and_enveloped->md_algs;
      break;
    default:
      OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_WRONG_CONTENT_TYPE);
      return 0;
  }


  obj = p7i->digest_alg->algorithm;
  // If the digest is not currently listed, add it
  int alg_found = 0;
  for (size_t i = 0; i < sk_X509_ALGOR_num(md_sk); i++) {
    alg = sk_X509_ALGOR_value(md_sk, i);
    if (OBJ_cmp(obj, alg->algorithm) == 0) {
      alg_found = 1;
      break;
    }
  }
  if (!alg_found) {
    if ((alg = X509_ALGOR_new()) == NULL ||
        (alg->parameter = ASN1_TYPE_new()) == NULL) {
      X509_ALGOR_free(alg);
      OPENSSL_PUT_ERROR(PKCS7, ERR_R_ASN1_LIB);
      return 0;
    }
    // If there is a constant copy of the ASN1 OBJECT in libcrypto, then
    // use that.  Otherwise, use a dynamically duplicated copy.
    int nid = OBJ_obj2nid(obj);
    if (nid != NID_undef) {
      alg->algorithm = OBJ_nid2obj(nid);
    } else {
      alg->algorithm = OBJ_dup(obj);
    }
    alg->parameter->type = V_ASN1_NULL;
    if (alg->algorithm == NULL || !sk_X509_ALGOR_push(md_sk, alg)) {
      X509_ALGOR_free(alg);
      return 0;
    }
  }

  if (!sk_PKCS7_SIGNER_INFO_push(signer_sk, p7i)) {
    return 0;
  }
  return 1;
}

ASN1_TYPE *PKCS7_get_signed_attribute(const PKCS7_SIGNER_INFO *si, int nid) {
  if (si == NULL) {
    OPENSSL_PUT_ERROR(PKCS7, ERR_R_PASSED_NULL_PARAMETER);
    return NULL;
  }
  for (size_t i = 0; i < sk_X509_ATTRIBUTE_num(si->auth_attr); i++) {
    X509_ATTRIBUTE *attr = sk_X509_ATTRIBUTE_value(si->auth_attr, i);
    ASN1_OBJECT *obj = X509_ATTRIBUTE_get0_object(attr);
    if (OBJ_obj2nid(obj) == nid) {
      return X509_ATTRIBUTE_get0_type(attr, 0);
    }
  }
  return NULL;
}

int PKCS7_set_digest(PKCS7 *p7, const EVP_MD *md) {
  switch (OBJ_obj2nid(p7->type)) {
    case NID_pkcs7_digest:
      if (EVP_MD_nid(md) == NID_undef) {
        OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_UNKNOWN_DIGEST_TYPE);
        return 0;
      }
      p7->d.digest->md = md;
      return 1;
    default:
      OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_WRONG_CONTENT_TYPE);
      return 0;
  }
}

STACK_OF(PKCS7_SIGNER_INFO) *PKCS7_get_signer_info(PKCS7 *p7) {
  if (p7 == NULL || p7->d.ptr == NULL) {
    OPENSSL_PUT_ERROR(PKCS7, ERR_R_PASSED_NULL_PARAMETER);
    return NULL;
  }

  switch (OBJ_obj2nid(p7->type)) {
    case NID_pkcs7_signed:
      return p7->d.sign->signer_info;
    case NID_pkcs7_signedAndEnveloped:
      return p7->d.signed_and_enveloped->signer_info;
    default:
      return NULL;
  }
}


STACK_OF(PKCS7_RECIP_INFO) *PKCS7_get_recipient_info(PKCS7 *p7) {
  if (p7 == NULL || p7->d.ptr == NULL) {
    return NULL;
  } else if (PKCS7_type_is_enveloped(p7)) {
    return p7->d.enveloped->recipientinfo;
  } else if (PKCS7_type_is_signedAndEnveloped(p7)) {
    return p7->d.signed_and_enveloped->recipientinfo;
  }
  return NULL;
}

int PKCS7_SIGNER_INFO_set(PKCS7_SIGNER_INFO *p7i, X509 *x509, EVP_PKEY *pkey,
                          const EVP_MD *dgst) {
  if (!p7i || !x509 || !pkey || !dgst) {
    OPENSSL_PUT_ERROR(PKCS7, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  } else if (!ASN1_INTEGER_set(p7i->version, 1)) {
    return 0;
  } else if (!X509_NAME_set(&p7i->issuer_and_serial->issuer,
                            X509_get_issuer_name(x509))) {
    return 0;
  }

  ASN1_INTEGER_free(p7i->issuer_and_serial->serial);
  if (!(p7i->issuer_and_serial->serial =
            ASN1_INTEGER_dup(X509_get0_serialNumber(x509)))) {
    return 0;
  }

  // NOTE: OpenSSL does not free |p7i->pkey| before setting it. we do so here
  // to avoid potential memory leaks.
  EVP_PKEY_free(p7i->pkey);
  EVP_PKEY_up_ref(pkey);
  p7i->pkey = pkey;

  if (!X509_ALGOR_set0(p7i->digest_alg, OBJ_nid2obj(EVP_MD_type(dgst)),
                       V_ASN1_NULL, NULL)) {
    return 0;
  }

  switch (EVP_PKEY_id(pkey)) {
    case EVP_PKEY_EC:
    case EVP_PKEY_DH: {
      int snid, hnid;
      X509_ALGOR *alg1, *alg2;
      PKCS7_SIGNER_INFO_get0_algs(p7i, NULL, &alg1, &alg2);
      if (alg1 == NULL || alg1->algorithm == NULL) {
        return 0;
      }
      hnid = OBJ_obj2nid(alg1->algorithm);
      if (hnid == NID_undef ||
          !OBJ_find_sigid_by_algs(&snid, hnid, EVP_PKEY_id(pkey)) ||
          !X509_ALGOR_set0(alg2, OBJ_nid2obj(snid), V_ASN1_UNDEF, NULL)) {
        return 0;
      }
      break;
    }
    case EVP_PKEY_RSA:
    case EVP_PKEY_RSA_PSS: {
      X509_ALGOR *alg = NULL;
      PKCS7_SIGNER_INFO_get0_algs(p7i, NULL, NULL, &alg);
      if (alg != NULL) {
        return X509_ALGOR_set0(alg, OBJ_nid2obj(NID_rsaEncryption), V_ASN1_NULL,
                               NULL);
      }
      break;
    }
    default:
      OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_SIGNING_NOT_SUPPORTED_FOR_THIS_KEY_TYPE);
      return 0;
  }

  return 1;
}

int PKCS7_RECIP_INFO_set(PKCS7_RECIP_INFO *p7i, X509 *x509) {
  if (!p7i || !x509) {
    OPENSSL_PUT_ERROR(PKCS7, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }
  if (!ASN1_INTEGER_set(p7i->version, 0)) {
    return 0;
  } else if (!X509_NAME_set(&p7i->issuer_and_serial->issuer,
                            X509_get_issuer_name(x509))) {
    return 0;
  }

  ASN1_INTEGER_free(p7i->issuer_and_serial->serial);
  if (!(p7i->issuer_and_serial->serial =
            ASN1_INTEGER_dup(X509_get0_serialNumber(x509)))) {
    return 0;
  }

  EVP_PKEY *pkey = X509_get0_pubkey(x509);
  if (pkey == NULL) {
    return 0;
  }

  if (EVP_PKEY_id(pkey) == EVP_PKEY_RSA_PSS) {
    return 0;
  } else if (EVP_PKEY_id(pkey) == EVP_PKEY_RSA) {
    X509_ALGOR *alg;
    PKCS7_RECIP_INFO_get0_alg(p7i, &alg);
    if (!X509_ALGOR_set0(alg, OBJ_nid2obj(NID_rsaEncryption), V_ASN1_NULL,
                         NULL)) {
      return 0;
    }
  }

  // NOTE: OpenSSL does not free |p7i->cert| before setting it. we do so here
  // to avoid potential memory leaks.
  X509_free(p7i->cert);
  X509_up_ref(x509);
  p7i->cert = x509;

  return 1;
}

void PKCS7_SIGNER_INFO_get0_algs(PKCS7_SIGNER_INFO *si, EVP_PKEY **pk,
                                 X509_ALGOR **pdig, X509_ALGOR **psig) {
  if (!si) {
    return;
  }
  if (pk) {
    *pk = si->pkey;
  }
  if (pdig) {
    *pdig = si->digest_alg;
  }
  if (psig) {
    *psig = si->digest_enc_alg;
  }
}

void PKCS7_RECIP_INFO_get0_alg(PKCS7_RECIP_INFO *ri, X509_ALGOR **penc) {
  if (!ri) {
    return;
  }
  if (penc) {
    *penc = ri->key_enc_algor;
  }
}

static int pkcs7_encode_rinfo(PKCS7_RECIP_INFO *ri, unsigned char *key,
                              int keylen) {
  EVP_PKEY_CTX *pctx = NULL;
  EVP_PKEY *pkey = NULL;
  unsigned char *ek = NULL;
  int ret = 0;
  size_t eklen;

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

BIO *PKCS7_dataInit(PKCS7 *p7, BIO *bio) {
  int i;
  BIO *out = NULL, *btmp = NULL;
  const EVP_CIPHER *evp_cipher = NULL;
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
      os = PKCS7_get_octet_string(p7->d.sign->contents);
      break;
    case NID_pkcs7_signedAndEnveloped:
      rsk = p7->d.signed_and_enveloped->recipientinfo;
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

    if ((btmp = BIO_new(BIO_f_cipher())) == NULL) {
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
    for (size_t ii = 0; ii < sk_PKCS7_RECIP_INFO_num(rsk); ii++) {
      ri = sk_PKCS7_RECIP_INFO_value(rsk, ii);
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
    if (os && os->length > 0) {
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

static BIO *PKCS7_find_digest(EVP_MD_CTX **pmd, BIO *bio, int nid) {
  for (;;) {
    bio = BIO_find_type(bio, BIO_TYPE_MD);
    if (bio == NULL) {
      OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_UNABLE_TO_FIND_MESSAGE_DIGEST);
      return NULL;
    }
    BIO_get_md_ctx(bio, pmd);
    if (*pmd == NULL) {
      OPENSSL_PUT_ERROR(PKCS7, ERR_R_INTERNAL_ERROR);
      return NULL;
    }
    if (EVP_MD_CTX_type(*pmd) == nid)
      return bio;
    bio = BIO_next(bio);
  }
  return NULL;
}

int PKCS7_dataFinal(PKCS7 *p7, BIO *bio) {
  int ret = 0;
  int i, j;
  BIO *btmp;
  PKCS7_SIGNER_INFO *si;
  EVP_MD_CTX *mdc, *ctx_tmp;
  STACK_OF(X509_ATTRIBUTE) *sk;
  STACK_OF(PKCS7_SIGNER_INFO) *si_sk = NULL;
  ASN1_OCTET_STRING *os = NULL;

  if (p7 == NULL) {
    OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_INVALID_NULL_POINTER);
    return 0;
  }

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
      if (PKCS7_type_is_data(p7->d.sign->contents) && PKCS7_is_detached(p7)) {
        ASN1_OCTET_STRING_free(os);
        os = NULL;
        p7->d.sign->contents->d.data = NULL;
      }
      break;

    case NID_pkcs7_digest:
      os = PKCS7_get_octet_string(p7->d.digest->contents);
      /* If detached data then the content is excluded */
      if (PKCS7_type_is_data(p7->d.digest->contents) && PKCS7_is_detached(p7)) {
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
    for (size_t ii = 0; ii < sk_PKCS7_SIGNER_INFO_num(si_sk); ii++) {
      si = sk_PKCS7_SIGNER_INFO_value(si_sk, ii);
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

      /* TODO [childw] we don't currently sign attributes like OSSL does
       * https://github.com/openssl/openssl/blob/2f33265039cdbd0e4589c80970e02e208f3f94d2/crypto/pkcs7/pk7_doit.c#L687
       */
      if (sk_X509_ATTRIBUTE_num(sk) > 0) {
        OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_PKCS7_DATASIGN);
        goto err;
      }
      unsigned char *abuf = NULL;
      unsigned int abuflen = EVP_PKEY_size(si->pkey);

      if (abuflen == 0 || (abuf = OPENSSL_malloc(abuflen)) == NULL)
        goto err;

      if (!EVP_SignInit_ex(ctx_tmp, ctx_tmp->digest, NULL) ||
          !EVP_SignFinal(ctx_tmp, abuf, &abuflen, si->pkey)) {
        OPENSSL_free(abuf);
        OPENSSL_PUT_ERROR(PKCS7, ERR_R_EVP_LIB);
        goto err;
      }
      ASN1_STRING_set0(si->enc_digest, abuf, abuflen);
    }
  } else if (i == NID_pkcs7_digest) {
    unsigned char md_data[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    if (!PKCS7_find_digest(&mdc, bio, EVP_MD_nid(p7->d.digest->md)))
      goto err;
    if (!EVP_DigestFinal_ex(mdc, md_data, &md_len))
      goto err;
    if (!ASN1_OCTET_STRING_set(p7->d.digest->digest, md_data, md_len))
      goto err;
  }

  if (!PKCS7_is_detached(p7) && os == NULL) {
    goto err;
  }
  ret = 1;
err:
  EVP_MD_CTX_free(ctx_tmp);
  return ret;
}

int PKCS7_is_detached(PKCS7 *p7) {
  if (PKCS7_type_is_signed(p7)) {
    return (p7->d.sign == NULL || p7->d.sign->contents->d.ptr == NULL);
  }
  return 0;
}

ASN1_OCTET_STRING *PKCS7_get_octet_string(PKCS7 *p7) {
  if (PKCS7_type_is_data(p7))
    return p7->d.data;
  if (PKCS7_type_is_other(p7) && p7->d.other &&
      (p7->d.other->type == V_ASN1_OCTET_STRING))
    return p7->d.other->value.octet_string;
  return NULL;
}

int PKCS7_type_is_other(const PKCS7 *p7) {
  GUARD_PTR(p7);
  switch (OBJ_obj2nid(p7->type)) {
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

PKCS7 *PKCS7_encrypt(STACK_OF(X509) *certs, BIO *in, const EVP_CIPHER *cipher,
                     int flags) {
  PKCS7 *p7;
  BIO *p7bio = NULL;
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

  for (size_t i = 0; i < sk_X509_num(certs); i++) {
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

int PKCS7_decrypt(PKCS7 *p7, EVP_PKEY *pkey, X509 *cert, BIO *data, int flags) {
  BIO *tmpmem;
  int ret = 0, i;

  if (p7 == NULL) {
    OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_INVALID_NULL_POINTER);
    return 0;
  }

  if (!PKCS7_type_is_enveloped(p7) && !PKCS7_type_is_signedAndEnveloped(p7)) {
    OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_WRONG_CONTENT_TYPE);
    return 0;
  }

  if (cert && !X509_check_private_key(cert, pkey)) {
    OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE);
    return 0;
  }

  if ((tmpmem = PKCS7_dataDecode(p7, pkey, NULL, cert)) == NULL) {
    OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_DECRYPT_ERROR);
    return 0;
  }

  // TODO [childw] support this?
  // if (flags & PKCS7_TEXT) {
  //   BIO *tmpbuf, *bread;
  //   /* Encrypt BIOs can't do BIO_gets() so add a buffer BIO */
  //   if ((tmpbuf = BIO_new(BIO_f_buffer())) == NULL) {
  //     OPENSSL_PUT_ERROR(PKCS7, ERR_R_BIO_LIB);
  //     BIO_free_all(tmpmem);
  //     return 0;
  //   }
  //   if ((bread = BIO_push(tmpbuf, tmpmem)) == NULL) {
  //     OPENSSL_PUT_ERROR(PKCS7, ERR_R_BIO_LIB);
  //     BIO_free_all(tmpbuf);
  //     BIO_free_all(tmpmem);
  //     return 0;
  //   }
  //   ret = SMIME_text(bread, data);
  //   if (ret > 0 && BIO_method_type(tmpmem) == BIO_TYPE_CIPHER) {
  //     if (BIO_get_cipher_status(tmpmem) <= 0)
  //       ret = 0;
  //   }
  //   BIO_free_all(bread);
  //   return ret;
  // }

  uint8_t *buf[1024];
  for (;;) {
    i = BIO_read(tmpmem, buf, sizeof(buf));
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
  BIO_free_all(tmpmem);
  return ret;
}

PKCS7 *SMIME_read_PKCS7(BIO *in, BIO **bcont) { return 0; }

int SMIME_write_PKCS7(BIO *out, PKCS7 *p7, BIO *data, int flags) { return 0; }

PKCS7_RECIP_INFO *PKCS7_add_recipient(PKCS7 *p7, X509 *x509) {
  PKCS7_RECIP_INFO *ri;

  if ((ri = PKCS7_RECIP_INFO_new()) == NULL)
    goto err;
  if (PKCS7_RECIP_INFO_set(ri, x509) <= 0)
    goto err;
  if (!PKCS7_add_recipient_info(p7, ri))
    goto err;
  return ri;
err:
  PKCS7_RECIP_INFO_free(ri);
  return NULL;
}


int PKCS7_final(PKCS7 *p7, BIO *data, int flags) {
  BIO *p7bio;
  int ret = 0;

  if ((p7bio = PKCS7_dataInit(p7, NULL)) == NULL) {
    OPENSSL_PUT_ERROR(PKCS7, ERR_R_PKCS7_LIB);
    return 0;
  }

  // poor man's SMIME_crlf_copy
  uint8_t buf[1024];
  while ((ret = BIO_read(data, buf, sizeof(buf))) > 0) {
    if ((ret = BIO_write(p7bio, buf, ret)) <= 0) {
      break;
    }
  }
  if (ret <= 0) {
    goto err;
  }

  (void)BIO_flush(p7bio);

  if (!PKCS7_dataFinal(p7, p7bio)) {
    OPENSSL_PUT_ERROR(PKCS7, ERR_R_PKCS7_LIB);
    goto err;
  }
  ret = 1;
err:
  BIO_free_all(p7bio);

  return ret;
}

static int pkcs7_cmp_ri(PKCS7_RECIP_INFO *ri, X509 *pcert) {
  int ret;
  ret =
      X509_NAME_cmp(ri->issuer_and_serial->issuer, X509_get_issuer_name(pcert));
  if (ret)
    return ret;
  return ASN1_INTEGER_cmp(X509_get0_serialNumber(pcert),
                          ri->issuer_and_serial->serial);
}

static /* decrypt to new buffer of dynamic size, checking any pre-determined
          size */
    int
    evp_pkey_decrypt_alloc(EVP_PKEY_CTX *ctx, unsigned char **outp,
                           size_t *outlenp, size_t expected_outlen,
                           const unsigned char *in, size_t inlen) {
  if (EVP_PKEY_decrypt(ctx, NULL, outlenp, in, inlen) <= 0 ||
      (*outp = OPENSSL_malloc(*outlenp)) == NULL)
    return -1;
  if (EVP_PKEY_decrypt(ctx, *outp, outlenp, in, inlen) <= 0 || *outlenp == 0 ||
      (expected_outlen != 0 && *outlenp != expected_outlen)) {
    OPENSSL_PUT_ERROR(EVP, ERR_R_EVP_LIB);
    OPENSSL_clear_free(*outp, *outlenp);
    *outp = NULL;
    return 0;
  }
  return 1;
}

static int pkcs7_decrypt_rinfo(unsigned char **pek, int *peklen,
                               PKCS7_RECIP_INFO *ri, EVP_PKEY *pkey,
                               size_t fixlen) {
  EVP_PKEY_CTX *pctx = NULL;
  unsigned char *ek = NULL;
  size_t eklen;
  int ret = -1;

  pctx = EVP_PKEY_CTX_new(pkey, /*engine*/ NULL);
  if (pctx == NULL)
    return -1;

  if (EVP_PKEY_decrypt_init(pctx) <= 0)
    goto err;

  if (EVP_PKEY_id(pkey) == EVP_PKEY_RSA)
    /* upper layer pkcs7 code incorrectly assumes that a successful RSA
     * decryption means that the key matches ciphertext (which never
     * was the case, implicit rejection or not), so to make it work
     * disable implicit rejection for RSA keys */
    EVP_PKEY_CTX_ctrl_str(pctx, "rsa_pkcs1_implicit_rejection", "0");

  ret = evp_pkey_decrypt_alloc(pctx, &ek, &eklen, fixlen, ri->enc_key->data,
                               ri->enc_key->length);
  if (ret <= 0)
    goto err;

  ret = 1;

  OPENSSL_clear_free(*pek, *peklen);
  *pek = ek;
  *peklen = eklen;

err:
  EVP_PKEY_CTX_free(pctx);
  if (!ret)
    OPENSSL_free(ek);

  return ret;
}

BIO *PKCS7_dataDecode(PKCS7 *p7, EVP_PKEY *pkey, BIO *in_bio, X509 *pcert) {
  int i, len;
  BIO *out = NULL, *btmp = NULL, *etmp = NULL, *bio = NULL;
  X509_ALGOR *xa;
  ASN1_OCTET_STRING *data_body = NULL;
  const EVP_MD *md;
  const EVP_CIPHER *cipher = NULL;
  EVP_CIPHER_CTX *evp_ctx = NULL;
  X509_ALGOR *enc_alg = NULL;
  STACK_OF(X509_ALGOR) *md_sk = NULL;
  STACK_OF(PKCS7_RECIP_INFO) *rsk = NULL;
  PKCS7_RECIP_INFO *ri = NULL;
  unsigned char *ek = NULL, *tkey = NULL;
  int eklen = 0, tkeylen = 0;

  if (p7 == NULL) {
    OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_INVALID_NULL_POINTER);
    return NULL;
  }

  if (p7->d.ptr == NULL) {
    OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_NO_CONTENT);
    return NULL;
  }

  i = OBJ_obj2nid(p7->type);

  switch (i) {
    case NID_pkcs7_signed:
      /*
       * p7->d.sign->contents is a PKCS7 structure consisting of a contentType
       * field and optional content.
       * data_body is NULL if that structure has no (=detached) content
       * or if the contentType is wrong (i.e., not "data").
       */
      data_body = PKCS7_get_octet_string(p7->d.sign->contents);
      if (!PKCS7_is_detached(p7) && data_body == NULL) {
        OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_INVALID_SIGNED_DATA_TYPE);
        goto err;
      }
      md_sk = p7->d.sign->md_algs;
      break;
    case NID_pkcs7_signedAndEnveloped:
      rsk = p7->d.signed_and_enveloped->recipientinfo;
      md_sk = p7->d.signed_and_enveloped->md_algs;
      /* data_body is NULL if the optional EncryptedContent is missing. */
      data_body = p7->d.signed_and_enveloped->enc_data->enc_data;
      enc_alg = p7->d.signed_and_enveloped->enc_data->algorithm;
      cipher = EVP_get_cipherbynid(OBJ_obj2nid(enc_alg->algorithm));
      if (cipher == NULL) {
        OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_UNSUPPORTED_CIPHER_TYPE);
        goto err;
      }
      break;
    case NID_pkcs7_enveloped:
      rsk = p7->d.enveloped->recipientinfo;
      enc_alg = p7->d.enveloped->enc_data->algorithm;
      cipher = EVP_get_cipherbynid(OBJ_obj2nid(enc_alg->algorithm));
      /* data_body is NULL if the optional EncryptedContent is missing. */
      data_body = p7->d.enveloped->enc_data->enc_data;

      if (cipher == NULL) {
        OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_UNSUPPORTED_CIPHER_TYPE);
        goto err;
      }
      break;
    default:
      OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_UNSUPPORTED_CONTENT_TYPE);
      goto err;
  }

  /* Detached content must be supplied via in_bio instead. */
  if (data_body == NULL && in_bio == NULL) {
    OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_NO_CONTENT);
    goto err;
  }

  /* We will be checking the signature */
  if (md_sk != NULL) {
    for (size_t ii = 0; ii < sk_X509_ALGOR_num(md_sk); ii++) {
      xa = sk_X509_ALGOR_value(md_sk, ii);
      if ((btmp = BIO_new(BIO_f_md())) == NULL) {
        OPENSSL_PUT_ERROR(PKCS7, ERR_R_BIO_LIB);
        goto err;
      }

      md = EVP_get_digestbynid(OBJ_obj2nid(xa->algorithm));
      if (md == NULL) {
        OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_UNKNOWN_DIGEST_TYPE);
        goto err;
      }

      if (BIO_set_md(btmp, (EVP_MD *)md) <= 0) {
        OPENSSL_PUT_ERROR(PKCS7, ERR_R_BIO_LIB);
        goto err;
      }
      if (out == NULL)
        out = btmp;
      else
        BIO_push(out, btmp);
      btmp = NULL;
    }
  }

  if (cipher != NULL) {
    if ((etmp = BIO_new(BIO_f_cipher())) == NULL) {
      OPENSSL_PUT_ERROR(PKCS7, ERR_R_BIO_LIB);
      goto err;
    }

    /*
     * It was encrypted, we need to decrypt the secret key with the
     * private key
     */

    /*
     * Find the recipientInfo which matches the passed certificate (if
     * any)
     */

    if (pcert) {
      for (size_t ii = 0; ii < sk_PKCS7_RECIP_INFO_num(rsk); ii++) {
        ri = sk_PKCS7_RECIP_INFO_value(rsk, ii);
        if (!pkcs7_cmp_ri(ri, pcert))
          break;
        ri = NULL;
      }
      if (ri == NULL) {
        OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_NO_RECIPIENT_MATCHES_CERTIFICATE);
        goto err;
      }
    }

    /* If we haven't got a certificate try each ri in turn */
    if (pcert == NULL) {
      /*
       * Always attempt to decrypt all rinfo even after success as a
       * defence against MMA timing attacks.
       */
      for (size_t ii = 0; ii < sk_PKCS7_RECIP_INFO_num(rsk); ii++) {
        ri = sk_PKCS7_RECIP_INFO_value(rsk, ii);
        if (pkcs7_decrypt_rinfo(&ek, &eklen, ri, pkey,
                                EVP_CIPHER_key_length(cipher)) < 0)
          goto err;
        ERR_clear_error();
      }
    } else {
      /* Only exit on fatal errors, not decrypt failure */
      if (pkcs7_decrypt_rinfo(&ek, &eklen, ri, pkey, 0) < 0)
        goto err;
      ERR_clear_error();
    }

    evp_ctx = NULL;
    BIO_get_cipher_ctx(etmp, &evp_ctx);
    if (EVP_CipherInit_ex(evp_ctx, cipher, NULL, NULL, NULL, 0) <= 0)
      goto err;
    // TODO [childw] -- do we need this?
    // if (EVP_CIPHER_asn1_to_param(evp_ctx, enc_alg->parameter) <= 0)
    // goto err;
    /* Generate random key as MMA defence */
    len = EVP_CIPHER_CTX_key_length(evp_ctx);
    if (len <= 0)
      goto err;
    tkeylen = (size_t)len;
    tkey = OPENSSL_malloc(tkeylen);
    if (tkey == NULL)
      goto err;
    RAND_bytes(tkey, tkeylen);
    if (ek == NULL) {
      ek = tkey;
      eklen = tkeylen;
      tkey = NULL;
    }

    if ((unsigned) eklen != EVP_CIPHER_CTX_key_length(evp_ctx)) {
      /*
       * Some S/MIME clients don't use the same key and effective key
       * length. The key length is determined by the size of the
       * decrypted RSA key.
       */
      if (EVP_CIPHER_CTX_set_key_length(evp_ctx, eklen) <= 0) {
        /* Use random key as MMA defence */
        OPENSSL_clear_free(ek, eklen);
        ek = tkey;
        eklen = tkeylen;
        tkey = NULL;
      }
    }
    /* Clear errors so we don't leak information useful in MMA */
    if (EVP_CipherInit_ex(evp_ctx, NULL, NULL, ek, NULL, 0) <= 0)
      goto err;

    OPENSSL_clear_free(ek, eklen);
    ek = NULL;
    OPENSSL_clear_free(tkey, tkeylen);
    tkey = NULL;

    if (out == NULL)
      out = etmp;
    else
      BIO_push(out, etmp);
    etmp = NULL;
  }
  if (in_bio != NULL) {
    bio = in_bio;
  } else {
    if (data_body->length > 0)
      bio = BIO_new_mem_buf(data_body->data, data_body->length);
    else {
      bio = BIO_new(BIO_s_mem());
      if (bio == NULL)
        goto err;
      BIO_set_mem_eof_return(bio, 0);
    }
    if (bio == NULL)
      goto err;
  }
  BIO_push(out, bio);
  bio = NULL;
  return out;

err:
  OPENSSL_clear_free(ek, eklen);
  OPENSSL_clear_free(tkey, tkeylen);
  BIO_free_all(out);
  BIO_free_all(btmp);
  BIO_free_all(etmp);
  BIO_free_all(bio);
  return NULL;
}

static STACK_OF(X509) *pkcs7_get0_certificates(const PKCS7 *p7)
{
  if (p7->d.ptr == NULL)
    return NULL;
  if (PKCS7_type_is_signed(p7))
    return p7->d.sign->cert;
  if (PKCS7_type_is_signedAndEnveloped(p7))
    return p7->d.signed_and_enveloped->cert;
  return NULL;
}

static STACK_OF(X509) *PKCS7_get0_signers(PKCS7 *p7, STACK_OF(X509) *certs,
                                   int flags)
{
  STACK_OF(X509) *signers, *included_certs;
  STACK_OF(PKCS7_SIGNER_INFO) *sinfos;
  PKCS7_SIGNER_INFO *si;
  PKCS7_ISSUER_AND_SERIAL *ias;
  X509 *signer;

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

  for (size_t i = 0; i < sk_PKCS7_SIGNER_INFO_num(sinfos); i++) {
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

static int X509_add_cert(STACK_OF(X509) *sk, X509 *cert, int flags)
{
  if (sk == NULL) {
    OPENSSL_PUT_ERROR(X509, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }
  if (!sk_X509_insert(sk, cert, -1)) {
    OPENSSL_PUT_ERROR(X509, ERR_R_CRYPTO_LIB);
    return 0;
                      }
  return 1;
}

static int ossl_x509_add_cert_new(STACK_OF(X509) **p_sk, X509 *cert, int flags)
{
  if (*p_sk == NULL && (*p_sk = sk_X509_new_null()) == NULL) {
    OPENSSL_PUT_ERROR(X509, ERR_R_CRYPTO_LIB);
    return 0;
  }
  return X509_add_cert(*p_sk, cert, flags);
}

static int ossl_x509_add_certs_new(STACK_OF(X509) **p_sk, STACK_OF(X509) *certs,
                            int flags) {
  /* compiler would allow 'const' for the certs, yet they may get up-ref'ed */
  int n = sk_X509_num(certs /* may be NULL */);
  int i;

  for (i = 0; i < n; i++) {
    /* if prepend, add certs in reverse order to keep original order */
    if (!ossl_x509_add_cert_new(p_sk, sk_X509_value(certs, i), flags))
      return 0;
  }
  return 1;
}


// static ASN1_TYPE *get_attribute(const STACK_OF(X509_ATTRIBUTE) *sk, int nid)
// {
//   int idx = X509at_get_attr_by_NID(sk, nid, -1);
//
//   if (idx < 0)
//     return NULL;
//   return X509_ATTRIBUTE_get0_type(X509at_get_attr(sk, idx), 0);
// }
//
// static ASN1_OCTET_STRING *PKCS7_digest_from_attributes(STACK_OF(X509_ATTRIBUTE) *sk)
// {
//   ASN1_TYPE *astype;
//   if ((astype = get_attribute(sk, NID_pkcs9_messageDigest)) == NULL)
//     return NULL;
//   return astype->value.octet_string;
// }

static int PKCS7_signatureVerify(BIO *bio, PKCS7 *p7, PKCS7_SIGNER_INFO *si,
                          X509 *signer)
{
    ASN1_OCTET_STRING *os;
    EVP_MD_CTX *mdc_tmp, *mdc;
    int ret = 0, i;
    int md_type;
    STACK_OF(X509_ATTRIBUTE) *sk;
    BIO *btmp;
    EVP_PKEY *pkey;
    unsigned char *abuf = NULL;

    mdc_tmp = EVP_MD_CTX_new();
    if (mdc_tmp == NULL) {
        OPENSSL_PUT_ERROR(PKCS7, ERR_R_EVP_LIB);
        goto err;
    }

    if (!PKCS7_type_is_signed(p7) && !PKCS7_type_is_signedAndEnveloped(p7)) {
        OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_WRONG_PKCS7_TYPE);
        goto err;
    }

    md_type = OBJ_obj2nid(si->digest_alg->algorithm);

    btmp = bio;
    for (;;) {
        if ((btmp == NULL) ||
            ((btmp = BIO_find_type(btmp, BIO_TYPE_MD)) == NULL)) {
            OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_UNABLE_TO_FIND_MESSAGE_DIGEST);
            goto err;
        }
        BIO_get_md_ctx(btmp, &mdc);
        if (mdc == NULL) {
            OPENSSL_PUT_ERROR(PKCS7, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (EVP_MD_CTX_type(mdc) == md_type)
            break;
        /*
         * Workaround for some broken clients that put the signature OID
         * instead of the digest OID in digest_alg->algorithm
         */
        if (EVP_MD_get_pkey_type(EVP_MD_CTX_md(mdc)) == md_type)
            break;
        btmp = BIO_next(btmp);
    }

    /*
     * mdc is the digest ctx that we want, unless there are attributes, in
     * which case the digest is the signed attributes
     */
    if (!EVP_MD_CTX_copy_ex(mdc_tmp, mdc))
        goto err;

    sk = si->auth_attr;
    if ((sk != NULL) && (sk_X509_ATTRIBUTE_num(sk) != 0)) {
      // TODO [childw] can we get away with not supporting this?
      OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_WRONG_CONTENT_TYPE);
      goto err;
        // unsigned char md_dat[EVP_MAX_MD_SIZE];
        // unsigned int md_len;
        // int alen;
        // ASN1_OCTET_STRING *message_digest;
        //
        // if (!EVP_DigestFinal_ex(mdc_tmp, md_dat, &md_len))
        //     goto err;
        // message_digest = PKCS7_digest_from_attributes(sk);
        // if (!message_digest) {
        //     OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_UNABLE_TO_FIND_MESSAGE_DIGEST);
        //     goto err;
        // }
        // if ((message_digest->length != (int)md_len) ||
        //     (memcmp(message_digest->data, md_dat, md_len))) {
        //     OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_DIGEST_FAILURE);
        //     ret = -1;
        //     goto err;
        // }
        //
        // const EVP_MD *md = EVP_get_digestbynid(md_type);
        // if (md == NULL || !EVP_VerifyInit_ex(mdc_tmp, md, NULL)) {
        //     goto err;
        // }
        //
        // alen = ASN1_item_i2d((ASN1_VALUE *)sk, &abuf,
        //                      ASN1_ITEM_rptr(PKCS7_ATTR_VERIFY));
        // if (alen <= 0 || abuf == NULL) {
        //     OPENSSL_PUT_ERROR(PKCS7, ERR_R_ASN1_LIB);
        //     ret = -1;
        //     goto err;
        // }
        // if (!EVP_VerifyUpdate(mdc_tmp, abuf, alen))
        //     goto err;
    }

    os = si->enc_digest;
    pkey = X509_get0_pubkey(signer);
    if (pkey == NULL) {
        ret = -1;
        goto err;
    }

    i = EVP_VerifyFinal(mdc_tmp, os->data, os->length, pkey);
    if (i <= 0) {
        OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_SIGNATURE_FAILURE);
        ret = -1;
        goto err;
    }
    ret = 1;
 err:
    OPENSSL_free(abuf);
    EVP_MD_CTX_free(mdc_tmp);
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
    int i, j = 0, ret = 0;
    BIO *p7bio = NULL;
    BIO *tmpout = NULL;

    if (p7 == NULL) {
        OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_INVALID_NULL_POINTER);
        return 0;
    }

    if (!PKCS7_type_is_signed(p7)) {
        OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_WRONG_CONTENT_TYPE);
        return 0;
    }

    /* Check for no data and no content: no data to verify signature */
    if (PKCS7_is_detached(p7) && indata == NULL) {
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
        if (!PKCS7_is_detached(p7) && indata != NULL) {
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
    cert_ctx = X509_STORE_CTX_new();
    if (cert_ctx == NULL)
        goto err;
    if ((flags & PKCS7_NOVERIFY) == 0) {
        if (!ossl_x509_add_certs_new(&untrusted, certs, 0/*flags*/))
            goto err;
        included_certs = pkcs7_get0_certificates(p7);
        if ((flags & PKCS7_NOCHAIN) == 0
            && !ossl_x509_add_certs_new(&untrusted, included_certs, 0/*flags*/))
            goto err;

        for (size_t k = 0; k < sk_X509_num(signers); k++) {
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
                OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_CERTIFICATE_VERIFY_ERROR);
                goto err;
            }
            /* Check for revocation status here */
        }
    }

    if ((p7bio = PKCS7_dataInit(p7, indata)) == NULL)
        goto err;

    // TODO [childw] determine whether to support, likely no.
      if (flags & PKCS7_TEXT) {
        // if ((tmpout = BIO_new(BIO_s_mem())) == NULL) {
        //     OPENSSL_PUT_ERROR(PKCS7, ERR_R_BIO_LIB);
        //     goto err;
        // }
        // BIO_set_mem_eof_return(tmpout, 0);
    } else
        tmpout = out;

    /* We now have to 'read' from p7bio to calculate digests etc. */
    const int BUFFERSIZE = 4096;
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
      // TODO [childw] determine whether to support here, likely not.
        // if (!SMIME_text(tmpout, out)) {
        //     OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_SMIME_TEXT_ERROR);
        //     BIO_free(tmpout);
        //     goto err;
        // }
        // BIO_free(tmpout);
    }

    /* Now Verify All Signatures */
    if (!(flags & PKCS7_NOSIGS))
        for (size_t ii = 0; ii < sk_PKCS7_SIGNER_INFO_num(sinfos); ii++) {
            si = sk_PKCS7_SIGNER_INFO_value(sinfos, ii);
            signer = sk_X509_value(signers, ii);
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

OPENSSL_END_ALLOW_DEPRECATED
