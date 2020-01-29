/*
 * ngtcp2
 *
 * Copyright (c) 2020 ngtcp2 contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <assert.h>

#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

//TODO remove this: DEBUG
#include <stdio.h>

static const gnutls_mac_algorithm_t mac_sha256 = GNUTLS_MAC_SHA256;
static const gnutls_mac_algorithm_t aes_128_gcm = GNUTLS_CIPHER_AES_128_GCM;
/* GnuTLS does not support ECB mode. Workaround by using CBC with zero IV. */
static const gnutls_mac_algorithm_t aes_128_cbc = GNUTLS_CIPHER_AES_128_CBC;

/*
 * Set the algorithms used for initial data encryption
 * */
ngtcp2_crypto_ctx *ngtcp2_crypto_ctx_initial(ngtcp2_crypto_ctx *ctx) {
  ctx->aead.native_handle = (void *)&aes_128_gcm;
  ctx->md.native_handle = (void *)&mac_sha256;
  ctx->hp.native_handle = (void *)&aes_128_cbc;
  return ctx;
}

/*
 * TLS will call this callback whenever new secrets are negotiated
 * */
static int ngtcp2_crypto_handshake_secret_cb(gnutls_session_t session,
                                             gnutls_handshake_secret_type_t type,
                                             const gnutls_datum_t *secret) {
  int rv = 0;

  FILE *debug;

  debug = fopen("/tmp/hanshake_secret.log", "a");
  if (debug == NULL) {
    fprintf(stderr, "Could not open debug log\n");
  }

  //TODO generate secrets and store somewhere
  switch(type) {
    case GNUTLS_SECRET_CLIENT_RANDOM:
      fprintf(debug, "SECRET_CLIENT_RANDOM\n");
      break;
    case GNUTLS_SECRET_CLIENT_EARLY_TRAFFIC_SECRET:
      fprintf(debug, "SECRET_CLIENT_EARLY_TRAFFIC_SECRET\n");
      break;
    case GNUTLS_SECRET_CLIENT_HANDSHAKE_TRAFFIC_SECRET:
      fprintf(debug, "SECRET_CLIENT_HANDSHAKE_TRAFFIC_SECRET\n");
      break;
    case GNUTLS_SECRET_SERVER_HANDSHAKE_TRAFFIC_SECRET:
      fprintf(debug, "SECRET_SERVER_HANDSHAKE_TRAFFIC_SECRET\n");
      break;
    case GNUTLS_SECRET_CLIENT_TRAFFIC_SECRET:
      fprintf(debug, "SECRET_CLIENT_TRAFFIC_SECRET\n");
      break;
    case GNUTLS_SECRET_SERVER_TRAFFIC_SECRET:
      fprintf(debug, "SECRET_SERVER_TRAFFIC_SECRET\n");
      break;
    case GNUTLS_SECRET_EARLY_EXPORTER_SECRET:
      fprintf(debug, "SECRET_EARLY_EXPORTER_SECRET\n");
      break;
    case GNUTLS_SECRET_EXPORTER_SECRET:
      fprintf(debug, "SECRET_EXPORTER_SECRET\n");
      break;
    default:
      fprintf(debug, "ERROR\n");
      //ERROR
      break;
  }

  fclose(debug);
  return rv;
}

/*
 * TLS will call this callback to write data to QUIC
 * */
static int ngtcp2_crypto_record_write_cb(gnutls_session_t session,
                                         gnutls_content_type_t type,
                                         const gnutls_datum_t *data) {
  int rv;

  FILE *debug;

  debug = fopen("/tmp/record_write.log", "a");
  if (debug == NULL) {
    fprintf(stderr, "Could not open debug log\n");
  }

  /* check type and decide what to do */
  switch(type) {
    case GNUTLS_RECORD_CHANGE_CIPHER_SPEC:
      fprintf(debug, "GNUTLS_RECORD_CHANGE_CIPHER_SPEC\n");
      break;
    case GNUTLS_RECORD_ALERT:
      fprintf(debug, "GNUTLS_RECORD_ALERT\n");
      break;
    case GNUTLS_RECORD_HANDSHAKE:
      fprintf(debug, "GNUTLS_RECORD_HANDSHAKE\n");
      break;
    case GNUTLS_RECORD_APPLICATION_DATA:
      fprintf(debug, "GNUTLS_RECORD_APPLICATION_DATA\n");
      break;
    default:
      //ERROR
      fprintf(debug, "ERROR\n");
      break;
  }

  fclose(debug);

  return rv;
}

//TODO Is this necessary?
void ngtcp2_crypto_install_record_write_callback(gnutls_session_t session) {
  gnutls_record_set_write_function(session, ngtcp2_crypto_record_write_cb);
}

//TODO Is this necessary?
void ngtcp2_crypto_install_handshake_secret_callback(gnutls_session_t session) {
  gnutls_handshake_set_secret_function(session, ngtcp2_crypto_handshake_secret_cb);
}

ngtcp2_crypto_ctx *ngtcp2_crypto_ctx_tls(ngtcp2_crypto_ctx *ctx,
    void *tls_native_handle) {

  //TODO Set the algorithms according to negotiated parameters
  // Necessary? Shouldn't this be done by the callback?

  return ctx;
}

//TODO maybe this is not the hmac len, but only the hash len
size_t ngtcp2_crypto_md_hashlen(const ngtcp2_crypto_md *md) {
  gnutls_mac_algorithm_t algo;

  // TODO Is this check necessary?
  if (md == NULL || md->native_handle == NULL) {
    //ERROR
    return 0;
  }

  algo = *((gnutls_mac_algorithm_t *)md->native_handle);

  return gnutls_hmac_get_len(algo);
}

size_t ngtcp2_crypto_aead_keylen(const ngtcp2_crypto_aead *aead) {
  gnutls_cipher_algorithm_t algo;

  // TODO Is this check necessary?
  if (aead == NULL || aead->native_handle == NULL) {
    //ERROR
    return 0;
  }

  algo = *((gnutls_cipher_algorithm_t *)aead->native_handle);

  return gnutls_cipher_get_key_size(algo);
}

size_t ngtcp2_crypto_aead_noncelen(const ngtcp2_crypto_aead *aead) {
  gnutls_cipher_algorithm_t algo;

  // TODO Is this check necessary?
  if (aead == NULL || aead->native_handle == NULL) {
    //ERROR
    return 0;
  }

  algo = *((gnutls_cipher_algorithm_t *)aead->native_handle);

  return gnutls_cipher_get_iv_size(algo);
}

size_t ngtcp2_crypto_aead_taglen(const ngtcp2_crypto_aead *aead) {
  gnutls_cipher_algorithm_t algo;

  // TODO Is this check necessary?
  if (aead == NULL || aead->native_handle == NULL) {
    //ERROR
    return 0;
  }

  algo = *((gnutls_cipher_algorithm_t *)aead->native_handle);

  return gnutls_cipher_get_tag_size(algo);
}

int ngtcp2_crypto_hkdf_extract(uint8_t *dest, const ngtcp2_crypto_md *md,
                               const uint8_t *secret, size_t secretlen,
                               const uint8_t *salt, size_t saltlen) {
  gnutls_mac_algorithm_t mac;
  gnutls_datum_t key_datum;
  gnutls_datum_t salt_datum;
  int rv = 0;

  // TODO Is this check necessary?
  /* Check input */
  if (dest == NULL || md == NULL || secret == NULL || salt == NULL) {
    return -1;
  }

  if (md->native_handle) {
    mac = *((gnutls_mac_algorithm_t *)md->native_handle);
  }

  key_datum.data = (void *)secret;
  key_datum.size = secretlen;

  salt_datum.data = (void *)salt;
  salt_datum.size = saltlen;

  rv = gnutls_hkdf_extract(mac, &key_datum, &salt_datum, dest);
  if (rv < 0) {
    //ERROR
    return rv;
  }

  return rv;
}

int ngtcp2_crypto_hkdf_expand(uint8_t *dest, size_t destlen,
                              const ngtcp2_crypto_md *md, const uint8_t *secret,
                              size_t secretlen, const uint8_t *info,
                              size_t infolen) {
  gnutls_mac_algorithm_t mac;
  gnutls_datum_t key_datum;
  gnutls_datum_t info_datum;

  int rv = 0;

  // TODO Is this check necessary?
  /* Check input */
  if (dest == NULL || md == NULL || secret == NULL || info == NULL) {
    return -1;
  }

  if (md->native_handle) {
    mac = *((gnutls_mac_algorithm_t *)md->native_handle);
  }

  key_datum.data = (void *)secret;
  key_datum.size = secretlen;

  info_datum.data = (void *)info;
  info_datum.size = infolen;

  rv = gnutls_hkdf_expand(mac, &key_datum, &info_datum, dest, destlen);
  if (rv < 0) {
    //ERROR
    return rv;
  }

  return rv;
}

int ngtcp2_crypto_encrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                          const uint8_t *plaintext, size_t plaintextlen,
                          const uint8_t *key, const uint8_t *nonce,
                          size_t noncelen, const uint8_t *ad, size_t adlen) {
  int rv = 0;
  gnutls_aead_cipher_hd_t handle;
  gnutls_cipher_algorithm_t cipher;
  gnutls_datum_t key_datum;

  size_t tag_size;
  size_t dest_len;

  // TODO Is this check necessary?
  if (dest == NULL || aead == NULL || plaintext == NULL || key == NULL ||
      nonce == NULL || ad == NULL) {
    //ERROR
    return -1;
  }

  if (aead->native_handle) {
    cipher = *((gnutls_cipher_algorithm_t *)aead->native_handle);
  } else {
    //ERROR
    return -1;
  }

  // Initialize key datum
  key_datum.data = (char *)key;
  key_datum.size = gnutls_cipher_get_key_size(cipher);
  tag_size = gnutls_cipher_get_tag_size(cipher);

  rv = gnutls_aead_cipher_init(&handle, cipher, &key_datum);
  if (rv < 0) {
    //ERROR
    return rv;
  }

  rv = gnutls_aead_cipher_encrypt(handle, nonce, noncelen, ad, adlen, tag_size,
      plaintext, plaintextlen, dest, &dest_len);
  if (rv < 0) {
    //ERROR
    return rv;
  }

  gnutls_aead_cipher_deinit(handle);

  return rv;
}

int ngtcp2_crypto_decrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                          const uint8_t *ciphertext, size_t ciphertextlen,
                          const uint8_t *key, const uint8_t *nonce,
                          size_t noncelen, const uint8_t *ad, size_t adlen) {
  int rv = 0;
  gnutls_aead_cipher_hd_t handle;
  gnutls_cipher_algorithm_t cipher;
  gnutls_datum_t key_datum;

  size_t tag_size;
  size_t dest_len;

  // TODO Is this check necessary?
  if (dest == NULL || aead == NULL || ciphertext == NULL || key == NULL ||
      nonce == NULL || ad == NULL) {
    //ERROR
    return -1;
  }

  if (aead->native_handle) {
    cipher = *((gnutls_cipher_algorithm_t *)aead->native_handle);
  } else {
    //ERROR
    return -1;
  }

  // Initialize key datum
  key_datum.data = (char *)key;
  key_datum.size = gnutls_cipher_get_key_size(cipher);
  tag_size = gnutls_cipher_get_tag_size(cipher);

  rv = gnutls_aead_cipher_init(&handle, cipher, &key_datum);
  if (rv < 0) {
    //ERROR
    return rv;
  }

  rv = gnutls_aead_cipher_decrypt(handle, nonce, noncelen, ad, adlen, tag_size,
      ciphertext, ciphertextlen, dest, &dest_len);
  if (rv < 0) {
    //ERROR
    return rv;
  }

  gnutls_aead_cipher_deinit(handle);

  return rv;
}

int ngtcp2_crypto_hp_mask(uint8_t *dest, const ngtcp2_crypto_cipher *hp,
                          const uint8_t *hp_key, const uint8_t *sample) {
  int rv = 0;

  gnutls_cipher_hd_t handle;
  gnutls_cipher_algorithm_t cipher;
  gnutls_datum_t key;
  gnutls_datum_t iv;
  gnutls_datum_t input;

  size_t dest_len;

  static uint8_t ZEROES[32] = {0};

  // TODO Is this check necessary?
  if (dest == NULL || hp == NULL || hp_key == NULL || sample == NULL) {
    //ERROR
    return -1;
  }

  if (hp->native_handle) {
    cipher = *((gnutls_cipher_algorithm_t *)hp->native_handle);
  } else {
    //ERROR
    return -1;
  }

  switch(cipher) {
    case GNUTLS_CIPHER_AES_128_CBC:
      /* In this case, the mask should be generated as:
       *
       * mask = AES_128_ECB(hp_key, sample)
       *
       * */
      iv.data = ZEROES;
      iv.size = 16;

      key.data = (char *)hp_key;
      key.size = 16;

      input.data = (char *)sample;
      input.size = 16;

      break;
    case GNUTLS_CIPHER_AES_256_CBC:
      /* In this case, the mask should be generated as:
       *
       * mask = AES_256_ECB(hp_key, sample)
       *
       * */
      iv.data = ZEROES;
      iv.size = 32;

      key.data = (char *)hp_key;
      key.size = 32;

      input.data = (char *)sample;
      input.size = 16;

      break;
    case GNUTLS_CIPHER_CHACHA20_POLY1305:
      /* In this case, the mask should be generated as:
       *
       * counter = sample[0..3]
       * nonce = sample[4..15]
       * mask = ChaCha20(hp_key, counter, nonce, {0, 0, 0, 0, 0})
       *
       * */

      key.data = (char *)hp_key;
      key.size = 32;

      iv.data = (char *)sample;
      iv.size = 16;

      input.data = ZEROES;
      input.size = 5;
      break;
    default:
      //ERROR
      return -1;
  }

  rv = gnutls_cipher_init(&handle, cipher, &key, &iv);
  if (rv < 0) {
    //ERROR
    return rv;
  }

  rv = gnutls_cipher_encrypt2(handle, input.data, input.size, dest, dest_len);
  if (rv < 0) {
    //ERROR
    return rv;
  }

  gnutls_cipher_deinit(handle);

  return rv;
}

int ngtcp2_crypto_read_write_crypto_data(ngtcp2_conn *conn, void *tls,
                                         ngtcp2_crypto_level crypto_level,
                                         const uint8_t *data, size_t datalen) {
  gnutls_session_t session;
  gnutls_content_type_t type;
  int rv = 0;

  session = (gnutls_session_t) tls;

  //TODO Check here if it was the right encryption level
  //TODO Is there a mapping from crypto->level to handshake?
  //TODO Can be anything different from HANDSHAKE ?
  switch (crypto_level) {
    case NGTCP2_CRYPTO_LEVEL_EARLY:
    case NGTCP2_CRYPTO_LEVEL_INITIAL:
    case NGTCP2_CRYPTO_LEVEL_HANDSHAKE:
      type = GNUTLS_RECORD_HANDSHAKE;
      break;
    case NGTCP2_CRYPTO_LEVEL_APP:
      type = GNUTLS_RECORD_APPLICATION_DATA;
      break;
    default:
      //ERROR
      return -1;
      break;
  }

  rv = gnutls_record_push_data(session, type, data, datalen);
  if (rv < 0) {
    fprintf(stderr, "Failed to push data\n");
    return rv;
  }

  /* Handshake */
  rv = gnutls_handshake(session);
  if (gnutls_error_is_fatal(rv)) {
    fprintf(stderr, "Fatal error received from TLS: %s", gnutls_strerror(rv));
    return rv;
  }

  /* TODO: Do we need to process post handshake messages? */

  return 0;
}

int ngtcp2_crypto_set_remote_transport_params(ngtcp2_conn *conn, void *tls,
                                              ngtcp2_crypto_side side) {
  gnutls_session_t session;
  int rv = 0;

  session = (gnutls_session_t) tls;

  /* Needed? The callback should get this */

  return rv;
}
