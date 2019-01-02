/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 * Copyright 2005 Nokia. All rights reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ssl.h>

/*
 * Note: SSL[_CTX]_set_{options,mode} use |= op on the previous value, they
 * cannot be used to clear bits.
 */

unsigned long SSL_CTX_get_options(const SSL_CTX *ctx)

{
   return (unsigned long)-1;
}


unsigned long SSL_get_options(const SSL *s)

{
   return (unsigned long)-1;
}


unsigned long SSL_CTX_clear_options(SSL_CTX *ctx, unsigned long op)

{
   return (unsigned long)-1;
}


unsigned long SSL_clear_options(SSL *s, unsigned long op)

{
   return (unsigned long)-1;
}


unsigned long SSL_CTX_set_options(SSL_CTX *ctx, unsigned long op)

{
   return (unsigned long)-1;
}


unsigned long SSL_set_options(SSL *s, unsigned long op)

{
   return (unsigned long)-1;
}




void SSL_CTX_set_msg_callback(SSL_CTX *ctx,
                              void (*cb) (int write_p, int version,
                                          int content_type, const void *buf,
                                          size_t len, SSL *ssl, void *arg))

{
}


void SSL_set_msg_callback(SSL *ssl,
                          void (*cb) (int write_p, int version,
                                      int content_type, const void *buf,
                                      size_t len, SSL *ssl, void *arg))

{
}



# ifndef OPENSSL_NO_SRP

/* see tls_srp.c */
__owur int SSL_SRP_CTX_init(SSL *s)

{
}


__owur int SSL_CTX_SRP_CTX_init(SSL_CTX *ctx)

{
}


int SSL_SRP_CTX_free(SSL *ctx)

{
}


int SSL_CTX_SRP_CTX_free(SSL_CTX *ctx)

{
}


__owur int SSL_srp_server_param_with_username(SSL *s, int *ad)

{
}


__owur int SRP_Calc_A_param(SSL *s)

{
}



# endif


LHASH_OF(SSL_SESSION) *SSL_CTX_sessions(SSL_CTX *ctx)

{
}



void SSL_CTX_sess_set_new_cb(SSL_CTX *ctx,
                             int (*new_session_cb) (struct ssl_st *ssl,
                                                    SSL_SESSION *sess))

{
}


int (*SSL_CTX_sess_get_new_cb(SSL_CTX *ctx)) (struct ssl_st *ssl,
                                              SSL_SESSION *sess)

{
}


void SSL_CTX_sess_set_remove_cb(SSL_CTX *ctx,
                                void (*remove_session_cb) (struct ssl_ctx_st
                                                           *ctx,
                                                           SSL_SESSION *sess))

{
}


void (*SSL_CTX_sess_get_remove_cb(SSL_CTX *ctx)) (struct ssl_ctx_st *ctx,
                                                  SSL_SESSION *sess)

{
}


void SSL_CTX_sess_set_get_cb(SSL_CTX *ctx,
                             SSL_SESSION *(*get_session_cb) (struct ssl_st
                                                             *ssl,
                                                             const unsigned char
                                                             *data, int len,
                                                             int *copy))

{
}


SSL_SESSION *(*SSL_CTX_sess_get_get_cb(SSL_CTX *ctx)) (struct ssl_st *ssl,
                                                       const unsigned char *data,
                                                       int len, int *copy)

{
}


void SSL_CTX_set_info_callback(SSL_CTX *ctx,
                               void (*cb) (const SSL *ssl, int type, int val))

{
}


void (*SSL_CTX_get_info_callback(SSL_CTX *ctx)) (const SSL *ssl, int type,
                                                 int val)

{
}


void SSL_CTX_set_client_cert_cb(SSL_CTX *ctx,
                                int (*client_cert_cb) (SSL *ssl, X509 **x509,
                                                       EVP_PKEY **pkey))

{
}


int (*SSL_CTX_get_client_cert_cb(SSL_CTX *ctx)) (SSL *ssl, X509 **x509,
                                                 EVP_PKEY **pkey)

{
}


# ifndef OPENSSL_NO_ENGINE
__owur int SSL_CTX_set_client_cert_engine(SSL_CTX *ctx, ENGINE *e)

{
}


# endif
void SSL_CTX_set_cookie_generate_cb(SSL_CTX *ctx,
                                    int (*app_gen_cookie_cb) (SSL *ssl,
                                                              unsigned char
                                                              *cookie,
                                                              unsigned int
                                                              *cookie_len))

{
}


void SSL_CTX_set_cookie_verify_cb(SSL_CTX *ctx,
                                  int (*app_verify_cookie_cb) (SSL *ssl,
                                                               const unsigned
                                                               char *cookie,
                                                               unsigned int
                                                               cookie_len))

{
}



void SSL_CTX_set_stateless_cookie_generate_cb(
    SSL_CTX *ctx,
    int (*gen_stateless_cookie_cb) (SSL *ssl,
                                    unsigned char *cookie,
                                    size_t *cookie_len))

{
}


void SSL_CTX_set_stateless_cookie_verify_cb(
    SSL_CTX *ctx,
    int (*verify_stateless_cookie_cb) (SSL *ssl,
                                       const unsigned char *cookie,
                                       size_t cookie_len))

{
}


# ifndef OPENSSL_NO_NEXTPROTONEG


void SSL_CTX_set_next_protos_advertised_cb(SSL_CTX *s,
                                           SSL_CTX_npn_advertised_cb_func cb,
                                           void *arg)

{
}


void SSL_CTX_set_next_proto_select_cb(SSL_CTX *s,
                                      SSL_CTX_npn_select_cb_func cb,
                                      void *arg)

{
}



void SSL_get0_next_proto_negotiated(const SSL *s, const unsigned char **data,
                                    unsigned *len)

{
}



__owur int SSL_select_next_proto(unsigned char **out, unsigned char *outlen,
                                 const unsigned char *in, unsigned int inlen,
                                 const unsigned char *client,
                                 unsigned int client_len)

{
}



__owur int SSL_CTX_set_alpn_protos(SSL_CTX *ctx, const unsigned char *protos,
                                   unsigned int protos_len)

{
}


__owur int SSL_set_alpn_protos(SSL *ssl, const unsigned char *protos,
                               unsigned int protos_len)

{
}


void SSL_CTX_set_alpn_select_cb(SSL_CTX *ctx,
                                SSL_CTX_alpn_select_cb_func cb,
                                void *arg)

{
}


void SSL_get0_alpn_selected(const SSL *ssl, const unsigned char **data,
                            unsigned int *len)

{
}



# ifndef OPENSSL_NO_PSK
void SSL_CTX_set_psk_client_callback(SSL_CTX *ctx, SSL_psk_client_cb_func cb)

{
}


void SSL_set_psk_client_callback(SSL *ssl, SSL_psk_client_cb_func cb)

{
}



void SSL_CTX_set_psk_server_callback(SSL_CTX *ctx, SSL_psk_server_cb_func cb)

{
}


void SSL_set_psk_server_callback(SSL *ssl, SSL_psk_server_cb_func cb)

{
}



__owur int SSL_CTX_use_psk_identity_hint(SSL_CTX *ctx, const char *identity_hint)

{
}


__owur int SSL_use_psk_identity_hint(SSL *s, const char *identity_hint)

{
}


const char *SSL_get_psk_identity_hint(const SSL *s)

{
}


const char *SSL_get_psk_identity(const SSL *s)

{
}


# endif

void SSL_set_psk_find_session_callback(SSL *s, SSL_psk_find_session_cb_func cb)

{
}


void SSL_CTX_set_psk_find_session_callback(SSL_CTX *ctx,
                                           SSL_psk_find_session_cb_func cb)

{
}


void SSL_set_psk_use_session_callback(SSL *s, SSL_psk_use_session_cb_func cb)

{
}


void SSL_CTX_set_psk_use_session_callback(SSL_CTX *ctx,
                                          SSL_psk_use_session_cb_func cb)

{
}



/* Register callbacks to handle custom TLS Extensions for client or server. */

__owur int SSL_CTX_has_client_custom_ext(const SSL_CTX *ctx,
                                         unsigned int ext_type)

{
}



__owur int SSL_CTX_add_client_custom_ext(SSL_CTX *ctx,
                                         unsigned int ext_type,
                                         custom_ext_add_cb add_cb,
                                         custom_ext_free_cb free_cb,
                                         void *add_arg,
                                         custom_ext_parse_cb parse_cb,
                                         void *parse_arg)

{
}



__owur int SSL_CTX_add_server_custom_ext(SSL_CTX *ctx,
                                         unsigned int ext_type,
                                         custom_ext_add_cb add_cb,
                                         custom_ext_free_cb free_cb,
                                         void *add_arg,
                                         custom_ext_parse_cb parse_cb,
                                         void *parse_arg)

{
}



__owur int SSL_CTX_add_custom_ext(SSL_CTX *ctx, unsigned int ext_type,
                                  unsigned int context,
                                  SSL_custom_ext_add_cb_ex add_cb,
                                  SSL_custom_ext_free_cb_ex free_cb,
                                  void *add_arg,
                                  SSL_custom_ext_parse_cb_ex parse_cb,
                                  void *parse_arg)

{
}



__owur int SSL_extension_supported(unsigned int ext_type)

{
}



/*
 * SSL_CTX_set_keylog_callback configures a callback to log key material. This
 * is intended for debugging use with tools like Wireshark. The cb function
 * should log line followed by a newline.
 */
void SSL_CTX_set_keylog_callback(SSL_CTX *ctx, SSL_CTX_keylog_cb_func cb)

{
}



/*
 * SSL_CTX_get_keylog_callback returns the callback configured by
 * SSL_CTX_set_keylog_callback.
 */
SSL_CTX_keylog_cb_func SSL_CTX_get_keylog_callback(const SSL_CTX *ctx)

{
}



int SSL_CTX_set_max_early_data(SSL_CTX *ctx, uint32_t max_early_data)

{
}


uint32_t SSL_CTX_get_max_early_data(const SSL_CTX *ctx)

{
}


int SSL_set_max_early_data(SSL *s, uint32_t max_early_data)

{
}


uint32_t SSL_get_max_early_data(const SSL *s)

{
}


int SSL_CTX_set_recv_max_early_data(SSL_CTX *ctx, uint32_t recv_max_early_data)

{
}


uint32_t SSL_CTX_get_recv_max_early_data(const SSL_CTX *ctx)

{
}


int SSL_set_recv_max_early_data(SSL *s, uint32_t recv_max_early_data)

{
}


uint32_t SSL_get_recv_max_early_data(const SSL *s)

{
}



void SSL_set_debug(SSL *s, int debug)

{
    // deprecated
}

int SSL_in_init(const SSL *s)

{
}


int SSL_in_before(const SSL *s)

{
}


int SSL_is_init_finished(const SSL *s)

{
}



/*-
 * Obtain latest Finished message
 *   -- that we sent (SSL_get_finished)
 *   -- that we expected from peer (SSL_get_peer_finished).
 * Returns length (0 == no Finished so far), copies up to 'count' bytes.
 */
size_t SSL_get_finished(const SSL *s, void *buf, size_t count)

{
}


size_t SSL_get_peer_finished(const SSL *s, void *buf, size_t count)

{
}



__owur const BIO_METHOD *BIO_f_ssl(void)

{
}


__owur BIO *BIO_new_ssl(SSL_CTX *ctx, int client)

{
}


__owur BIO *BIO_new_ssl_connect(SSL_CTX *ctx)

{
}


__owur BIO *BIO_new_buffer_ssl_connect(SSL_CTX *ctx)

{
}


__owur int BIO_ssl_copy_session_id(BIO *to, BIO *from)

{
}


void BIO_ssl_shutdown(BIO *ssl_bio)

{
}



__owur int SSL_CTX_set_cipher_list(SSL_CTX *, const char *str)

{
}


__owur SSL_CTX *SSL_CTX_new(const SSL_METHOD *meth)

{
}


int SSL_CTX_up_ref(SSL_CTX *ctx)

{
}


void SSL_CTX_free(SSL_CTX *)

{
}


__owur long SSL_CTX_set_timeout(SSL_CTX *ctx, long t)

{
}


__owur long SSL_CTX_get_timeout(const SSL_CTX *ctx)

{
}


__owur X509_STORE *SSL_CTX_get_cert_store(const SSL_CTX *)

{
}


void SSL_CTX_set_cert_store(SSL_CTX *, X509_STORE *)

{
}


void SSL_CTX_set1_cert_store(SSL_CTX *, X509_STORE *)

{
}


__owur int SSL_want(const SSL *s)

{
}


__owur int SSL_clear(SSL *s)

{
}



void SSL_CTX_flush_sessions(SSL_CTX *ctx, long tm)

{
}



__owur const SSL_CIPHER *SSL_get_current_cipher(const SSL *s)

{
}


__owur const SSL_CIPHER *SSL_get_pending_cipher(const SSL *s)

{
}


__owur int SSL_CIPHER_get_bits(const SSL_CIPHER *c, int *alg_bits)

{
}


__owur const char *SSL_CIPHER_get_version(const SSL_CIPHER *c)

{
}


__owur const char *SSL_CIPHER_get_name(const SSL_CIPHER *c)

{
}


__owur const char *SSL_CIPHER_standard_name(const SSL_CIPHER *c)

{
}


__owur const char *OPENSSL_cipher_name(const char *rfc_name)

{
}


__owur uint32_t SSL_CIPHER_get_id(const SSL_CIPHER *c)

{
}


__owur uint16_t SSL_CIPHER_get_protocol_id(const SSL_CIPHER *c)

{
}


__owur int SSL_CIPHER_get_kx_nid(const SSL_CIPHER *c)

{
}


__owur int SSL_CIPHER_get_auth_nid(const SSL_CIPHER *c)

{
}


__owur const EVP_MD *SSL_CIPHER_get_handshake_digest(const SSL_CIPHER *c)

{
}


__owur int SSL_CIPHER_is_aead(const SSL_CIPHER *c)

{
}



__owur int SSL_get_fd(const SSL *s)

{
}


__owur int SSL_get_rfd(const SSL *s)

{
}


__owur int SSL_get_wfd(const SSL *s)

{
}


__owur const char *SSL_get_cipher_list(const SSL *s, int n)

{
}


__owur char *SSL_get_shared_ciphers(const SSL *s, char *buf, int size)

{
}


__owur int SSL_get_read_ahead(const SSL *s)

{
}


__owur int SSL_pending(const SSL *s)

{
}


__owur int SSL_has_pending(const SSL *s)

{
}


# ifndef OPENSSL_NO_SOCK
__owur int SSL_set_fd(SSL *s, int fd)

{
}


__owur int SSL_set_rfd(SSL *s, int fd)

{
}


__owur int SSL_set_wfd(SSL *s, int fd)

{
}


# endif
void SSL_set0_rbio(SSL *s, BIO *rbio)

{
}


void SSL_set0_wbio(SSL *s, BIO *wbio)

{
}


void SSL_set_bio(SSL *s, BIO *rbio, BIO *wbio)

{
}


__owur BIO *SSL_get_rbio(const SSL *s)

{
}


__owur BIO *SSL_get_wbio(const SSL *s)

{
}


__owur int SSL_set_cipher_list(SSL *s, const char *str)

{
}


__owur int SSL_CTX_set_ciphersuites(SSL_CTX *ctx, const char *str)

{
}


__owur int SSL_set_ciphersuites(SSL *s, const char *str)

{
}


void SSL_set_read_ahead(SSL *s, int yes)

{
}


__owur int SSL_get_verify_mode(const SSL *s)

{
}


__owur int SSL_get_verify_depth(const SSL *s)

{
}


__owur SSL_verify_cb SSL_get_verify_callback(const SSL *s)

{
}


void SSL_set_verify(SSL *s, int mode, SSL_verify_cb callback)

{
}


void SSL_set_verify_depth(SSL *s, int depth)

{
}


void SSL_set_cert_cb(SSL *s, int (*cb) (SSL *ssl, void *arg), void *arg)

{
}


# ifndef OPENSSL_NO_RSA
__owur int SSL_use_RSAPrivateKey(SSL *ssl, RSA *rsa)

{
}


__owur int SSL_use_RSAPrivateKey_ASN1(SSL *ssl, const unsigned char *d,
                                      long len)

{
}


# endif
__owur int SSL_use_PrivateKey(SSL *ssl, EVP_PKEY *pkey)

{
}


__owur int SSL_use_PrivateKey_ASN1(int pk, SSL *ssl, const unsigned char *d,
                                   long len)

{
}


__owur int SSL_use_certificate(SSL *ssl, X509 *x)

{
}


__owur int SSL_use_certificate_ASN1(SSL *ssl, const unsigned char *d, int len)

{
}


__owur int SSL_use_cert_and_key(SSL *ssl, X509 *x509, EVP_PKEY *privatekey,
                                STACK_OF(X509) *chain, int override)

{
}



/* Set serverinfo data for the current active cert. */
__owur int SSL_CTX_use_serverinfo(SSL_CTX *ctx, const unsigned char *serverinfo,
                                  size_t serverinfo_length)

{
}


__owur int SSL_CTX_use_serverinfo_ex(SSL_CTX *ctx, unsigned int version,
                                     const unsigned char *serverinfo,
                                     size_t serverinfo_length)

{
}


__owur int SSL_CTX_use_serverinfo_file(SSL_CTX *ctx, const char *file)

{
}



#ifndef OPENSSL_NO_RSA
__owur int SSL_use_RSAPrivateKey_file(SSL *ssl, const char *file, int type)

{
}


#endif

__owur int SSL_use_PrivateKey_file(SSL *ssl, const char *file, int type)

{
}


__owur int SSL_use_certificate_file(SSL *ssl, const char *file, int type)

{
}



#ifndef OPENSSL_NO_RSA
__owur int SSL_CTX_use_RSAPrivateKey_file(SSL_CTX *ctx, const char *file,
                                          int type)

{
}


#endif
__owur int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file,
                                       int type)

{
}


__owur int SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *file,
                                        int type)

{
}


/* PEM type */
__owur int SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file)

{
}


__owur int SSL_use_certificate_chain_file(SSL *ssl, const char *file)

{
}


__owur STACK_OF(X509_NAME) *SSL_load_client_CA_file(const char *file)

{
}


__owur int SSL_add_file_cert_subjects_to_stack(STACK_OF(X509_NAME) *stackCAs,
                                               const char *file)

{
}


int SSL_add_dir_cert_subjects_to_stack(STACK_OF(X509_NAME) *stackCAs,
                                       const char *dir)

{
}



__owur const char *SSL_state_string(const SSL *s)

{
}


__owur const char *SSL_rstate_string(const SSL *s)

{
}


__owur const char *SSL_state_string_long(const SSL *s)

{
}


__owur const char *SSL_rstate_string_long(const SSL *s)

{
}


__owur long SSL_SESSION_get_time(const SSL_SESSION *s)

{
}


__owur long SSL_SESSION_set_time(SSL_SESSION *s, long t)

{
}


__owur long SSL_SESSION_get_timeout(const SSL_SESSION *s)

{
}


__owur long SSL_SESSION_set_timeout(SSL_SESSION *s, long t)

{
}


__owur int SSL_SESSION_get_protocol_version(const SSL_SESSION *s)

{
}


__owur int SSL_SESSION_set_protocol_version(SSL_SESSION *s, int version)

{
}



__owur const char *SSL_SESSION_get0_hostname(const SSL_SESSION *s)

{
}


__owur int SSL_SESSION_set1_hostname(SSL_SESSION *s, const char *hostname)

{
}


void SSL_SESSION_get0_alpn_selected(const SSL_SESSION *s,
                                    const unsigned char **alpn,
                                    size_t *len)

{
}


__owur int SSL_SESSION_set1_alpn_selected(SSL_SESSION *s,
                                          const unsigned char *alpn,
                                          size_t len)

{
}


__owur const SSL_CIPHER *SSL_SESSION_get0_cipher(const SSL_SESSION *s)

{
}


__owur int SSL_SESSION_set_cipher(SSL_SESSION *s, const SSL_CIPHER *cipher)

{
}


__owur int SSL_SESSION_has_ticket(const SSL_SESSION *s)

{
}


__owur unsigned long SSL_SESSION_get_ticket_lifetime_hint(const SSL_SESSION *s)

{
   return (unsigned long)-1;
}


void SSL_SESSION_get0_ticket(const SSL_SESSION *s, const unsigned char **tick,
                             size_t *len)

{
}


__owur uint32_t SSL_SESSION_get_max_early_data(const SSL_SESSION *s)

{
}


__owur int SSL_SESSION_set_max_early_data(SSL_SESSION *s,
                                          uint32_t max_early_data)

{
}


__owur int SSL_copy_session_id(SSL *to, const SSL *from)

{
}


__owur X509 *SSL_SESSION_get0_peer(SSL_SESSION *s)

{
}


__owur int SSL_SESSION_set1_id_context(SSL_SESSION *s,
                                       const unsigned char *sid_ctx,
                                       unsigned int sid_ctx_len)

{
}


__owur int SSL_SESSION_set1_id(SSL_SESSION *s, const unsigned char *sid,
                               unsigned int sid_len)

{
}


__owur int SSL_SESSION_is_resumable(const SSL_SESSION *s)

{
}



__owur SSL_SESSION *SSL_SESSION_new(void)

{
}


__owur SSL_SESSION *SSL_SESSION_dup(SSL_SESSION *src)

{
}


const unsigned char *SSL_SESSION_get_id(const SSL_SESSION *s,
                                        unsigned int *len)

{
}


const unsigned char *SSL_SESSION_get0_id_context(const SSL_SESSION *s,
                                                 unsigned int *len)

{
}


__owur unsigned int SSL_SESSION_get_compress_id(const SSL_SESSION *s)

{
}


# ifndef OPENSSL_NO_STDIO
int SSL_SESSION_print_fp(FILE *fp, const SSL_SESSION *ses)

{
}


# endif
int SSL_SESSION_print(BIO *fp, const SSL_SESSION *ses)

{
}


int SSL_SESSION_print_keylog(BIO *bp, const SSL_SESSION *x)

{
}


int SSL_SESSION_up_ref(SSL_SESSION *ses)

{
}


void SSL_SESSION_free(SSL_SESSION *ses)

{
}


__owur int i2d_SSL_SESSION(SSL_SESSION *in, unsigned char **pp)

{
}


__owur int SSL_set_session(SSL *to, SSL_SESSION *session)

{
}


int SSL_CTX_add_session(SSL_CTX *ctx, SSL_SESSION *session)

{
}


int SSL_CTX_remove_session(SSL_CTX *ctx, SSL_SESSION *session)

{
}


__owur int SSL_CTX_set_generate_session_id(SSL_CTX *ctx, GEN_SESSION_CB cb)

{
}


__owur int SSL_set_generate_session_id(SSL *s, GEN_SESSION_CB cb)

{
}


__owur int SSL_has_matching_session_id(const SSL *s,
                                       const unsigned char *id,
                                       unsigned int id_len)

{
}


SSL_SESSION *d2i_SSL_SESSION(SSL_SESSION **a, const unsigned char **pp,
                             long length)

{
}



# ifdef HEADER_X509_H
__owur X509 *SSL_get_peer_certificate(const SSL *s)

{
}


# endif

__owur STACK_OF(X509) *SSL_get_peer_cert_chain(const SSL *s)

{
}



__owur int SSL_CTX_get_verify_mode(const SSL_CTX *ctx)

{
}


__owur int SSL_CTX_get_verify_depth(const SSL_CTX *ctx)

{
}


__owur SSL_verify_cb SSL_CTX_get_verify_callback(const SSL_CTX *ctx)

{
}


void SSL_CTX_set_verify(SSL_CTX *ctx, int mode, SSL_verify_cb callback)

{
}


void SSL_CTX_set_verify_depth(SSL_CTX *ctx, int depth)

{
}


void SSL_CTX_set_cert_verify_callback(SSL_CTX *ctx,
                                      int (*cb) (X509_STORE_CTX *, void *),
                                      void *arg)

{
}


void SSL_CTX_set_cert_cb(SSL_CTX *c, int (*cb) (SSL *ssl, void *arg),
                         void *arg)

{
}


# ifndef OPENSSL_NO_RSA
__owur int SSL_CTX_use_RSAPrivateKey(SSL_CTX *ctx, RSA *rsa)

{
}


__owur int SSL_CTX_use_RSAPrivateKey_ASN1(SSL_CTX *ctx, const unsigned char *d,
                                          long len)

{
}


# endif
__owur int SSL_CTX_use_PrivateKey(SSL_CTX *ctx, EVP_PKEY *pkey)

{
}


__owur int SSL_CTX_use_PrivateKey_ASN1(int pk, SSL_CTX *ctx,
                                       const unsigned char *d, long len)

{
}


__owur int SSL_CTX_use_certificate(SSL_CTX *ctx, X509 *x)

{
}


__owur int SSL_CTX_use_certificate_ASN1(SSL_CTX *ctx, int len,
                                        const unsigned char *d)

{
}


__owur int SSL_CTX_use_cert_and_key(SSL_CTX *ctx, X509 *x509, EVP_PKEY *privatekey,
                                    STACK_OF(X509) *chain, int override)

{
}



void SSL_CTX_set_default_passwd_cb(SSL_CTX *ctx, pem_password_cb *cb)

{
}


void SSL_CTX_set_default_passwd_cb_userdata(SSL_CTX *ctx, void *u)

{
}


pem_password_cb *SSL_CTX_get_default_passwd_cb(SSL_CTX *ctx)

{
}


void *SSL_CTX_get_default_passwd_cb_userdata(SSL_CTX *ctx)

{
}


void SSL_set_default_passwd_cb(SSL *s, pem_password_cb *cb)

{
}


void SSL_set_default_passwd_cb_userdata(SSL *s, void *u)

{
}


pem_password_cb *SSL_get_default_passwd_cb(SSL *s)

{
}


void *SSL_get_default_passwd_cb_userdata(SSL *s)

{
}



__owur int SSL_CTX_check_private_key(const SSL_CTX *ctx)

{
}


__owur int SSL_check_private_key(const SSL *ctx)

{
}



__owur int SSL_CTX_set_session_id_context(SSL_CTX *ctx,
                                          const unsigned char *sid_ctx,
                                          unsigned int sid_ctx_len)

{
}



SSL *SSL_new(SSL_CTX *ctx)

{
}


int SSL_up_ref(SSL *s)

{
}


int SSL_is_dtls(const SSL *s)

{
}


__owur int SSL_set_session_id_context(SSL *ssl, const unsigned char *sid_ctx,
                                      unsigned int sid_ctx_len)

{
}



__owur int SSL_CTX_set_purpose(SSL_CTX *ctx, int purpose)

{
}


__owur int SSL_set_purpose(SSL *ssl, int purpose)

{
}


__owur int SSL_CTX_set_trust(SSL_CTX *ctx, int trust)

{
}


__owur int SSL_set_trust(SSL *ssl, int trust)

{
}



__owur int SSL_set1_host(SSL *s, const char *hostname)

{
}


__owur int SSL_add1_host(SSL *s, const char *hostname)

{
}


__owur const char *SSL_get0_peername(SSL *s)

{
}


void SSL_set_hostflags(SSL *s, unsigned int flags)

{
}



__owur int SSL_CTX_dane_enable(SSL_CTX *ctx)

{
}


__owur int SSL_CTX_dane_mtype_set(SSL_CTX *ctx, const EVP_MD *md,
                                  uint8_t mtype, uint8_t ord)

{
}


__owur int SSL_dane_enable(SSL *s, const char *basedomain)

{
}


__owur int SSL_dane_tlsa_add(SSL *s, uint8_t usage, uint8_t selector,
                             uint8_t mtype, unsigned const char *data, size_t dlen)

{
}


__owur int SSL_get0_dane_authority(SSL *s, X509 **mcert, EVP_PKEY **mspki)

{
}


__owur int SSL_get0_dane_tlsa(SSL *s, uint8_t *usage, uint8_t *selector,
                              uint8_t *mtype, unsigned const char **data,
                              size_t *dlen)

{
}


/*
 * Bridge opacity barrier between libcrypt and libssl, also needed to support
 * offline testing in test/danetest.c
 */
SSL_DANE *SSL_get0_dane(SSL *ssl)

{
}


/*
 * DANE flags
 */
unsigned long SSL_CTX_dane_set_flags(SSL_CTX *ctx, unsigned long flags)

{
   return (unsigned long)-1;
}


unsigned long SSL_CTX_dane_clear_flags(SSL_CTX *ctx, unsigned long flags)

{
   return (unsigned long)-1;
}


unsigned long SSL_dane_set_flags(SSL *ssl, unsigned long flags)

{
   return (unsigned long)-1;
}


unsigned long SSL_dane_clear_flags(SSL *ssl, unsigned long flags)

{
   return (unsigned long)-1;
}



__owur int SSL_CTX_set1_param(SSL_CTX *ctx, X509_VERIFY_PARAM *vpm)

{
   return (unsigned long)-1;
}


__owur int SSL_set1_param(SSL *ssl, X509_VERIFY_PARAM *vpm)

{
}



__owur X509_VERIFY_PARAM *SSL_CTX_get0_param(SSL_CTX *ctx)

{
}


__owur X509_VERIFY_PARAM *SSL_get0_param(SSL *ssl)

{
}



# ifndef OPENSSL_NO_SRP
int SSL_CTX_set_srp_username(SSL_CTX *ctx, char *name)

{
}


int SSL_CTX_set_srp_password(SSL_CTX *ctx, char *password)

{
}


int SSL_CTX_set_srp_strength(SSL_CTX *ctx, int strength)

{
}


int SSL_CTX_set_srp_client_pwd_callback(SSL_CTX *ctx,
                                        char *(*cb) (SSL *, void *))

{
}


int SSL_CTX_set_srp_verify_param_callback(SSL_CTX *ctx,
                                          int (*cb) (SSL *, void *))

{
}


int SSL_CTX_set_srp_username_callback(SSL_CTX *ctx,
                                      int (*cb) (SSL *, int *, void *))

{
}


int SSL_CTX_set_srp_cb_arg(SSL_CTX *ctx, void *arg)

{
}



int SSL_set_srp_server_param(SSL *s, const BIGNUM *N, const BIGNUM *g,
                             BIGNUM *sa, BIGNUM *v, char *info)

{
}


int SSL_set_srp_server_param_pw(SSL *s, const char *user, const char *pass,
                                const char *grp)

{
}



__owur BIGNUM *SSL_get_srp_g(SSL *s)

{
}


__owur BIGNUM *SSL_get_srp_N(SSL *s)

{
}



__owur char *SSL_get_srp_username(SSL *s)

{
}


__owur char *SSL_get_srp_userinfo(SSL *s)

{
}


# endif

/*
 * ClientHello callback and helpers.
 */

void SSL_CTX_set_client_hello_cb(SSL_CTX *c, SSL_client_hello_cb_fn cb,
                                 void *arg)

{
}


int SSL_client_hello_isv2(SSL *s)

{
}


unsigned int SSL_client_hello_get0_legacy_version(SSL *s)

{
}


size_t SSL_client_hello_get0_random(SSL *s, const unsigned char **out)

{
}


size_t SSL_client_hello_get0_session_id(SSL *s, const unsigned char **out)

{
}


size_t SSL_client_hello_get0_ciphers(SSL *s, const unsigned char **out)

{
}


size_t SSL_client_hello_get0_compression_methods(SSL *s,
                                                 const unsigned char **out)

{
}


int SSL_client_hello_get1_extensions_present(SSL *s, int **out, size_t *outlen)

{
}


int SSL_client_hello_get0_ext(SSL *s, unsigned int type,
                              const unsigned char **out, size_t *outlen)

{
}



void SSL_certs_clear(SSL *s)

{
}


void SSL_free(SSL *ssl)

{
}


# ifdef OSSL_ASYNC_FD
/*
 * Windows application developer has to include windows.h to use these.
 */
__owur int SSL_waiting_for_async(SSL *s)

{
}


__owur int SSL_get_all_async_fds(SSL *s, OSSL_ASYNC_FD *fds, size_t *numfds)

{
}


__owur int SSL_get_changed_async_fds(SSL *s, OSSL_ASYNC_FD *addfd,
                                     size_t *numaddfds, OSSL_ASYNC_FD *delfd,
                                     size_t *numdelfds)

{
}


# endif
__owur int SSL_accept(SSL *ssl)

{
}


__owur int SSL_stateless(SSL *s)

{
}


__owur int SSL_connect(SSL *ssl)

{
}


__owur int SSL_read(SSL *ssl, void *buf, int num)

{
}


__owur int SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes)

{
}



__owur int SSL_read_early_data(SSL *s, void *buf, size_t num,
                               size_t *readbytes)

{
}


__owur int SSL_peek(SSL *ssl, void *buf, int num)

{
}


__owur int SSL_peek_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes)

{
}


__owur int SSL_write(SSL *ssl, const void *buf, int num)

{
}


__owur int SSL_write_ex(SSL *s, const void *buf, size_t num, size_t *written)

{
}


__owur int SSL_write_early_data(SSL *s, const void *buf, size_t num,
                                size_t *written)

{
}


long SSL_ctrl(SSL *ssl, int cmd, long larg, void *parg)

{
}


long SSL_callback_ctrl(SSL *, int, void (*)(void))

{
}


long SSL_CTX_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg)

{
}


long SSL_CTX_callback_ctrl(SSL_CTX *, int, void (*)(void))

{
}



__owur int SSL_get_early_data_status(const SSL *s)

{
}



__owur int SSL_get_error(const SSL *s, int ret_code)

{
}


__owur const char *SSL_get_version(const SSL *s)

{
}



/* This sets the 'default' SSL version that SSL_new() will create */
__owur int SSL_CTX_set_ssl_version(SSL_CTX *ctx, const SSL_METHOD *meth)

{
}



# ifndef OPENSSL_NO_SSL3_METHOD
DEPRECATEDIN_1_1_0(__owur const SSL_METHOD *SSLv3_method(void)) /* SSLv3 */
DEPRECATEDIN_1_1_0(__owur const SSL_METHOD *SSLv3_server_method(void))
DEPRECATEDIN_1_1_0(__owur const SSL_METHOD *SSLv3_client_method(void))
# endif

/* Negotiate highest available SSL/TLS version */
__owur const SSL_METHOD *TLS_method(void)

{
}


__owur const SSL_METHOD *TLS_server_method(void)

{
}


__owur const SSL_METHOD *TLS_client_method(void)

{
}



# ifndef OPENSSL_NO_TLS1_METHOD
DEPRECATEDIN_1_1_0(__owur const SSL_METHOD *TLSv1_method(void)) /* TLSv1.0 */
DEPRECATEDIN_1_1_0(__owur const SSL_METHOD *TLSv1_server_method(void))
DEPRECATEDIN_1_1_0(__owur const SSL_METHOD *TLSv1_client_method(void))
# endif

# ifndef OPENSSL_NO_TLS1_1_METHOD
DEPRECATEDIN_1_1_0(__owur const SSL_METHOD *TLSv1_1_method(void)) /* TLSv1.1 */
DEPRECATEDIN_1_1_0(__owur const SSL_METHOD *TLSv1_1_server_method(void))
DEPRECATEDIN_1_1_0(__owur const SSL_METHOD *TLSv1_1_client_method(void))
# endif

# ifndef OPENSSL_NO_TLS1_2_METHOD
DEPRECATEDIN_1_1_0(__owur const SSL_METHOD *TLSv1_2_method(void)) /* TLSv1.2 */
DEPRECATEDIN_1_1_0(__owur const SSL_METHOD *TLSv1_2_server_method(void))
DEPRECATEDIN_1_1_0(__owur const SSL_METHOD *TLSv1_2_client_method(void))
# endif

# ifndef OPENSSL_NO_DTLS1_METHOD
DEPRECATEDIN_1_1_0(__owur const SSL_METHOD *DTLSv1_method(void)) /* DTLSv1.0 */
DEPRECATEDIN_1_1_0(__owur const SSL_METHOD *DTLSv1_server_method(void))
DEPRECATEDIN_1_1_0(__owur const SSL_METHOD *DTLSv1_client_method(void))
# endif

# ifndef OPENSSL_NO_DTLS1_2_METHOD
/* DTLSv1.2 */
DEPRECATEDIN_1_1_0(__owur const SSL_METHOD *DTLSv1_2_method(void))
DEPRECATEDIN_1_1_0(__owur const SSL_METHOD *DTLSv1_2_server_method(void))
DEPRECATEDIN_1_1_0(__owur const SSL_METHOD *DTLSv1_2_client_method(void))
# endif

__owur const SSL_METHOD *DTLS_method(void)

{
}

 /* DTLS 1.0 and 1.2 */
__owur const SSL_METHOD *DTLS_server_method(void)

{
}

 /* DTLS 1.0 and 1.2 */
__owur const SSL_METHOD *DTLS_client_method(void)

{
}

 /* DTLS 1.0 and 1.2 */

__owur size_t DTLS_get_data_mtu(const SSL *s)

{
}



__owur STACK_OF(SSL_CIPHER) *SSL_get_ciphers(const SSL *s)

{
}


__owur STACK_OF(SSL_CIPHER) *SSL_CTX_get_ciphers(const SSL_CTX *ctx)

{
}


__owur STACK_OF(SSL_CIPHER) *SSL_get_client_ciphers(const SSL *s)

{
}


__owur STACK_OF(SSL_CIPHER) *SSL_get1_supported_ciphers(SSL *s)

{
}



__owur int SSL_do_handshake(SSL *s)

{
}


int SSL_key_update(SSL *s, int updatetype)

{
}


int SSL_get_key_update_type(SSL *s)

{
}


int SSL_renegotiate(SSL *s)

{
}


int SSL_renegotiate_abbreviated(SSL *s)

{
}


__owur int SSL_renegotiate_pending(SSL *s)

{
}


int SSL_shutdown(SSL *s)

{
}


__owur int SSL_verify_client_post_handshake(SSL *s)

{
}


void SSL_CTX_set_post_handshake_auth(SSL_CTX *ctx, int val)

{
}


void SSL_set_post_handshake_auth(SSL *s, int val)

{
}



__owur const SSL_METHOD *SSL_CTX_get_ssl_method(SSL_CTX *ctx)

{
}


__owur const SSL_METHOD *SSL_get_ssl_method(SSL *s)

{
}


__owur int SSL_set_ssl_method(SSL *s, const SSL_METHOD *method)

{
}


__owur const char *SSL_alert_type_string_long(int value)

{
}


__owur const char *SSL_alert_type_string(int value)

{
}


__owur const char *SSL_alert_desc_string_long(int value)

{
}


__owur const char *SSL_alert_desc_string(int value)

{
}



void SSL_set0_CA_list(SSL *s, STACK_OF(X509_NAME) *name_list)

{
}


void SSL_CTX_set0_CA_list(SSL_CTX *ctx, STACK_OF(X509_NAME) *name_list)

{
}


__owur const STACK_OF(X509_NAME) *SSL_get0_CA_list(const SSL *s)

{
}


__owur const STACK_OF(X509_NAME) *SSL_CTX_get0_CA_list(const SSL_CTX *ctx)

{
}


__owur int SSL_add1_to_CA_list(SSL *ssl, const X509 *x)

{
}


__owur int SSL_CTX_add1_to_CA_list(SSL_CTX *ctx, const X509 *x)

{
}


__owur const STACK_OF(X509_NAME) *SSL_get0_peer_CA_list(const SSL *s)

{
}



void SSL_set_client_CA_list(SSL *s, STACK_OF(X509_NAME) *name_list)

{
}


void SSL_CTX_set_client_CA_list(SSL_CTX *ctx, STACK_OF(X509_NAME) *name_list)

{
}


__owur STACK_OF(X509_NAME) *SSL_get_client_CA_list(const SSL *s)

{
}


__owur STACK_OF(X509_NAME) *SSL_CTX_get_client_CA_list(const SSL_CTX *s)

{
}


__owur int SSL_add_client_CA(SSL *ssl, X509 *x)

{
}


__owur int SSL_CTX_add_client_CA(SSL_CTX *ctx, X509 *x)

{
}



void SSL_set_connect_state(SSL *s)

{
}


void SSL_set_accept_state(SSL *s)

{
}



__owur long SSL_get_default_timeout(const SSL *s)

{
}



__owur char *SSL_CIPHER_description(const SSL_CIPHER *, char *buf, int size)

{
}


__owur STACK_OF(X509_NAME) *SSL_dup_CA_list(const STACK_OF(X509_NAME) *sk)

{
}



__owur SSL *SSL_dup(SSL *ssl)

{
}



__owur X509 *SSL_get_certificate(const SSL *ssl)

{
}


/*
 * EVP_PKEY
 */
struct evp_pkey_st *SSL_get_privatekey(const SSL *ssl)

{
}



__owur X509 *SSL_CTX_get0_certificate(const SSL_CTX *ctx)

{
}


__owur EVP_PKEY *SSL_CTX_get0_privatekey(const SSL_CTX *ctx)

{
}



void SSL_CTX_set_quiet_shutdown(SSL_CTX *ctx, int mode)

{
}


__owur int SSL_CTX_get_quiet_shutdown(const SSL_CTX *ctx)

{
}


void SSL_set_quiet_shutdown(SSL *ssl, int mode)

{
}


__owur int SSL_get_quiet_shutdown(const SSL *ssl)

{
}


void SSL_set_shutdown(SSL *ssl, int mode)

{
}


__owur int SSL_get_shutdown(const SSL *ssl)

{
}


__owur int SSL_version(const SSL *ssl)

{
}


__owur int SSL_client_version(const SSL *s)

{
}


__owur int SSL_CTX_set_default_verify_paths(SSL_CTX *ctx)

{
}


__owur int SSL_CTX_set_default_verify_dir(SSL_CTX *ctx)

{
}


__owur int SSL_CTX_set_default_verify_file(SSL_CTX *ctx)

{
}


__owur int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile,
                                         const char *CApath)

{
}


# define SSL_get0_session SSL_get_session/* just peek at pointer */
__owur SSL_SESSION *SSL_get_session(const SSL *ssl)

{
}


__owur SSL_SESSION *SSL_get1_session(SSL *ssl)

{
}

 /* obtain a reference count */
__owur SSL_CTX *SSL_get_SSL_CTX(const SSL *ssl)

{
}


SSL_CTX *SSL_set_SSL_CTX(SSL *ssl, SSL_CTX *ctx)

{
}


void SSL_set_info_callback(SSL *ssl,
                           void (*cb) (const SSL *ssl, int type, int val))

{
}


void (*SSL_get_info_callback(const SSL *ssl)) (const SSL *ssl, int type,
                                               int val)

{
}


__owur OSSL_HANDSHAKE_STATE SSL_get_state(const SSL *ssl)

{
}



void SSL_set_verify_result(SSL *ssl, long v)

{
}


__owur long SSL_get_verify_result(const SSL *ssl)

{
}


__owur STACK_OF(X509) *SSL_get0_verified_chain(const SSL *s)

{
}



__owur size_t SSL_get_client_random(const SSL *ssl, unsigned char *out,
                                    size_t outlen)

{
}


__owur size_t SSL_get_server_random(const SSL *ssl, unsigned char *out,
                                    size_t outlen)

{
}


__owur size_t SSL_SESSION_get_master_key(const SSL_SESSION *sess,
                                         unsigned char *out, size_t outlen)

{
}


__owur int SSL_SESSION_set1_master_key(SSL_SESSION *sess,
                                       const unsigned char *in, size_t len)

{
}


uint8_t SSL_SESSION_get_max_fragment_length(const SSL_SESSION *sess)

{
}



__owur int SSL_set_ex_data(SSL *ssl, int idx, void *data)

{
}


void *SSL_get_ex_data(const SSL *ssl, int idx)

{
}


__owur int SSL_SESSION_set_ex_data(SSL_SESSION *ss, int idx, void *data)

{
}


void *SSL_SESSION_get_ex_data(const SSL_SESSION *ss, int idx)

{
}


__owur int SSL_CTX_set_ex_data(SSL_CTX *ssl, int idx, void *data)

{
}


void *SSL_CTX_get_ex_data(const SSL_CTX *ssl, int idx)

{
}



__owur int SSL_get_ex_data_X509_STORE_CTX_idx(void)

{
}


void SSL_CTX_set_default_read_buffer_len(SSL_CTX *ctx, size_t len)

{
}


void SSL_set_default_read_buffer_len(SSL *s, size_t len)

{
}



# ifndef OPENSSL_NO_DH
/* NB: the |keylength| is only applicable when is_export is true */
void SSL_CTX_set_tmp_dh_callback(SSL_CTX *ctx,
                                 DH *(*dh) (SSL *ssl, int is_export,
                                            int keylength))

{
}


void SSL_set_tmp_dh_callback(SSL *ssl,
                             DH *(*dh) (SSL *ssl, int is_export,
                                        int keylength))

{
}


# endif

__owur const COMP_METHOD *SSL_get_current_compression(SSL *s)

{
}


__owur const COMP_METHOD *SSL_get_current_expansion(SSL *s)

{
}


__owur const char *SSL_COMP_get_name(const COMP_METHOD *comp)

{
}


__owur const char *SSL_COMP_get0_name(const SSL_COMP *comp)

{
}


__owur int SSL_COMP_get_id(const SSL_COMP *comp)

{
}


STACK_OF(SSL_COMP) *SSL_COMP_get_compression_methods(void)

{
}


__owur STACK_OF(SSL_COMP) *SSL_COMP_set0_compression_methods(STACK_OF(SSL_COMP)
                                                             *meths)

{
}


__owur int SSL_COMP_add_compression_method(int id, COMP_METHOD *cm)

{
}



const SSL_CIPHER *SSL_CIPHER_find(SSL *ssl, const unsigned char *ptr)

{
}


int SSL_CIPHER_get_cipher_nid(const SSL_CIPHER *c)

{
}


int SSL_CIPHER_get_digest_nid(const SSL_CIPHER *c)

{
}


int SSL_bytes_to_cipher_list(SSL *s, const unsigned char *bytes, size_t len,
                             int isv2format, STACK_OF(SSL_CIPHER) **sk,
                             STACK_OF(SSL_CIPHER) **scsvs)

{
}



/* TLS extensions functions */
__owur int SSL_set_session_ticket_ext(SSL *s, void *ext_data, int ext_len)

{
}



__owur int SSL_set_session_ticket_ext_cb(SSL *s,
                                         tls_session_ticket_ext_cb_fn cb,
                                         void *arg)

{
}



/* Pre-shared secret session resumption functions */
__owur int SSL_set_session_secret_cb(SSL *s,
                                     tls_session_secret_cb_fn session_secret_cb,
                                     void *arg)

{
}



void SSL_CTX_set_not_resumable_session_callback(SSL_CTX *ctx,
                                                int (*cb) (SSL *ssl,
                                                           int
                                                           is_forward_secure))

{
}



void SSL_set_not_resumable_session_callback(SSL *ssl,
                                            int (*cb) (SSL *ssl,
                                                       int is_forward_secure))

{
}



void SSL_CTX_set_record_padding_callback(SSL_CTX *ctx,
                                         size_t (*cb) (SSL *ssl, int type,
                                                       size_t len, void *arg))

{
}


void SSL_CTX_set_record_padding_callback_arg(SSL_CTX *ctx, void *arg)

{
}


void *SSL_CTX_get_record_padding_callback_arg(SSL_CTX *ctx)

{
}


int SSL_CTX_set_block_padding(SSL_CTX *ctx, size_t block_size)

{
}



void SSL_set_record_padding_callback(SSL *ssl,
                                    size_t (*cb) (SSL *ssl, int type,
                                                  size_t len, void *arg))

{
}


void SSL_set_record_padding_callback_arg(SSL *ssl, void *arg)

{
}


void *SSL_get_record_padding_callback_arg(SSL *ssl)

{
}


int SSL_set_block_padding(SSL *ssl, size_t block_size)

{
}



int SSL_set_num_tickets(SSL *s, size_t num_tickets)

{
}


size_t SSL_get_num_tickets(SSL *s)

{
}


int SSL_CTX_set_num_tickets(SSL_CTX *ctx, size_t num_tickets)

{
}


size_t SSL_CTX_get_num_tickets(SSL_CTX *ctx)

{
}



# if OPENSSL_API_COMPAT < 0x10100000L
#  define SSL_cache_hit(s) SSL_session_reused(s)
# endif

__owur int SSL_session_reused(SSL *s)

{
}


__owur int SSL_is_server(const SSL *s)

{
}



__owur __owur SSL_CONF_CTX *SSL_CONF_CTX_new(void)

{
}


int SSL_CONF_CTX_finish(SSL_CONF_CTX *cctx)

{
}


void SSL_CONF_CTX_free(SSL_CONF_CTX *cctx)

{
}


unsigned int SSL_CONF_CTX_set_flags(SSL_CONF_CTX *cctx, unsigned int flags)

{
}


__owur unsigned int SSL_CONF_CTX_clear_flags(SSL_CONF_CTX *cctx,
                                             unsigned int flags)

{
}


__owur int SSL_CONF_CTX_set1_prefix(SSL_CONF_CTX *cctx, const char *pre)

{
}



void SSL_CONF_CTX_set_ssl(SSL_CONF_CTX *cctx, SSL *ssl)

{
}


void SSL_CONF_CTX_set_ssl_ctx(SSL_CONF_CTX *cctx, SSL_CTX *ctx)

{
}



__owur int SSL_CONF_cmd(SSL_CONF_CTX *cctx, const char *cmd, const char *value)

{
}


__owur int SSL_CONF_cmd_argv(SSL_CONF_CTX *cctx, int *pargc, char ***pargv)

{
}


__owur int SSL_CONF_cmd_value_type(SSL_CONF_CTX *cctx, const char *cmd)

{
}



void SSL_add_ssl_module(void)

{
}


int SSL_config(SSL *s, const char *name)

{
}


int SSL_CTX_config(SSL_CTX *ctx, const char *name)

{
}



# ifndef OPENSSL_NO_SSL_TRACE
void SSL_trace(int write_p, int version, int content_type,
               const void *buf, size_t len, SSL *ssl, void *arg)

{
}


# endif

# ifndef OPENSSL_NO_SOCK
int DTLSv1_listen(SSL *s, BIO_ADDR *client)

{
}


# endif

# ifndef OPENSSL_NO_CT

/*
 * Sets a |callback| that is invoked upon receipt of ServerHelloDone to validate
 * the received SCTs.
 * If the callback returns a non-positive result, the connection is terminated.
 * Call this function before beginning a handshake.
 * If a NULL |callback| is provided, SCT validation is disabled.
 * |arg| is arbitrary userdata that will be passed to the callback whenever it
 * is invoked. Ownership of |arg| remains with the caller.
 *
 * NOTE: A side-effect of setting a CT callback is that an OCSP stapled response
 *       will be requested.
 */
int SSL_set_ct_validation_callback(SSL *s, ssl_ct_validation_cb callback,
                                   void *arg)

{
}


int SSL_CTX_set_ct_validation_callback(SSL_CTX *ctx,
                                       ssl_ct_validation_cb callback,
        ((void) SSL_CTX_set_validation_callback((ctx), NULL, NULL))
/*
 * Enable CT by setting up a callback that implements one of the built-in
 * validation variants.  The SSL_CT_VALIDATION_PERMISSIVE variant always
 * continues the handshake, the application can make appropriate decisions at
 * handshake completion.  The SSL_CT_VALIDATION_STRICT variant requires at
 * least one valid SCT, or else handshake termination will be requested.  The
 * handshake may continue anyway if SSL_VERIFY_NONE is in effect.
 */
int SSL_enable_ct(SSL *s, int validation_mode)

{
}


int SSL_CTX_enable_ct(SSL_CTX *ctx, int validation_mode)

{
}



/*
 * Report whether a non-NULL callback is enabled.
 */
int SSL_ct_is_enabled(const SSL *s)

{
}


int SSL_CTX_ct_is_enabled(const SSL_CTX *ctx)

{
}



/* Gets the SCTs received from a connection */
const STACK_OF(SCT) *SSL_get0_peer_scts(SSL *s)

{
}



/*
 * Loads the CT log list from the default location.
 * If a CTLOG_STORE has previously been set using SSL_CTX_set_ctlog_store,
 * the log information loaded from this file will be appended to the
 * CTLOG_STORE.
 * Returns 1 on success, 0 otherwise.
 */
int SSL_CTX_set_default_ctlog_list_file(SSL_CTX *ctx)

{
}



/*
 * Loads the CT log list from the specified file path.
 * If a CTLOG_STORE has previously been set using SSL_CTX_set_ctlog_store,
 * the log information loaded from this file will be appended to the
 * CTLOG_STORE.
 * Returns 1 on success, 0 otherwise.
 */
int SSL_CTX_set_ctlog_list_file(SSL_CTX *ctx, const char *path)

{
}



/*
 * Sets the CT log list used by all SSL connections created from this SSL_CTX.
 * Ownership of the CTLOG_STORE is transferred to the SSL_CTX.
 */
void SSL_CTX_set0_ctlog_store(SSL_CTX *ctx, CTLOG_STORE *logs)

{
}



/*
 * Gets the CT log list used by all SSL connections created from this SSL_CTX.
 * This will be NULL unless one of the following functions has been called:
 * - SSL_CTX_set_default_ctlog_list_file
 * - SSL_CTX_set_ctlog_list_file
 * - SSL_CTX_set_ctlog_store
 */
const CTLOG_STORE *SSL_CTX_get0_ctlog_store(const SSL_CTX *ctx)

{
}



# endif /* OPENSSL_NO_CT */

void SSL_set_security_level(SSL *s, int level)

{
}


__owur int SSL_get_security_level(const SSL *s)

{
}


void SSL_set_security_callback(SSL *s,
                               int (*cb) (const SSL *s, const SSL_CTX *ctx,
                                          int op, int bits, int nid,
                                          void *other, void *ex))

{
}


int (*SSL_get_security_callback(const SSL *s)) (const SSL *s,
                                                const SSL_CTX *ctx, int op,
                                                int bits, int nid, void *other,
                                                void *ex)

{
}


void SSL_set0_security_ex_data(SSL *s, void *ex)

{
}


__owur void *SSL_get0_security_ex_data(const SSL *s)

{
}



void SSL_CTX_set_security_level(SSL_CTX *ctx, int level)

{
}


__owur int SSL_CTX_get_security_level(const SSL_CTX *ctx)

{
}


void SSL_CTX_set_security_callback(SSL_CTX *ctx,
                                   int (*cb) (const SSL *s, const SSL_CTX *ctx,
                                              int op, int bits, int nid,
                                              void *other, void *ex))

{
}


int (*SSL_CTX_get_security_callback(const SSL_CTX *ctx)) (const SSL *s,
                                                          const SSL_CTX *ctx,
                                                          int op, int bits,
                                                          int nid,
                                                          void *other,
                                                          void *ex)

{
}


void SSL_CTX_set0_security_ex_data(SSL_CTX *ctx, void *ex)

{
}


__owur void *SSL_CTX_get0_security_ex_data(const SSL_CTX *ctx)

{
}



int OPENSSL_init_ssl(uint64_t opts, const OPENSSL_INIT_SETTINGS *settings)

{
}



# ifndef OPENSSL_NO_UNIT_TEST
__owur const struct openssl_ssl_test_functions *SSL_test_functions(void)

{
}


# endif

__owur int SSL_free_buffers(SSL *ssl)

{
}


__owur int SSL_alloc_buffers(SSL *ssl)

{
}



int SSL_CTX_set_session_ticket_cb(SSL_CTX *ctx,
                                  SSL_CTX_generate_session_ticket_fn gen_cb,
                                  SSL_CTX_decrypt_session_ticket_fn dec_cb,
                                  void *arg)

{
}


int SSL_SESSION_set1_ticket_appdata(SSL_SESSION *ss, const void *data, size_t len)

{
}


int SSL_SESSION_get0_ticket_appdata(SSL_SESSION *ss, void **data, size_t *len)

{
}



void DTLS_set_timer_cb(SSL *s, DTLS_timer_cb cb)

{
}


void SSL_CTX_set_allow_early_data_cb(SSL_CTX *ctx,
                                     SSL_allow_early_data_cb_fn cb,
                                     void *arg)

{
}


void SSL_set_allow_early_data_cb(SSL *s,
                                 SSL_allow_early_data_cb_fn cb,
                                 void *arg)

{
}



