// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <ctype.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/safecrt.h>
#include <openenclave/internal/asn1.h>
#include <openenclave/internal/cert.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/pem.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/utils.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include "crl.h"
#include "ec.h"
#include "init.h"
#include "rsa.h"

/*
**==============================================================================
**
** Local definitions:
**
**==============================================================================
*/

/* Randomly generated magic number */
#define OE_CERT_MAGIC 0xbc8e184285de4d2a

static void _set_err(oe_verify_cert_error_t* error, const char* str)
{
    if (error)
    {
        error->buf[0] = '\0';
        oe_strncat_s(
            error->buf, sizeof(error->buf), str, sizeof(error->buf) - 1);
    }
}

typedef struct _cert
{
    uint64_t magic;
    X509* x509;
} Cert;

static void _cert_init(Cert* impl, X509* x509)
{
    if (impl)
    {
        impl->magic = OE_CERT_MAGIC;
        impl->x509 = x509;
    }
}

static bool _cert_is_valid(const Cert* impl)
{
    return impl && (impl->magic == OE_CERT_MAGIC) && impl->x509;
}

static void _cert_clear(Cert* impl)
{
    if (impl)
    {
        impl->magic = 0;
        impl->x509 = NULL;
    }
}

/* Randomly generated magic number */
#define OE_CERT_CHAIN_MAGIC 0xa5ddf70fb28f4480

typedef struct _cert_chain
{
    uint64_t magic;
    STACK_OF(X509) * sk;
} CertChain;

static void _cert_chain_init(CertChain* impl, STACK_OF(X509) * sk)
{
    if (impl)
    {
        impl->magic = OE_CERT_CHAIN_MAGIC;
        impl->sk = sk;
    }
}

static bool _cert_chain_is_valid(const CertChain* impl)
{
    return impl && (impl->magic == OE_CERT_CHAIN_MAGIC) && impl->sk;
}

static void _cert_chain_clear(CertChain* impl)
{
    if (impl)
    {
        impl->magic = 0;
        impl->sk = NULL;
    }
}

static STACK_OF(X509) * _read_cert_chain(const char* pem)
{
    STACK_OF(X509)* result = NULL;
    STACK_OF(X509)* sk = NULL;
    BIO* bio = NULL;
    X509* x509 = NULL;

    // Check parameters:
    if (!pem)
        goto done;

    // Create empty X509 stack:
    if (!(sk = sk_X509_new_null()))
        goto done;

    while (*pem)
    {
        const char* end;

        /* The PEM certificate must start with this */
        if (strncmp(
                pem, OE_PEM_BEGIN_CERTIFICATE, OE_PEM_BEGIN_CERTIFICATE_LEN) !=
            0)
            goto done;

        /* Find the end of this PEM certificate */
        {
            if (!(end = strstr(pem, OE_PEM_END_CERTIFICATE)))
                goto done;

            end += OE_PEM_END_CERTIFICATE_LEN;
        }

        /* Skip trailing spaces */
        while (isspace(*end))
            end++;

        /* Create a BIO for this certificate */
        if (!(bio = BIO_new_mem_buf(pem, (int)(end - pem))))
            goto done;

        /* Read BIO into X509 object */
        if (!(x509 = PEM_read_bio_X509(bio, NULL, 0, NULL)))
            goto done;

        // Push certificate onto stack:
        {
            if (!sk_X509_push(sk, x509))
                goto done;

            x509 = NULL;
        }

        // Release the bio:
        BIO_free(bio);
        bio = NULL;

        pem = end;
    }

    result = sk;
    sk = NULL;

done:

    if (bio)
        BIO_free(bio);

    if (sk)
        sk_X509_pop_free(sk, X509_free);

    return result;
}

/* Clone the certificate to clear any verification state */
static X509* _clone_x509(X509* x509)
{
    X509* ret = NULL;
    BIO* out = NULL;
    BIO* in = NULL;
    BUF_MEM* mem;

    if (!x509)
        goto done;

    if (!(out = BIO_new(BIO_s_mem())))
        goto done;

    if (!PEM_write_bio_X509(out, x509))
        goto done;

    if (!BIO_get_mem_ptr(out, &mem))
        goto done;

    if (mem->length > OE_INT_MAX)
        goto done;

    if (!(in = BIO_new_mem_buf(mem->data, (int)mem->length)))
        goto done;

    ret = PEM_read_bio_X509(in, NULL, 0, NULL);

done:

    if (out)
        BIO_free(out);

    if (in)
        BIO_free(in);

    return ret;
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
/* Needed because some versions of OpenSSL do not support X509_up_ref() */
static int X509_up_ref(X509* x509)
{
    if (!x509)
        return 0;

    CRYPTO_add(&x509->references, 1, CRYPTO_LOCK_X509);
    return 1;
}

/* Needed because some versions of OpenSSL do not support X509_CRL_up_ref() */
static int X509_CRL_up_ref(X509_CRL* x509_crl)
{
    if (!x509_crl)
        return 0;

    CRYPTO_add(&x509_crl->references, 1, CRYPTO_LOCK_X509_CRL);
    return 1;
}

static const STACK_OF(X509_EXTENSION) * X509_get0_extensions(const X509* x)
{
    if (!x->cert_info)
    {
        return NULL;
    }
    return x->cert_info->extensions;
}

#endif

static oe_result_t _cert_chain_get_length(const CertChain* impl, int* length)
{
    oe_result_t result = OE_UNEXPECTED;
    int num;

    *length = 0;

    if ((num = sk_X509_num(impl->sk)) <= 0)
        OE_RAISE(OE_FAILURE);

    *length = num;

    result = OE_OK;

done:
    return result;
}

static STACK_OF(X509) * _clone_chain(STACK_OF(X509) * chain)
{
    STACK_OF(X509)* sk = NULL;
    int n = sk_X509_num(chain);

    if (!(sk = sk_X509_new(NULL)))
        return NULL;

    for (int i = 0; i < n; i++)
    {
        X509* x509;

        if (!(x509 = sk_X509_value(chain, (int)i)))
            return NULL;

        if (!(x509 = _clone_x509(x509)))
            return NULL;

        if (!sk_X509_push(sk, x509))
            return NULL;
    }

    return sk;
}

static oe_result_t _verify_cert(X509* cert_, STACK_OF(X509) * chain_)
{
    oe_result_t result = OE_UNEXPECTED;
    X509_STORE_CTX* ctx = NULL;
    X509* cert = NULL;
    STACK_OF(X509)* chain = NULL;

    /* Clone the certificate to clear any cached verification state */
    if (!(cert = _clone_x509(cert_)))
        OE_RAISE(OE_FAILURE);

    /* Clone the chain to clear any cached verification state */
    if (!(chain = _clone_chain(chain_)))
        OE_RAISE(OE_FAILURE);

    /* Create a context for verification */
    if (!(ctx = X509_STORE_CTX_new()))
        OE_RAISE(OE_FAILURE);

    /* Initialize the context that will be used to verify the certificate */
    if (!X509_STORE_CTX_init(ctx, NULL, NULL, NULL))
        OE_RAISE(OE_FAILURE);

    /* Inject the certificate into the verification context */
    X509_STORE_CTX_set_cert(ctx, cert);

    /* Set the CA chain into the verification context */
    X509_STORE_CTX_trusted_stack(ctx, chain);

    /* Finally verify the certificate */
    if (!X509_verify_cert(ctx))
        OE_RAISE(OE_FAILURE);

    result = OE_OK;

done:

    if (cert)
        X509_free(cert);

    if (chain)
        sk_X509_pop_free(chain, X509_free);

    if (ctx)
        X509_STORE_CTX_free(ctx);

    return result;
}

// Find the last certificate in the chain and then verify that it's a
// self-signed certificate (a root certificate).
static X509* _find_root_cert(STACK_OF(X509) * chain)
{
    int n = sk_X509_num(chain);
    X509* x509;

    /* Get the last certificate in the list */
    if (!(x509 = sk_X509_value(chain, n - 1)))
        return NULL;

    /* If the last certificate is not self-signed, then fail */
    {
        const X509_NAME* subject = X509_get_subject_name(x509);
        const X509_NAME* issuer = X509_get_issuer_name(x509);

        if (!subject || !issuer || X509_NAME_cmp(subject, issuer) != 0)
            return NULL;
    }

    /* Return the root certificate */
    return x509;
}

/* Verify each certificate in the chain against its predecessor. */
static oe_result_t _verify_whole_chain(STACK_OF(X509) * chain)
{
    oe_result_t result = OE_UNEXPECTED;
    X509* root;
    STACK_OF(X509)* subchain = NULL;
    int n;

    if (!chain)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Get the root certificate */
    if (!(root = _find_root_cert(chain)))
        OE_RAISE(OE_FAILURE);

    /* Get number of certificates in the chain */
    n = sk_X509_num(chain);

    /* If chain is empty */
    if (n < 1)
        OE_RAISE(OE_FAILURE);

    /* Create a subchain that grows to include the whole chain */
    if (!(subchain = sk_X509_new_null()))
        OE_RAISE(OE_OUT_OF_MEMORY);

    /* Add the root certificate to the subchain */
    {
        X509_up_ref(root);

        if (!sk_X509_push(subchain, root))
            OE_RAISE(OE_FAILURE);
    }

    /* Verify each certificate in the chain against the subchain */
    for (int i = sk_X509_num(chain) - 1; i >= 0; i--)
    {
        X509* cert = sk_X509_value(chain, i);

        if (!cert)
            OE_RAISE(OE_FAILURE);

        OE_CHECK(_verify_cert(cert, subchain));

        /* Add this certificate to the subchain */
        {
            X509_up_ref(cert);

            if (!sk_X509_push(subchain, cert))
                OE_RAISE(OE_FAILURE);
        }
    }

    result = OE_OK;

done:

    if (subchain)
        sk_X509_pop_free(subchain, X509_free);

    return result;
}

/*
**==============================================================================
**
** Public functions
**
**==============================================================================
*/

oe_result_t oe_cert_read_pem(
    oe_cert_t* cert,
    const void* pem_data,
    size_t pem_size)
{
    oe_result_t result = OE_UNEXPECTED;
    Cert* impl = (Cert*)cert;
    BIO* bio = NULL;
    X509* x509 = NULL;

    /* Zero-initialize the implementation */
    if (impl)
        impl->magic = 0;

    /* Check parameters */
    if (!pem_data || !pem_size || pem_size > OE_INT_MAX || !cert)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Must have pem_size-1 non-zero characters followed by zero-terminator */
    if (strnlen((const char*)pem_data, pem_size) != pem_size - 1)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Initialize OpenSSL (if not already initialized) */
    oe_initialize_openssl();

    /* Create a BIO object for reading the PEM data */
    if (!(bio = BIO_new_mem_buf(pem_data, (int)pem_size)))
        OE_RAISE(OE_FAILURE);

    /* Convert the PEM BIO into a certificate object */
    if (!(x509 = PEM_read_bio_X509(bio, NULL, 0, NULL)))
        OE_RAISE(OE_FAILURE);

    _cert_init(impl, x509);
    x509 = NULL;

    result = OE_OK;

done:

    if (bio)
        BIO_free(bio);

    if (x509)
        X509_free(x509);

    return result;
}

oe_result_t oe_cert_free(oe_cert_t* cert)
{
    oe_result_t result = OE_UNEXPECTED;
    Cert* impl = (Cert*)cert;

    /* Check parameters */
    if (!_cert_is_valid(impl))
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Free the certificate */
    X509_free(impl->x509);
    _cert_clear(impl);

    result = OE_OK;

done:
    return result;
}

/**
 * Compare issue dates (not before dates) of two certs.
 * Returns
 *      0 if c1 and c2 were issued at the same time
 *      1 if c1 was issued before c2
 *     -1 if c1 was issued after c2
 */
static int _cert_issue_date_compare(
    const X509* const* c1,
    const X509* const* c2)
{
    ASN1_TIME* issue_date_c1 = X509_get_notBefore(*c1);
    ASN1_TIME* issue_date_c2 = X509_get_notBefore(*c2);

    int pday = 0;
    int psec = 0;
    // Get days and seconds elapsed after issue of c1 till issue of c2.
    ASN1_TIME_diff(&pday, &psec, issue_date_c1, issue_date_c2);

    // Use days elapsed first.
    if (pday != 0)
        return pday;
    return psec;
}

/**
 * Reorder the cert chain to be leaf->intermeditate->root.
 * This order simplifies cert validation.
 * The preferred order is also the reverse chronological order of issue dates.
 */
static void _sort_certs_by_issue_date(STACK_OF(X509) * chain)
{
    sk_X509_set_cmp_func(chain, _cert_issue_date_compare);
    sk_X509_sort(chain);
}

oe_result_t oe_cert_chain_read_pem(
    oe_cert_chain_t* chain,
    const void* pem_data,
    size_t pem_size)
{
    oe_result_t result = OE_UNEXPECTED;
    CertChain* impl = (CertChain*)chain;
    STACK_OF(X509)* sk = NULL;

    /* Zero-initialize the implementation */
    if (impl)
        memset(impl, 0, sizeof(CertChain));

    /* Check parameters */
    if (!pem_data || !pem_size || !chain)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Must have pem_size-1 non-zero characters followed by zero-terminator */
    if (strnlen((const char*)pem_data, pem_size) != pem_size - 1)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Initialize OpenSSL (if not already initialized) */
    oe_initialize_openssl();

    /* Read the certificate chain into memory */
    if (!(sk = _read_cert_chain((const char*)pem_data)))
        OE_RAISE(OE_FAILURE);

    /* Reorder certs in the chain to preferred order */
    _sort_certs_by_issue_date(sk);

    /* Verify the whole certificate chain */
    OE_CHECK(_verify_whole_chain(sk));

    _cert_chain_init(impl, sk);

    result = OE_OK;

done:

    return result;
}

oe_result_t oe_cert_chain_free(oe_cert_chain_t* chain)
{
    oe_result_t result = OE_UNEXPECTED;
    CertChain* impl = (CertChain*)chain;

    /* Check the parameter */
    if (_cert_chain_is_valid(impl))
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Release the stack of certificates */
    sk_X509_pop_free(impl->sk, X509_free);

    /* Clear the implementation */
    _cert_chain_clear(impl);

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_cert_verify(
    oe_cert_t* cert,
    oe_cert_chain_t* chain,
    const oe_crl_t* const* crls,
    size_t num_crls,
    oe_verify_cert_error_t* error)
{
    oe_result_t result = OE_UNEXPECTED;
    Cert* cert_impl = (Cert*)cert;
    CertChain* chain_impl = (CertChain*)chain;
    X509_STORE_CTX* ctx = NULL;
    X509_STORE* store = NULL;
    X509* x509 = NULL;

    /* Initialize error to NULL for now */
    if (error)
        *error->buf = '\0';

    /* Check for invalid cert parameter */
    if (!_cert_is_valid(cert_impl))
    {
        _set_err(error, "invalid cert parameter");
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    /* Check for invalid chain parameter */
    if (!_cert_chain_is_valid(chain_impl))
    {
        _set_err(error, "invalid chain parameter");
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    /* We must make a copy of the certificate, else previous successful
     * verifications cause subsequent bad verifications to succeed. It is
     * likely that some state is stored in the certificate upon successful
     * verification. We can clear this by making a copy.
     */
    if (!(x509 = _clone_x509(cert_impl->x509)))
    {
        _set_err(error, "invalid X509 certificate");
        OE_RAISE(OE_FAILURE);
    }

    /* Initialize OpenSSL (if not already initialized) */
    oe_initialize_openssl();

    /* Create a context for verification */
    if (!(ctx = X509_STORE_CTX_new()))
    {
        _set_err(error, "failed to allocate X509 context");
        OE_RAISE(OE_FAILURE);
    }

    /* Create a store for the verification */
    if (!(store = X509_STORE_new()))
    {
        _set_err(error, "failed to allocate X509 store");
        OE_RAISE(OE_FAILURE);
    }

    /* Initialize the context that will be used to verify the certificate */
    if (!X509_STORE_CTX_init(ctx, store, NULL, NULL))
    {
        _set_err(error, "failed to initialize X509 context");
        OE_RAISE(OE_FAILURE);
    }

    /* Set the certificate into the verification context */
    X509_STORE_CTX_set_cert(ctx, x509);

    /* Set the CA chain into the verification context */
    X509_STORE_CTX_trusted_stack(ctx, chain_impl->sk);

    /* Set the CRLs if any */
    if (crls && num_crls)
    {
        X509_VERIFY_PARAM* verify_param;

        for (size_t i = 0; i < num_crls; i++)
        {
            crl_t* crl_impl = (crl_t*)crls[i];

            X509_CRL_up_ref(crl_impl->crl);

            if (!X509_STORE_add_crl(store, crl_impl->crl))
                OE_RAISE(OE_FAILURE);
        }

        /* Get the verify parameter (must not be null) */
        if (!(verify_param = X509_STORE_CTX_get0_param(ctx)))
            OE_RAISE(OE_FAILURE);

        X509_VERIFY_PARAM_set_flags(verify_param, X509_V_FLAG_CRL_CHECK);
        X509_VERIFY_PARAM_set_flags(verify_param, X509_V_FLAG_CRL_CHECK_ALL);
    }

    /* Finally verify the certificate */
    if (!X509_verify_cert(ctx))
    {
        int errorno;
        if (error)
            _set_err(
                error,
                X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));

        errorno = X509_STORE_CTX_get_error(ctx);
        OE_RAISE_MSG(
            (X509_V_ERR_CRL_HAS_EXPIRED == errorno) ? OE_VERIFY_CRL_EXPIRED
                                                    : OE_VERIFY_FAILED,
            "X509_verify_cert failed!\n"
            " error: (%d) %s\n",
            errorno,
            X509_verify_cert_error_string(errorno));
    }

    result = OE_OK;

done:

    if (ctx)
        X509_STORE_CTX_free(ctx);

    if (store)
        X509_STORE_free(store);

    if (x509)
        X509_free(x509);

    return result;
}

oe_result_t oe_cert_get_rsa_public_key(
    const oe_cert_t* cert,
    oe_rsa_public_key_t* public_key)
{
    oe_result_t result = OE_UNEXPECTED;
    const Cert* impl = (const Cert*)cert;
    EVP_PKEY* pkey = NULL;
    RSA* rsa = NULL;

    /* Clear public key for all error pathways */
    if (public_key)
        oe_secure_zero_fill(public_key, sizeof(oe_rsa_public_key_t));

    /* Reject invalid parameters */
    if (!_cert_is_valid(impl) || !public_key)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Get public key (increments reference count) */
    if (!(pkey = X509_get_pubkey(impl->x509)))
        OE_RAISE(OE_FAILURE);

    /* Get RSA public key (increments reference count) */
    if (!(rsa = EVP_PKEY_get1_RSA(pkey)))
        OE_RAISE(OE_PUBLIC_KEY_NOT_FOUND);

    /* Initialize the RSA public key */
    oe_rsa_public_key_init(public_key, pkey);
    pkey = NULL;

    result = OE_OK;

done:

    if (pkey)
    {
        /* Decrement reference count (incremented above) */
        EVP_PKEY_free(pkey);
    }

    return result;
}

oe_result_t oe_cert_get_ec_public_key(
    const oe_cert_t* cert,
    oe_ec_public_key_t* public_key)
{
    oe_result_t result = OE_UNEXPECTED;
    const Cert* impl = (const Cert*)cert;
    EVP_PKEY* pkey = NULL;

    /* Clear public key for all error pathways */
    if (public_key)
        oe_secure_zero_fill(public_key, sizeof(oe_ec_public_key_t));

    /* Reject invalid parameters */
    if (!_cert_is_valid(impl) || !public_key)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Get public key (increments reference count) */
    if (!(pkey = X509_get_pubkey(impl->x509)))
        OE_RAISE(OE_FAILURE);

    /* If this is not an EC key */
    {
        EC_KEY* ec;

        if (!(ec = EVP_PKEY_get1_EC_KEY(pkey)))
            OE_RAISE(OE_FAILURE);

        EC_KEY_free(ec);
    }

    /* Initialize the EC public key */
    oe_ec_public_key_init(public_key, pkey);
    pkey = NULL;

    result = OE_OK;

done:

    if (pkey)
    {
        /* Decrement reference count (incremented above) */
        EVP_PKEY_free(pkey);
    }

    return result;
}

oe_result_t oe_cert_chain_get_length(
    const oe_cert_chain_t* chain,
    size_t* length)
{
    oe_result_t result = OE_UNEXPECTED;
    const CertChain* impl = (const CertChain*)chain;

    /* Clear the length (for failed return case) */
    if (length)
        *length = 0;

    /* Reject invalid parameters */
    if (!_cert_chain_is_valid(impl) || !length)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Get the number of certificates in the chain */
    {
        int n;
        OE_CHECK(_cert_chain_get_length(impl, &n));
        *length = (size_t)n;
    }

    result = OE_OK;

done:

    return result;
}

oe_result_t oe_cert_chain_get_cert(
    const oe_cert_chain_t* chain,
    size_t index,
    oe_cert_t* cert)
{
    oe_result_t result = OE_UNEXPECTED;
    const CertChain* impl = (const CertChain*)chain;
    size_t length;
    X509* x509 = NULL;

    /* Clear the output certificate for all error pathways */
    if (cert)
        memset(cert, 0, sizeof(oe_cert_t));

    /* Reject invalid parameters */
    if (!_cert_chain_is_valid(impl) || !cert)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Get the length of the certificate chain */
    {
        int n;
        OE_CHECK(_cert_chain_get_length(impl, &n));
        length = (size_t)n;
    }

    /* Check for out of bounds */
    if (index >= length)
        OE_RAISE(OE_OUT_OF_BOUNDS);

    /* Check for overflow when converting to int */
    if (index >= OE_INT_MAX)
        OE_RAISE(OE_INTEGER_OVERFLOW);

    /* Get the certificate with the given index */
    if (!(x509 = sk_X509_value(impl->sk, (int)index)))
        OE_RAISE(OE_FAILURE);

    /* Increment the reference count and initialize the output certificate */
    if (!X509_up_ref(x509))
        OE_RAISE(OE_FAILURE);
    _cert_init((Cert*)cert, x509);

    result = OE_OK;

done:

    return result;
}

oe_result_t oe_cert_chain_get_root_cert(
    const oe_cert_chain_t* chain,
    oe_cert_t* cert)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t length;

    OE_CHECK(oe_cert_chain_get_length(chain, &length));
    OE_CHECK(oe_cert_chain_get_cert(chain, length - 1, cert));
    result = OE_OK;

done:
    return result;
}

oe_result_t oe_cert_chain_get_leaf_cert(
    const oe_cert_chain_t* chain,
    oe_cert_t* cert)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t length;

    OE_CHECK(oe_cert_chain_get_length(chain, &length));
    OE_CHECK(oe_cert_chain_get_cert(chain, 0, cert));
    result = OE_OK;

done:
    return result;
}

oe_result_t oe_cert_find_extension(
    const oe_cert_t* cert,
    const char* oid,
    uint8_t* data,
    size_t* size)
{
    oe_result_t result = OE_UNEXPECTED;
    const Cert* impl = (const Cert*)cert;
    const STACK_OF(X509_EXTENSION) * extensions;
    int num_extensions;

    /* Reject invalid parameters */
    if (!_cert_is_valid(impl) || !oid || !size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Set a pointer to the stack of extensions (possibly NULL) */
    if (!(extensions = X509_get0_extensions(impl->x509)))
        OE_RAISE(OE_NOT_FOUND);

    /* Get the number of extensions (possibly zero) */
    num_extensions = sk_X509_EXTENSION_num(extensions);

    /* Find the certificate with this OID */
    for (int i = 0; i < num_extensions; i++)
    {
        X509_EXTENSION* ext;
        ASN1_OBJECT* obj;
        oe_oid_string_t ext_oid;

        /* Get the i-th extension from the stack */
        if (!(ext = sk_X509_EXTENSION_value(extensions, i)))
            OE_RAISE(OE_FAILURE);

        /* Get the OID */
        if (!(obj = X509_EXTENSION_get_object(ext)))
            OE_RAISE(OE_FAILURE);

        /* Get the string name of the OID */
        if (!OBJ_obj2txt(ext_oid.buf, sizeof(ext_oid.buf), obj, 1))
            OE_RAISE(OE_FAILURE);

        /* If found then get the data */
        if (strcmp(ext_oid.buf, oid) == 0)
        {
            ASN1_OCTET_STRING* str;

            /* Get the data from the extension */
            if (!(str = X509_EXTENSION_get_data(ext)))
                OE_RAISE(OE_FAILURE);

            /* If the caller's buffer is too small, raise error */
            if ((size_t)str->length > *size)
            {
                *size = (size_t)str->length;
                OE_RAISE(OE_BUFFER_TOO_SMALL);
            }

            if (data)
            {
                OE_CHECK(
                    oe_memcpy_s(data, *size, str->data, (size_t)str->length));
                *size = (size_t)str->length;
                result = OE_OK;
                goto done;
            }
        }
    }

    result = OE_NOT_FOUND;

done:
    return result;
}
