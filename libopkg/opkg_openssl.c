/* vi: set expandtab sw=4 sts=4: */
/* opkg_openssl.c - the opkg package management system

    Copyright (C) 2001 University of Southern California
    Copyright (C) 2008 OpenMoko Inc
    Copyright (C) 2009 Camille Moncelier <moncelier@devlife.org>
    Copyright (C) 2014 Paul Barker

    SPDX-License-Identifier: GPL-2.0-or-later

    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation; either version 2, or (at
    your option) any later version.

    This program is distributed in the hope that it will be useful, but
    WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    General Public License for more details.
*/

#include "config.h"

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>

#include "config.h"
#include "opkg_conf.h"
#include "opkg_message.h"
#include "opkg_openssl.h"


static X509_STORE *setup_verify(char *CAfile, char *CApath)
{
    int r;
    X509_STORE *store = NULL;
    X509_LOOKUP *lookup = NULL;

    store = X509_STORE_new();
    if (!store) {
        // Something bad is happening...
        goto end;
    }
    // adds the X509 file lookup method
    lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
    if (!lookup) {
        goto end;
    }
    // Autenticating against one CA file
    if (CAfile) {
        r = X509_LOOKUP_load_file(lookup, CAfile, X509_FILETYPE_PEM);
        if (!r) {
            // Invalid CA => Bye bye
            opkg_msg(ERROR, "Error loading file %s.\n", CAfile);
            goto end;
        }
    } else {
        X509_LOOKUP_load_file(lookup, NULL, X509_FILETYPE_DEFAULT);
    }

    // Now look into CApath directory if supplied
    lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir());
    if (lookup == NULL) {
        goto end;
    }

    if (CApath) {
        r = X509_LOOKUP_add_dir(lookup, CApath, X509_FILETYPE_PEM);
        if (!r) {
            opkg_msg(ERROR, "Error loading directory %s.\n", CApath);
            goto end;
        }
    } else {
        X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT);
    }

    // All right !
    ERR_clear_error();
    return store;

 end:

    X509_STORE_free(store);
    return NULL;

}

void openssl_init(void)
{
    static int init = 0;

    if (!init) {
        OPENSSL_config(NULL);
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
        init = 1;
    }
}

int opkg_verify_openssl_signature(const char *file, const char *sigfile)
{
    X509_STORE *store = NULL;
    PKCS7 *p7 = NULL;
    BIO *in = NULL, *indata = NULL;
    int r;

    // Sig check failed by default !
    int status = -1;

    openssl_init();

    // Set-up the key store
    store = setup_verify(opkg_config->signature_ca_file,
                         opkg_config->signature_ca_path);
    if (!store) {
        opkg_msg(ERROR, "Can't open CA certificates.\n");
        goto verify_file_end;
    }
    // Open a BIO to read the sig file
    in = BIO_new_file(sigfile, "rb");
    if (!in) {
        opkg_msg(ERROR, "Can't open signature file %s.\n", sigfile);
        goto verify_file_end;
    }
    // Read the PKCS7 block contained in the sig file
    p7 = PEM_read_bio_PKCS7(in, NULL, NULL, NULL);
    if (!p7) {
        opkg_msg(ERROR, "Can't read signature file %s (Corrupted ?).\n",
                 sigfile);
        goto verify_file_end;
    }
    // Open the Package file to authenticate
    indata = BIO_new_file(file, "rb");
    if (!indata) {
        opkg_msg(ERROR, "Can't open file %s.\n", file);
        goto verify_file_end;
    }
    // Let's verify the autenticity !
    r = PKCS7_verify(p7, NULL, store, indata, NULL, PKCS7_BINARY);
    if (r != 1) {
        // Get Off My Lawn!
        opkg_msg(ERROR, "Verification failure.\n");
    } else {
        // Victory !
        status = 0;
    }

 verify_file_end:
    BIO_free(in);
    BIO_free(indata);
    PKCS7_free(p7);
    X509_STORE_free(store);

    return status;
}
